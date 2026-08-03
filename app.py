"""
app.py  —  YukiCrypt encrypted file manager
============================================
Zero-install encrypted vault with a full file manager UI.

Requirements:
    pip install PyQt6 cryptography
    (optional: pip install argon2-cffi  for stronger key derivation)

Run:
    python app.py
"""

import sys
import os
import shutil
import time
import logging
import platform
import subprocess
from pathlib import Path
from datetime import datetime

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout,
    QLabel, QPushButton, QLineEdit, QFileDialog, QMessageBox,
    QTreeWidget, QTreeWidgetItem, QProgressBar, QCheckBox,
    QDialog, QSplitter, QMenu,
    QStatusBar, QToolBar, QSizePolicy, QAbstractItemView, QStackedWidget
)
from PyQt6.QtCore import (
    Qt, QThread, pyqtSignal, QTimer, QSize, QPoint
)
from PyQt6.QtGui import (
    QColor, QPalette, QDragEnterEvent, QDropEvent
)

from vault import Vault, VaultError, WrongPasswordError, TamperedError, analyse_password

# Let the caller configure logging; default to no-op if not configured
log = logging.getLogger(__name__)
if not log.handlers:
    log.addHandler(logging.NullHandler())


_icon_cache = None   # cached so we don't regenerate on every dialog open


def make_icon() -> "QIcon":
    """
    Generate a custom app icon programmatically — cached after first call.
    Dark rounded square with green ◈ symbol. No external image file needed.
    """
    global _icon_cache
    if _icon_cache is not None:
        return _icon_cache

    from PyQt6.QtGui import QIcon, QPixmap, QPainter, QColor, QFont, QPen, QBrush
    from PyQt6.QtCore import QRect

    icon = QIcon()
    for size in [16, 32, 48, 64, 128, 256]:
        px = QPixmap(size, size)
        px.fill(QColor(0, 0, 0, 0))

        p = QPainter(px)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        p.setBrush(QBrush(QColor("#0d120d")))
        p.setPen(QPen(QColor("#3aff4a"), max(1, size // 32)))
        p.drawRoundedRect(1, 1, size - 2, size - 2, size // 6, size // 6)

        p.setFont(QFont("Consolas", int(size * 0.52), QFont.Weight.Bold))
        p.setPen(QColor("#3aff4a"))
        p.drawText(QRect(0, 0, size, size), Qt.AlignmentFlag.AlignCenter, "◈")
        p.end()
        icon.addPixmap(px)

    _icon_cache = icon
    return icon


# ────────────────────────────────────────────────────────────────────────────
# Themes
# ────────────────────────────────────────────────────────────────────────────

FONT = "'JetBrains Mono', 'Cascadia Code', 'Fira Code', 'Consolas', monospace"

THEME_DARK = {
    "name":          "Dark",
    # backgrounds
    "bg_main":       "#0b0f0b",
    "bg_panel":      "#0d120d",
    "bg_input":      "#0d120d",
    "bg_hover":      "#0f1e0f",
    "bg_select":     "#0f2010",
    "bg_btn_primary":"#0a1f0a",
    "bg_danger":     "#1a0a0a",
    # foregrounds
    "fg_main":       "#b0c4b1",
    "fg_dim":        "#7a9a7a",
    "fg_dimmer":     "#2a4a2a",
    "fg_accent":     "#3aff4a",
    "fg_accent2":    "#5dff6e",
    "fg_btn":        "#4a8a4a",
    "fg_btn_hover":  "#8fba8f",
    "fg_danger":     "#c05050",
    "fg_danger_h":   "#ff5050",
    # borders
    "border":        "#1a2e1a",
    "border2":       "#2a4a2a",
    "border_input":  "#2a4a2a",
    # misc
    "scrollbar":     "#1a2e1a",
    "progress":      "#3aff4a",
    "logo_color":    "#1a3a1a",
    "sidebar_info":  "#1a3a1a",
    "stats_color":   "#1a3a1a",
    "folder_color":  "#8fba4a",
    "size_color":    "#2a5a2a",
}

THEME_LIGHT = {
    "name":          "Light",
    # backgrounds
    "bg_main":       "#f5f7f5",
    "bg_panel":      "#eef1ee",
    "bg_input":      "#ffffff",
    "bg_hover":      "#e2ebe2",
    "bg_select":     "#d0ecd0",
    "bg_btn_primary":"#e8f5e8",
    "bg_danger":     "#fdecea",
    # foregrounds
    "fg_main":       "#1a2e1a",
    "fg_dim":        "#4a6a4a",
    "fg_dimmer":     "#8aaa8a",
    "fg_accent":     "#1a7a2a",
    "fg_accent2":    "#1a8a2a",
    "fg_btn":        "#2a6a2a",
    "fg_btn_hover":  "#1a4a1a",
    "fg_danger":     "#c0303a",
    "fg_danger_h":   "#e0202a",
    # borders
    "border":        "#c8d8c8",
    "border2":       "#a0c0a0",
    "border_input":  "#a0c0a0",
    # misc
    "scrollbar":     "#c8d8c8",
    "progress":      "#2a8a3a",
    "logo_color":    "#4a8a5a",
    "sidebar_info":  "#6a8a6a",
    "stats_color":   "#6a8a6a",
    "folder_color":  "#7a6a20",
    "size_color":    "#4a7a4a",
}

_current_theme = THEME_DARK


def _make_stylesheet(t: dict) -> str:
    return f"""
* {{
    font-family: {FONT};
    font-size: 12px;
    color: {t['fg_main']};
    background-color: transparent;
}}
QMainWindow {{ background-color: {t['bg_main']}; }}
QDialog     {{ background-color: {t['bg_main']}; }}
QWidget     {{ background-color: transparent; }}

QToolBar {{
    background-color: {t['bg_panel']};
    border-bottom: 1px solid {t['border']};
    padding: 4px 12px;
    spacing: 6px;
}}
QToolBar QToolButton {{
    background-color: transparent;
    border: 1px solid transparent;
    padding: 6px 14px;
    color: {t['fg_btn']};
    letter-spacing: 1px;
    font-size: 11px;
}}
QToolBar QToolButton:hover {{
    border: 1px solid {t['border2']};
    color: {t['fg_btn_hover']};
    background-color: {t['bg_hover']};
}}
QToolBar QToolButton:pressed {{ background-color: {t['bg_select']}; }}

#sidebar {{
    background-color: {t['bg_panel']};
    border-right: 1px solid {t['border']};
    min-width: 200px;
    max-width: 240px;
}}
#sideTitle {{
    color: {t['fg_dimmer']};
    font-size: 9px;
    letter-spacing: 3px;
    padding: 12px 16px 6px 16px;
}}

QTreeWidget, QListWidget {{
    background-color: {t['bg_main']};
    border: none;
    outline: none;
    color: {t['fg_dim']};
}}
QTreeWidget::item, QListWidget::item {{
    padding: 6px 8px;
    border-bottom: 1px solid {t['border']};
}}
QTreeWidget::item:selected, QListWidget::item:selected {{
    background-color: {t['bg_select']};
    color: {t['fg_accent2']};
    border-left: 2px solid {t['fg_accent']};
}}
QTreeWidget::item:hover, QListWidget::item:hover {{
    background-color: {t['bg_hover']};
}}
QHeaderView::section {{
    background-color: {t['bg_panel']};
    color: {t['fg_dimmer']};
    border: none;
    border-bottom: 1px solid {t['border']};
    padding: 6px 8px;
    font-size: 9px;
    letter-spacing: 2px;
}}

QPushButton {{
    background-color: transparent;
    color: {t['fg_btn']};
    border: 1px solid {t['border2']};
    padding: 8px 18px;
    letter-spacing: 1px;
    font-size: 11px;
}}
QPushButton:hover {{
    border-color: {t['fg_btn']};
    color: {t['fg_btn_hover']};
    background-color: {t['bg_hover']};
}}
QPushButton:pressed {{ background-color: {t['bg_select']}; }}
QPushButton:disabled {{ color: {t['fg_dimmer']}; border-color: {t['border']}; }}
QPushButton#primaryBtn {{
    border-color: {t['fg_accent']};
    color: {t['fg_accent']};
    background-color: {t['bg_btn_primary']};
}}
QPushButton#primaryBtn:hover {{ background-color: {t['bg_select']}; }}
QPushButton#dangerBtn {{
    border-color: {t['fg_danger']};
    color: {t['fg_danger']};
}}
QPushButton#dangerBtn:hover {{
    background-color: {t['bg_danger']};
    color: {t['fg_danger_h']};
}}

QLineEdit {{
    background-color: {t['bg_input']};
    border: none;
    border-bottom: 1px solid {t['border_input']};
    color: {t['fg_main']};
    padding: 8px 4px;
    selection-background-color: {t['bg_select']};
}}
QLineEdit:focus {{ border-bottom-color: {t['fg_accent']}; }}

QProgressBar {{
    background-color: {t['bg_panel']};
    border: none;
    border-bottom: 1px solid {t['border']};
    height: 3px;
    color: transparent;
}}
QProgressBar::chunk {{ background-color: {t['progress']}; }}

QLabel#heading {{
    color: {t['fg_accent']};
    font-size: 13px;
    letter-spacing: 4px;
}}
QLabel#subtext {{
    color: {t['fg_dimmer']};
    font-size: 10px;
    letter-spacing: 1px;
}}

QStatusBar {{
    background-color: {t['bg_panel']};
    color: {t['fg_dimmer']};
    border-top: 1px solid {t['border']};
    font-size: 10px;
    letter-spacing: 1px;
}}

QScrollBar:vertical {{
    background: {t['bg_main']};
    width: 8px;
    border: none;
}}
QScrollBar::handle:vertical {{
    background: {t['scrollbar']};
    border-radius: 4px;
    min-height: 20px;
}}
QScrollBar::handle:vertical:hover {{ background: {t['border2']}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}

QMenu {{
    background-color: {t['bg_panel']};
    border: 1px solid {t['border']};
    padding: 4px;
}}
QMenu::item {{ padding: 7px 20px; color: {t['fg_dim']}; }}
QMenu::item:selected {{ background-color: {t['bg_select']}; color: {t['fg_accent2']}; }}
QMenu::separator {{ height: 1px; background: {t['border']}; margin: 4px 8px; }}

QSplitter::handle {{ background-color: {t['border']}; width: 1px; }}

QCheckBox {{ color: {t['fg_dim']}; spacing: 8px; }}
QCheckBox::indicator {{
    width: 13px; height: 13px;
    border: 1px solid {t['border2']};
    background: {t['bg_input']};
}}
QCheckBox::indicator:checked {{
    background-color: {t['fg_accent']};
    border-color: {t['fg_accent']};
}}
"""


def _make_palette(t: dict) -> "QPalette":
    pal = QPalette()
    pal.setColor(QPalette.ColorRole.Window,           QColor(t["bg_main"]))
    pal.setColor(QPalette.ColorRole.WindowText,       QColor(t["fg_main"]))
    pal.setColor(QPalette.ColorRole.Base,             QColor(t["bg_input"]))
    pal.setColor(QPalette.ColorRole.AlternateBase,    QColor(t["bg_panel"]))
    pal.setColor(QPalette.ColorRole.Text,             QColor(t["fg_main"]))
    pal.setColor(QPalette.ColorRole.Button,           QColor(t["bg_panel"]))
    pal.setColor(QPalette.ColorRole.ButtonText,       QColor(t["fg_btn"]))
    pal.setColor(QPalette.ColorRole.Highlight,        QColor(t["bg_select"]))
    pal.setColor(QPalette.ColorRole.HighlightedText,  QColor(t["fg_accent"]))
    pal.setColor(QPalette.ColorRole.ToolTipBase,      QColor(t["bg_panel"]))
    pal.setColor(QPalette.ColorRole.ToolTipText,      QColor(t["fg_main"]))
    return pal


def apply_theme(app: "QApplication", theme: dict):
    global _current_theme
    _current_theme = theme
    app.setStyleSheet(_make_stylesheet(theme))
    app.setPalette(_make_palette(theme))


def current_theme() -> dict:
    return _current_theme


# ────────────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────────────

def fmt_size(n: int) -> str:
    if n < 1024:       return f"{n} B"
    if n < 1024**2:    return f"{n/1024:.1f} KB"
    if n < 1024**3:    return f"{n/1024**2:.1f} MB"
    return f"{n/1024**3:.2f} GB"

def fmt_time(ts: int) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")

def open_file(path: str):
    """Open a file with the default system application."""
    system = platform.system()
    try:
        if system == "Windows":
            os.startfile(path)
        elif system == "Darwin":
            subprocess.Popen(["open", path],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.Popen(["xdg-open", path],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        log.warning(f"Could not open file: {e}")

FILE_ICONS = {
    ".pdf":  "📄", ".doc": "📝", ".docx": "📝", ".txt": "📄",
    ".xls":  "📊", ".xlsx": "📊", ".csv": "📊",
    ".ppt":  "📋", ".pptx": "📋",
    ".jpg":  "🖼", ".jpeg": "🖼", ".png": "🖼", ".gif": "🖼", ".webp": "🖼",
    ".mp4":  "🎬", ".mkv": "🎬", ".avi": "🎬", ".mov": "🎬",
    ".mp3":  "🎵", ".wav": "🎵", ".flac": "🎵",
    ".zip":  "📦", ".rar": "📦", ".7z": "📦", ".tar": "📦",
    ".py":   "🐍", ".js": "⚡", ".html": "🌐", ".css": "🎨",
    ".exe":  "⚙", ".dll": "⚙",
}

def file_icon(ext: str) -> str:
    return FILE_ICONS.get(ext.lower(), "📁")


# ────────────────────────────────────────────────────────────────────────────
# Worker threads
# ────────────────────────────────────────────────────────────────────────────

class ImportWorker(QThread):
    progress  = pyqtSignal(int, int)   # current, total
    finished  = pyqtSignal(int, int)   # success, failed
    error_msg = pyqtSignal(str)

    def __init__(self, vault: Vault, file_pairs: list[tuple[str, str]]):
        super().__init__()
        self.vault      = vault
        self.file_pairs = file_pairs   # [(disk_path, virtual_path), ...]

    def run(self):
        success, failed = 0, 0
        total = len(self.file_pairs)
        for i, (disk_path, virtual_path) in enumerate(self.file_pairs):
            self.progress.emit(i + 1, total)
            try:
                if disk_path is None:
                    # Empty folder placeholder — store zero bytes
                    data = b""
                else:
                    with open(disk_path, "rb") as f:
                        data = f.read()
                self.vault.write_file(virtual_path, data)
                success += 1
            except MemoryError:
                failed += 1
                name = Path(disk_path).name if disk_path else virtual_path
                self.error_msg.emit(f"Failed: {name} — file too large to encrypt in memory")
            except Exception as e:
                failed += 1
                name = Path(disk_path).name if disk_path else virtual_path
                self.error_msg.emit(f"Failed: {name} — {e}")
        self.finished.emit(success, failed)


class DeleteWorker(QThread):
    progress  = pyqtSignal(int, int)
    finished  = pyqtSignal(int, int)
    error_msg = pyqtSignal(str)

    def __init__(self, vault: Vault, paths: list[str]):
        super().__init__()
        self.vault = vault
        self.paths = paths

    def run(self):
        success, failed = 0, 0
        total = len(self.paths)
        for i, path in enumerate(self.paths):
            self.progress.emit(i + 1, total)
            try:
                self.vault.delete_file(path)
                success += 1
            except Exception as e:
                failed += 1
                self.error_msg.emit(f"Delete failed: {path} — {e}")
        self.finished.emit(success, failed)


class IntegrityWorker(QThread):
    progress = pyqtSignal(int, int)
    finished = pyqtSignal(dict)

    def __init__(self, vault: Vault):
        super().__init__()
        self.vault = vault

    def run(self):
        result = self.vault.check_integrity(
            progress_cb=lambda c, t: self.progress.emit(c, t)
        )
        self.finished.emit(result)


class RecoveryWorker(QThread):
    progress = pyqtSignal(int, int)
    finished = pyqtSignal(dict)

    def __init__(self, vault: Vault, output_dir: str):
        super().__init__()
        self.vault      = vault
        self.output_dir = output_dir

    def run(self):
        result = self.vault.recover_readable(
            self.output_dir,
            progress_cb=lambda c, t: self.progress.emit(c, t)
        )
        self.finished.emit(result)


class ExportWorker(QThread):
    progress  = pyqtSignal(int, int)
    finished  = pyqtSignal(int, int, str)   # ok, failed, dest
    error_msg = pyqtSignal(str)

    def __init__(self, vault: Vault, files: list, dest: str):
        super().__init__()
        self.vault = vault
        self.files = files
        self.dest  = dest

    def run(self):
        ok, fail = 0, 0
        for i, f in enumerate(self.files):
            self.progress.emit(i + 1, len(self.files))
            try:
                data = self.vault.read_file(f["path"])
                # Preserve subfolder structure to avoid name collisions
                if f["folder"]:
                    out_dir = os.path.join(self.dest, f["folder"].replace("/", os.sep))
                    os.makedirs(out_dir, exist_ok=True)
                    outpath = os.path.join(out_dir, f["name"])
                else:
                    outpath = os.path.join(self.dest, f["name"])
                with open(outpath, "wb") as fh:
                    fh.write(data)
                ok += 1
            except Exception as e:
                fail += 1
                self.error_msg.emit(f"Export failed: {f['name']} — {e}")
        self.finished.emit(ok, fail, self.dest)


class CompactWorker(QThread):
    finished = pyqtSignal(bool, str)   # success, message

    def __init__(self, vault: Vault):
        super().__init__()
        self.vault = vault

    def run(self):
        try:
            before, after = self.vault.compact()
            saved = before - after
            self.finished.emit(True, f"{saved}")
        except Exception as e:
            self.finished.emit(False, str(e))


class BackupWorker(QThread):
    finished = pyqtSignal(bool, str)   # success, message/path

    def __init__(self, vault: Vault, backup_path: str):
        super().__init__()
        self.vault       = vault
        self.backup_path = backup_path

    def run(self):
        try:
            original_size, backup_size = self.vault.backup(self.backup_path)
            saved = original_size - backup_size
            # Pass path and size info as "path|saved_bytes"
            self.finished.emit(True, f"{self.backup_path}|{saved}")
        except Exception as e:
            self.finished.emit(False, str(e))


# ────────────────────────────────────────────────────────────────────────────
# Password dialog
# ────────────────────────────────────────────────────────────────────────────

class PasswordDialog(QDialog):
    def __init__(self, parent=None, mode="unlock", vault_path=""):
        super().__init__(parent)
        self.mode = mode
        self.setWindowTitle("YukiCrypt")
        self.setWindowIcon(make_icon())
        self.setMinimumWidth(480)
        self.setModal(True)
        self._build()

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 40, 40, 40)
        layout.setSpacing(20)

        # Header
        icon_lbl = QLabel("◈")
        icon_lbl.setStyleSheet(f"color: {current_theme()['fg_accent']}; font-size: 32px;")
        icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(icon_lbl)

        title = QLabel("YUKICRYPT" if self.mode == "unlock" else "CREATE NEW VAULT")
        title.setObjectName("heading")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        sub = QLabel(
            "Enter your password to unlock the vault"
            if self.mode == "unlock"
            else "Choose a strong password for your new vault"
        )
        sub.setObjectName("subtext")
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(sub)

        # Password
        self.pw = QLineEdit()
        self.pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.pw.setPlaceholderText("Password...")
        self.pw.textChanged.connect(self._pw_changed)
        layout.addWidget(self.pw)

        if self.mode == "create":
            # Confirm
            self.conf = QLineEdit()
            self.conf.setEchoMode(QLineEdit.EchoMode.Password)
            self.conf.setPlaceholderText("Confirm password...")
            layout.addWidget(self.conf)

            # Strength indicator
            self.strength_lbl = QLabel("")
            self.strength_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.strength_bar = QProgressBar()
            self.strength_bar.setRange(0, 100)
            self.strength_bar.setTextVisible(False)
            self.strength_bar.setFixedHeight(3)
            layout.addWidget(self.strength_bar)
            layout.addWidget(self.strength_lbl)

            # Tips
            self.tips_lbl = QLabel("")
            self.tips_lbl.setObjectName("subtext")
            self.tips_lbl.setWordWrap(True)
            self.tips_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(self.tips_lbl)

        # Show password — toggles both fields in create mode
        show_chk = QCheckBox("SHOW PASSWORD")
        def _toggle_show(visible: bool):
            mode = QLineEdit.EchoMode.Normal if visible else QLineEdit.EchoMode.Password
            self.pw.setEchoMode(mode)
            if self.mode == "create":
                self.conf.setEchoMode(mode)
        show_chk.toggled.connect(_toggle_show)
        layout.addWidget(show_chk)

        # OK button
        self.ok_btn = QPushButton(
            "UNLOCK" if self.mode == "unlock" else "CREATE VAULT"
        )
        self.ok_btn.setObjectName("primaryBtn")
        self.ok_btn.setFixedHeight(44)
        self.ok_btn.clicked.connect(self._accept)
        self.pw.returnPressed.connect(self._accept)
        layout.addWidget(self.ok_btn)

    def _pw_changed(self, text):
        if self.mode != "create":
            return
        if not text:
            self.strength_bar.setValue(0)
            self.strength_lbl.setText("")
            self.tips_lbl.setText("")
            return
        r = analyse_password(text)
        self.strength_bar.setValue(r["score"])
        colour = {"Weak": "#ff4444", "Fair": "#ffaa00",
                  "Good": "#aadd00", "Strong": "#3aff4a"}[r["rating"]]
        self.strength_bar.setStyleSheet(
            f"QProgressBar::chunk {{ background-color: {colour}; }}"
        )
        self.strength_lbl.setText(
            f"{r['rating'].upper()}  ·  {r['entropy']:.0f} bits entropy"
        )
        self.strength_lbl.setStyleSheet(f"color: {colour}; font-size: 10px;")
        self.tips_lbl.setText("  ·  ".join(r["issues"]) if r["issues"] else "✓ Good password")

    def _accept(self):
        pw = self.pw.text()
        if len(pw) < 8:
            QMessageBox.warning(self, "Error", "Password must be at least 8 characters.")
            return
        if self.mode == "create":
            if pw != self.conf.text():
                QMessageBox.warning(self, "Error", "Passwords do not match.")
                return
            r = analyse_password(pw)
            if r["rating"] == "Weak":
                reply = QMessageBox.question(
                    self, "Weak Password",
                    f"Password entropy: {r['entropy']:.0f} bits — rated WEAK.\n"
                    f"Issues: {', '.join(r['issues'])}\n\nContinue anyway?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                )
                if reply != QMessageBox.StandardButton.Yes:
                    return
        self.accept()

    def password(self) -> str:
        return self.pw.text()


# ────────────────────────────────────────────────────────────────────────────
# File list widget
# ────────────────────────────────────────────────────────────────────────────

class FileList(QTreeWidget):
    """Main file browser — shows decrypted file metadata."""

    file_open_requested    = pyqtSignal(dict)
    file_delete_requested  = pyqtSignal(list)   # list of file dicts
    folder_delete_requested = pyqtSignal(str)   # folder path
    files_dropped          = pyqtSignal(list)   # list of disk paths

    def __init__(self):
        super().__init__()
        self.setColumnCount(4)
        self.setHeaderLabels(["  NAME", "SIZE", "MODIFIED", "TYPE"])
        self.header().setDefaultSectionSize(220)
        self.header().resizeSection(0, 340)
        self.header().resizeSection(1, 90)
        self.header().resizeSection(2, 140)
        self.header().resizeSection(3, 80)
        self.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.setRootIsDecorated(False)
        self.setAlternatingRowColors(False)
        self.setSortingEnabled(False)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._context_menu)
        self.itemDoubleClicked.connect(self._double_clicked)
        self.setAcceptDrops(True)

        # Drag & drop
        self.setDragDropMode(QAbstractItemView.DragDropMode.DropOnly)

        # Make header clickable for manual sort (folders always on top)
        self.header().setSectionsClickable(True)
        self.header().sectionClicked.connect(self._header_clicked)
        self._sort_col       = 0
        self._sort_asc       = True
        self._all_subfolders = []
        self._all_files      = []
        self._navigate_cb    = None

    def _header_clicked(self, col: int):
        if self._sort_col == col:
            self._sort_asc = not self._sort_asc
        else:
            self._sort_col = col
            self._sort_asc = True
        self._resort()

    def populate(self, files: list[dict], selected_folder: str = "",
                 subfolders: list[str] = None, navigate_cb=None):
        self.clear()
        self._navigate_cb  = navigate_cb
        self._all_subfolders = list(subfolders or [])
        self._all_files      = list(files)
        self._resort()

    def _resort(self):
        self.clear()
        col = self._sort_col
        rev = not self._sort_asc

        def file_sort_key(f):
            if col == 1:   return f["size"]
            if col == 2:   return f["modified"]
            if col == 3:   return f["ext"].lower()
            return f["name"].lower()

        # Folders always on top, sorted by name regardless of column
        t = current_theme()
        for sf in sorted(self._all_subfolders, reverse=rev if col == 0 else False):
            sf_name = sf.split("/")[-1]
            item = QTreeWidgetItem([f"  📁  {sf_name}", "", "", "FOLDER"])
            item.setData(0, Qt.ItemDataRole.UserRole, {"_is_folder": True, "path": sf})
            item.setForeground(0, QColor(t["folder_color"]))
            item.setForeground(3, QColor(t["fg_dimmer"]))
            self.addTopLevelItem(item)

        # Files below folders, sorted by chosen column
        for f in sorted(self._all_files, key=file_sort_key, reverse=rev):
            icon = file_icon(f["ext"])
            item = QTreeWidgetItem([
                f"  {icon}  {f['name']}",
                fmt_size(f["size"]),
                fmt_time(f["modified"]),
                f["ext"].lstrip(".").upper() or "—",
            ])
            item.setData(0, Qt.ItemDataRole.UserRole, f)
            item.setForeground(1, QColor(t["size_color"]))
            item.setForeground(2, QColor(t["size_color"]))
            item.setForeground(3, QColor(t["fg_dim"]))
            self.addTopLevelItem(item)

    def selected_files(self) -> list[dict]:
        result = []
        for item in self.selectedItems():
            d = item.data(0, Qt.ItemDataRole.UserRole)
            if d and not d.get("_is_folder"):
                result.append(d)
        return result

    def _double_clicked(self, item, col):
        d = item.data(0, Qt.ItemDataRole.UserRole)
        if not d:
            return
        if d.get("_is_folder"):
            if self._navigate_cb:
                self._navigate_cb(d["path"])
        else:
            self.file_open_requested.emit(d)

    def _context_menu(self, pos: QPoint):
        item = self.itemAt(pos)
        if not item:
            return
        d = item.data(0, Qt.ItemDataRole.UserRole)
        if not d:
            return

        menu = QMenu(self)

        if d.get("_is_folder"):
            # Folder row selected
            folder_path = d["path"]
            folder_name = folder_path.split("/")[-1]
            del_act = menu.addAction(f"Delete folder '{folder_name}' and all contents")
            del_act.triggered.connect(lambda: self.folder_delete_requested.emit(folder_path))
        else:
            # File row(s) selected
            sel = self.selected_files()
            if not sel:
                return
            if len(sel) == 1:
                open_act = menu.addAction("Open")
                open_act.triggered.connect(lambda: self.file_open_requested.emit(sel[0]))
                menu.addSeparator()
            del_act = menu.addAction(f"Delete {len(sel)} file{'s' if len(sel)>1 else ''}")
            del_act.triggered.connect(lambda: self.file_delete_requested.emit(sel))

        menu.exec(self.viewport().mapToGlobal(pos))

    def dragEnterEvent(self, e: QDragEnterEvent):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()

    def dragMoveEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()

    def dropEvent(self, e: QDropEvent):
        urls = e.mimeData().urls()
        paths = [u.toLocalFile() for u in urls if u.isLocalFile()]
        if paths:
            self.files_dropped.emit(paths)


# ────────────────────────────────────────────────────────────────────────────
# Lock screen
# ────────────────────────────────────────────────────────────────────────────

class LockScreen(QWidget):
    unlock_requested = pyqtSignal()
    new_vault        = pyqtSignal()
    open_vault       = pyqtSignal()

    def __init__(self):
        super().__init__()
        self._build()

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(16)

        # ASCII-art style logo
        self.logo = QLabel(
            "┌─────────────────────────────┐\n"
            "│                             │\n"
            "│        ◈ YUKICRYPT          │\n"
            "│   ENCRYPTED FILE MANAGER    │\n"
            "│                             │\n"
            "│   AES-256-GCM · ARGON2ID    │\n"
            "│   ZERO INSTALLS REQUIRED    │\n"
            "│                             │\n"
            "└─────────────────────────────┘"
        )
        self.logo.setStyleSheet(
            f"color: {current_theme()['logo_color']}; font-size: 13px; letter-spacing: 2px;"
        )
        self.logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.logo)

        layout.addSpacing(20)

        new_btn = QPushButton("CREATE NEW VAULT")
        new_btn.setObjectName("primaryBtn")
        new_btn.setFixedWidth(260)
        new_btn.setFixedHeight(44)
        new_btn.clicked.connect(self.new_vault.emit)
        layout.addWidget(new_btn, alignment=Qt.AlignmentFlag.AlignCenter)

        open_btn = QPushButton("OPEN EXISTING VAULT")
        open_btn.setFixedWidth(260)
        open_btn.setFixedHeight(44)
        open_btn.clicked.connect(self.open_vault.emit)
        layout.addWidget(open_btn, alignment=Qt.AlignmentFlag.AlignCenter)

        layout.addSpacing(20)
        note = QLabel("No installation required  ·  All data encrypted at rest")
        note.setObjectName("subtext")
        note.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(note)

        layout.addSpacing(8)
        # Label reflects current theme so it's correct after vault lock/unlock cycles
        theme_label = "☀  LIGHT THEME" if current_theme()["name"] == "Dark" else "🌙  DARK THEME"
        self._theme_btn = QPushButton(theme_label)
        self._theme_btn.setFixedWidth(180)
        self._theme_btn.setFixedHeight(36)
        self._theme_btn.clicked.connect(self._toggle_theme_lock)
        layout.addWidget(self._theme_btn, alignment=Qt.AlignmentFlag.AlignCenter)


    def _toggle_theme_lock(self):
        app = QApplication.instance()
        if current_theme()["name"] == "Dark":
            apply_theme(app, THEME_LIGHT)
            self._theme_btn.setText("🌙  DARK THEME")
        else:
            apply_theme(app, THEME_DARK)
            self._theme_btn.setText("☀  LIGHT THEME")
        # Re-apply hardcoded logo style
        self.logo.setStyleSheet(
            f"color: {current_theme()['logo_color']}; font-size: 13px; letter-spacing: 2px;"
        )


# ────────────────────────────────────────────────────────────────────────────
# Main vault view
# ────────────────────────────────────────────────────────────────────────────

class VaultView(QWidget):
    lock_requested = pyqtSignal()

    def __init__(self, vault: Vault, vault_path: str, status_cb):
        super().__init__()
        self.vault      = vault
        self.vault_path = vault_path
        self.status_cb  = status_cb
        self._open_map: dict[str, str] = {}   # virtual_path → temp_path
        self._refreshing = False
        self._active_workers: list = []       # FIX: keep refs so workers aren't GC'd
        self._build()
        self._refresh()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Toolbar ──────────────────────────────────────────────────────
        tb = QToolBar()
        tb.setMovable(False)
        tb.setIconSize(QSize(16, 16))

        # Theme toggle — leftmost so it never gets cut off when window is narrow
        self._theme_btn = QPushButton("☀  LIGHT")
        self._theme_btn.setFixedWidth(90)
        self._theme_btn.setFixedHeight(28)
        self._theme_btn.setToolTip("Switch between dark and light theme")
        self._theme_btn.clicked.connect(self._toggle_theme)
        tb.addWidget(self._theme_btn)
        tb.addSeparator()

        def tb_action(label, slot):
            btn = tb.addAction(label)
            btn.triggered.connect(slot)
            return btn

        tb_action("＋  ADD FILES",    self._add_files)
        tb_action("＋  ADD FOLDER",   self._add_folder)
        tb.addSeparator()
        tb_action("↓  EXPORT",        self._export_selected)
        tb.addSeparator()
        tb_action("✓  CHECK",         self._check_integrity)
        tb_action("⊞  BACKUP",        self._backup_vault)
        tb_action("▼  COMPACT",       self._compact_vault)
        tb_action("⚕  RECOVER",       self._recover_vault)
        tb.addSeparator()
        tb_action("🔒  LOCK VAULT",   self.lock_requested.emit)

        # Stats label — shrinks gracefully when window is narrow
        self.stats_lbl = QLabel("")
        self.stats_lbl.setStyleSheet(f"color: {current_theme()['stats_color']}; font-size: 10px; padding: 0 12px;")
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        tb.addWidget(spacer)
        tb.addWidget(self.stats_lbl)

        self._toolbar = tb
        root.addWidget(tb)

        # ── Progress bar ─────────────────────────────────────────────────
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.progress.setFixedHeight(3)
        root.addWidget(self.progress)

        # ── Main area ────────────────────────────────────────────────────
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Sidebar
        sidebar = QWidget()
        sidebar.setObjectName("sidebar")
        sb_layout = QVBoxLayout(sidebar)
        sb_layout.setContentsMargins(0, 0, 0, 0)
        sb_layout.setSpacing(0)

        sb_title = QLabel("VAULT")
        sb_title.setObjectName("sideTitle")
        sb_layout.addWidget(sb_title)

        self.folder_tree = QTreeWidget()
        self.folder_tree.setHeaderHidden(True)
        self.folder_tree.setObjectName("folderList")
        self.folder_tree.setRootIsDecorated(True)
        self.folder_tree.setIndentation(14)
        self.folder_tree.currentItemChanged.connect(self._folder_changed)
        self.folder_tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.folder_tree.customContextMenuRequested.connect(self._sidebar_context_menu)
        sb_layout.addWidget(self.folder_tree)
        sb_layout.addStretch()

        # Vault info
        self.info_lbl = QLabel("")
        self.info_lbl.setObjectName("subtext")
        self.info_lbl.setWordWrap(True)
        self.info_lbl.setStyleSheet(
            f"color: {current_theme()['sidebar_info']}; font-size: 9px; padding: 12px; letter-spacing: 1px;"
        )
        sb_layout.addWidget(self.info_lbl)

        splitter.addWidget(sidebar)

        # File list
        self.file_list = FileList()
        self.file_list.file_open_requested.connect(self._open_file)
        self.file_list.file_delete_requested.connect(self._delete_files)
        self.file_list.folder_delete_requested.connect(self._delete_folder)
        self.file_list.files_dropped.connect(self._import_files)
        splitter.addWidget(self.file_list)

        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        root.addWidget(splitter)

        # ── Drop zone hint ───────────────────────────────────────────────
        self.drop_hint = QLabel("Drag & drop files here to add them to the vault")
        self.drop_hint.setObjectName("subtext")
        self.drop_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.drop_hint.setFixedHeight(32)
        self.drop_hint.setStyleSheet(
            f"color: {current_theme()['fg_dimmer']}; border-top: 1px solid {current_theme()['border']}; font-size: 10px;"
        )
        root.addWidget(self.drop_hint)

        # Enable drag & drop on whole widget
        self.setAcceptDrops(True)

    # ── File operations ───────────────────────────────────────────────────

    def _add_files(self):
        paths, _ = QFileDialog.getOpenFileNames(
            self, "Select Files to Add", str(Path.home()), "All Files (*)"
        )
        if paths:
            self._import_files(paths)

    def _add_folder(self):
        folder = QFileDialog.getExistingDirectory(
            self, "Select Folder to Add", str(Path.home())
        )
        if not folder:
            return

        folder      = os.path.normpath(folder)
        base_folder = os.path.dirname(folder)   # parent — so folder name is included in paths

        all_files  = []
        empty_dirs = []

        for root_dir, dirs, files in os.walk(folder):
            for fname in files:
                all_files.append(os.path.join(root_dir, fname))
            # FIX #15: track dirs that have no files directly inside them
            if not files:
                empty_dirs.append(root_dir)

        virtual_keeps = []
        for empty_dir in empty_dirs:
            rel = os.path.relpath(empty_dir, base_folder).replace("\\", "/")
            virtual_keeps.append(rel + "/.keep")

        self._import_files(all_files, base_folder=base_folder, virtual_keeps=virtual_keeps)

    def _import_files(self, disk_paths: list[str], base_folder: str = "",
                      virtual_keeps: list[str] = None):
        pairs = []
        total_import_size = 0
        for disk_path in disk_paths:
            if not os.path.isfile(disk_path):
                continue
            if base_folder:
                rel = os.path.relpath(disk_path, base_folder)
                virtual = rel.replace("\\", "/")
            else:
                virtual = Path(disk_path).name
            pairs.append((disk_path, virtual))
            try:
                total_import_size += os.path.getsize(disk_path)
            except Exception:
                pass

        # Add placeholder entries for empty folders
        keep_pairs = [(None, vk) for vk in (virtual_keeps or [])]
        all_pairs  = pairs + keep_pairs

        if not all_pairs:
            return

        # ── Disk space check ─────────────────────────────────────────────
        # Encrypted data is slightly larger than plaintext (GCM tag = 16 bytes/file)
        needed = total_import_size + len(pairs) * 32
        try:
            vault_drive = os.path.dirname(os.path.abspath(self.vault_path))
            free = shutil.disk_usage(vault_drive).free
            if needed > free * 0.95:   # warn if import uses >95% of free space
                reply = QMessageBox.warning(
                    self, "Low Disk Space",
                    f"Import size: {fmt_size(needed)}\n"
                    f"Free space:  {fmt_size(free)}\n\n"
                    "Disk may fill up during import which can corrupt the vault.\n"
                    "Continue anyway?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                )
                if reply != QMessageBox.StandardButton.Yes:
                    return
        except Exception:
            pass  # disk check failed — don't block the import

        self._set_busy(True)
        self.progress.setVisible(True)
        self.progress.setRange(0, len(all_pairs))
        self.status_cb(f"Importing {len(pairs)} file(s)  ({fmt_size(total_import_size)})...")

        worker = ImportWorker(self.vault, all_pairs)
        self._active_workers.append(worker)
        worker.progress.connect(lambda c, t: self.progress.setValue(c))
        worker.finished.connect(self._import_done)
        worker.finished.connect(lambda: self._active_workers.remove(worker) if worker in self._active_workers else None)
        worker.error_msg.connect(lambda m: log.warning(m))
        worker.start()

    def _import_done(self, success: int, failed: int):
        self.progress.setVisible(False)
        self._set_busy(False)
        self._refresh()
        msg = f"Added {success} file(s)."
        if failed:
            msg += f" {failed} failed."
        self.status_cb(msg)

    def _open_file(self, file_info: dict):
        virtual_path = file_info["path"]

        # If already open, just re-open the existing temp
        if virtual_path in self._open_map:
            tmp = self._open_map[virtual_path]
            if os.path.exists(tmp):
                open_file(tmp)
                self.status_cb(f"Opened: {file_info['name']}")
                return
            else:
                # Stale entry — temp was deleted externally, clean up
                self._open_map.pop(virtual_path, None)

        try:
            tmp = self.vault.extract_to_temp(virtual_path)
            self._open_map[virtual_path] = tmp
            open_file(tmp)
            self.status_cb(f"Opened: {file_info['name']}  (temp file will be wiped on close)")

            # Watch for file modifications and re-encrypt
            self._watch_temp(virtual_path, tmp)

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not open file:\n{e}")

    def _watch_temp(self, virtual_path: str, tmp_path: str):
        """Watch a temp file for changes and re-encrypt on modification.
        Uses weakref so the timer doesn't keep VaultView alive after it's destroyed."""
        import weakref
        try:
            mtime_before = os.path.getmtime(tmp_path)
        except Exception:
            return

        deadline  = time.time() + 1800   # 30 minute max watch window
        self_ref  = weakref.ref(self)     # weak ref — won't prevent GC

        def _check():
            view = self_ref()
            if view is None:
                # VaultView was destroyed — try to wipe temp file
                try:
                    if os.path.exists(tmp_path):
                        import os as _os
                        _os.remove(tmp_path)
                except Exception:
                    pass
                return
            try:
                if not os.path.exists(tmp_path) or time.time() > deadline:
                    view._open_map.pop(virtual_path, None)
                    return
                mtime_after = os.path.getmtime(tmp_path)
                if mtime_after != mtime_before:
                    view.vault.reimport_temp(virtual_path, tmp_path)
                    view._open_map.pop(virtual_path, None)
                    view._refresh()
                    view.status_cb(f"Re-encrypted: {Path(virtual_path).name}")
                else:
                    QTimer.singleShot(3000, _check)
            except Exception as e:
                log.warning(f"Watch error: {e}")
                view._open_map.pop(virtual_path, None)
                try:
                    if os.path.exists(tmp_path):
                        view.vault.secure_delete_temp(tmp_path)
                except Exception:
                    pass

        QTimer.singleShot(3000, _check)

    def _export_selected(self):
        sel = self.file_list.selected_files()
        if not sel:
            QMessageBox.information(self, "Export", "Select files to export first.")
            return
        dest = QFileDialog.getExistingDirectory(self, "Export To", str(Path.home()))
        if not dest:
            return

        self._set_busy(True)
        self.progress.setVisible(True)
        self.progress.setRange(0, len(sel))
        self.status_cb(f"Exporting {len(sel)} file(s)...")

        eworker = ExportWorker(self.vault, sel, dest)
        self._active_workers.append(eworker)
        eworker.progress.connect(lambda c, t: self.progress.setValue(c))
        eworker.finished.connect(self._export_done)
        eworker.finished.connect(lambda: self._active_workers.remove(eworker) if eworker in self._active_workers else None)
        eworker.error_msg.connect(lambda m: log.warning(m))
        eworker.start()

    def _export_done(self, ok: int, fail: int, dest: str):
        self.progress.setVisible(False)
        self._set_busy(False)
        msg = f"Exported {ok} file(s) to {dest}."
        if fail:
            msg += f" {fail} failed."
        self.status_cb(msg)

    def _delete_files(self, files: list[dict]):
        names = "\n".join(f["name"] for f in files[:5])
        if len(files) > 5:
            names += f"\n... and {len(files)-5} more"
        reply = QMessageBox.question(
            self, "Delete Files",
            f"Permanently delete from vault:\n\n{names}\n\nThis cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        paths = [f["path"] for f in files]
        self._set_busy(True)
        self.progress.setVisible(True)
        self.progress.setRange(0, len(paths))
        self.status_cb(f"Deleting {len(paths)} file(s)...")

        dworker = DeleteWorker(self.vault, paths)
        self._active_workers.append(dworker)
        dworker.progress.connect(lambda c, t: self.progress.setValue(c))
        dworker.error_msg.connect(lambda m: log.warning(m))
        dworker.finished.connect(self._delete_done)
        dworker.finished.connect(lambda: self._active_workers.remove(dworker) if dworker in self._active_workers else None)
        dworker.start()

    def _delete_done(self, success: int, failed: int):
        self.progress.setVisible(False)
        self._set_busy(False)
        self._refresh()
        msg = f"Deleted {success} file(s)."
        if failed:
            msg += f" {failed} failed."
        self.status_cb(msg)

    def _delete_folder(self, folder_path: str):
        """Delete all files inside a folder recursively."""
        all_files = self.vault.list_files()
        # Find all files whose path starts with folder_path/
        to_delete = [
            f for f in all_files
            if f["path"] == folder_path
            or f["path"].startswith(folder_path + "/")
        ]
        if not to_delete:
            # Already empty — just refresh to clear ghost
            self._refresh()
            return

        folder_name = folder_path.split("/")[-1]
        reply = QMessageBox.question(
            self, "Delete Folder",
            f"Delete folder '{folder_name}' and all {len(to_delete)} file(s) inside?\n\n"
            "This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        paths = [f["path"] for f in to_delete]
        self._set_busy(True)
        self.progress.setVisible(True)
        self.progress.setRange(0, len(paths))
        self.status_cb(f"Deleting folder '{folder_name}'...")

        dworker2 = DeleteWorker(self.vault, paths)
        self._active_workers.append(dworker2)
        dworker2.progress.connect(lambda c, t: self.progress.setValue(c))
        dworker2.error_msg.connect(lambda m: log.warning(m))
        dworker2.finished.connect(self._delete_done)
        dworker2.finished.connect(lambda: self._active_workers.remove(dworker2) if dworker2 in self._active_workers else None)
        dworker2.start()

    def _set_busy(self, busy: bool):
        """Disable toolbar actions during long operations to prevent double-clicks."""
        self._toolbar.setEnabled(not busy)
        self.file_list.setEnabled(not busy)

    # ── Integrity check ───────────────────────────────────────────────────

    def _check_integrity(self):
        """Scan every file and verify AES-GCM authentication tag."""
        stats = self.vault.vault_stats()
        if stats["file_count"] == 0:
            QMessageBox.information(self, "Integrity Check", "Vault is empty.")
            return

        self._set_busy(True)
        self.progress.setVisible(True)
        self.progress.setRange(0, stats["file_count"])
        self.status_cb("Checking integrity...")

        iworker = IntegrityWorker(self.vault)
        self._active_workers.append(iworker)
        iworker.progress.connect(lambda c, t: self.progress.setValue(c))
        iworker.finished.connect(self._integrity_done)
        iworker.finished.connect(lambda: self._active_workers.remove(iworker) if iworker in self._active_workers else None)
        iworker.start()

    def _integrity_done(self, result: dict):
        self.progress.setVisible(False)
        self._set_busy(False)
        ok        = len(result["ok"])
        corrupted = result["corrupted"]
        total     = result["total"]

        if not corrupted:
            QMessageBox.information(
                self, "✓ Integrity OK",
                f"All {ok} files passed authentication.\n\n"
                "No corruption or tampering detected."
            )
            self.status_cb(f"Integrity check passed — {ok} files OK.")
        else:
            msg = (
                f"{ok}/{total} files are healthy.\n\n"
                f"⚠  {len(corrupted)} CORRUPTED file(s):\n"
                + "\n".join(f"  • {p}" for p in corrupted[:20])
            )
            if len(corrupted) > 20:
                msg += f"\n  ... and {len(corrupted)-20} more"
            msg += "\n\nUse RECOVER to extract all readable files."
            QMessageBox.critical(self, "Corruption Detected", msg)
            self.status_cb(f"⚠ {len(corrupted)} corrupted file(s) found.")

    # ── Backup ───────────────────────────────────────────────────────────

    def _backup_vault(self):
        """Create a safe copy of the vault using SQLite's atomic backup API."""
        ts      = int(time.time())
        stem    = self.vault_path
        for ext in (".ykc", ".safebox"):
            stem = stem.replace(ext, "")
        default = f"{stem}_backup_{ts}.ykc"
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Backup As", default,
            "YukiCrypt Vault (*.ykc *.safebox);;All Files (*)"
        )
        if not path:
            return

        # Check destination has enough space
        try:
            vault_size = os.path.getsize(self.vault_path)
            free       = shutil.disk_usage(os.path.dirname(os.path.abspath(path))).free
            if vault_size > free:
                QMessageBox.critical(
                    self, "Not Enough Space",
                    f"Vault size: {fmt_size(vault_size)}\nFree space: {fmt_size(free)}"
                )
                return
        except Exception:
            pass

        self._set_busy(True)
        self.status_cb("Creating backup...")

        bworker = BackupWorker(self.vault, path)
        self._active_workers.append(bworker)
        bworker.finished.connect(self._backup_done)
        bworker.finished.connect(lambda: self._active_workers.remove(bworker) if bworker in self._active_workers else None)
        bworker.start()

    def _backup_done(self, success: bool, msg: str):
        self._set_busy(False)
        if success:
            parts     = msg.split("|")
            path      = parts[0]
            saved     = int(parts[1]) if len(parts) > 1 else 0
            size_info = f"\nSpace saved vs original: {fmt_size(saved)}" if saved > 0 else ""
            self.status_cb(f"Backup saved: {Path(path).name}")
            QMessageBox.information(
                self, "Backup Complete",
                f"Vault backed up to:\n{path}\n"
                f"Backup is already compact — no wasted space.{size_info}\n\n"
                "Encrypted with your same password."
            )
        else:
            self.status_cb("Backup failed.")
            QMessageBox.critical(self, "Backup Failed", f"Error:\n{msg}")

    # ── Compact ──────────────────────────────────────────────────────────

    def _compact_vault(self):
        """Run VACUUM to reclaim space freed by deleted files."""
        stats = self.vault.vault_stats()
        db_size = stats["db_size"]

        reply = QMessageBox.question(
            self, "Compact Vault",
            f"Current vault size: {fmt_size(db_size)}\n\n"
            "This will rebuild the vault file and reclaim space from deleted files.\n"
            "The vault stays encrypted throughout.\n\n"
            "Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        self._set_busy(True)
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)   # indeterminate — VACUUM duration varies
        self.status_cb("Compacting vault...")

        cworker = CompactWorker(self.vault)
        self._active_workers.append(cworker)
        cworker.finished.connect(self._compact_done)
        cworker.finished.connect(
            lambda: self._active_workers.remove(cworker)
            if cworker in self._active_workers else None
        )
        cworker.start()

    def _compact_done(self, success: bool, msg: str):
        self.progress.setVisible(False)
        self._set_busy(False)
        self._refresh()
        if success:
            saved = int(msg)
            if saved > 0:
                QMessageBox.information(
                    self, "Compact Complete",
                    f"Vault compacted successfully.\n\nSpace reclaimed: {fmt_size(saved)}"
                )
                self.status_cb(f"Compacted — saved {fmt_size(saved)}.")
            else:
                QMessageBox.information(
                    self, "Compact Complete",
                    "Vault is already compact — no free space to reclaim."
                )
                self.status_cb("Vault already compact.")
        else:
            QMessageBox.critical(self, "Compact Failed", f"Error:\n{msg}")
            self.status_cb("Compact failed.")

    # ── Recovery ─────────────────────────────────────────────────────────

    def _recover_vault(self):
        """Extract all readable files to a folder, skipping corrupted ones."""
        reply = QMessageBox.question(
            self, "Emergency Recovery",
            "This will extract ALL readable files to a folder you choose.\n\n"
            "Corrupted files will be skipped.\n"
            "Files will be decrypted — choose a safe location.\n\n"
            "Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        dest = QFileDialog.getExistingDirectory(
            self, "Recover Files To", str(Path.home())
        )
        if not dest:
            return

        # Check disk space
        try:
            stats     = self.vault.vault_stats()
            needed    = stats["total_size"]
            free      = shutil.disk_usage(dest).free
            if needed > free:
                QMessageBox.critical(
                    self, "Not Enough Space",
                    f"Need: {fmt_size(needed)}\nFree: {fmt_size(free)}"
                )
                return
        except Exception:
            pass

        self._set_busy(True)
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)   # indeterminate
        self.status_cb("Recovering files...")

        rworker = RecoveryWorker(self.vault, dest)
        self._active_workers.append(rworker)
        rworker.progress.connect(
            lambda c, t: (self.progress.setRange(0, t), self.progress.setValue(c))
        )
        rworker.finished.connect(self._recovery_done)
        rworker.finished.connect(lambda: self._active_workers.remove(rworker) if rworker in self._active_workers else None)
        rworker.start()

    def _recovery_done(self, result: dict):
        self.progress.setVisible(False)
        self._set_busy(False)
        recovered = len(result["recovered"])
        failed    = len(result["failed"])

        msg = f"Recovery complete.\n\n✓ Recovered: {recovered} file(s)"
        if failed:
            msg += f"\n✗ Could not recover: {failed} file(s) (corrupted)"
        QMessageBox.information(self, "Recovery Complete", msg)
        self.status_cb(f"Recovery: {recovered} files saved, {failed} unrecoverable.")

    def _toggle_theme(self):
        """Switch between dark and light theme."""
        app = QApplication.instance()
        if current_theme()["name"] == "Dark":
            apply_theme(app, THEME_LIGHT)
            self._theme_btn.setText("🌙  DARK")
            # Sync lock screen button if it's accessible
            mw = self.window()
            if hasattr(mw, "lock_screen") and hasattr(mw.lock_screen, "_theme_btn"):
                mw.lock_screen._theme_btn.setText("🌙  DARK THEME")
        else:
            apply_theme(app, THEME_DARK)
            self._theme_btn.setText("☀  LIGHT")
            mw = self.window()
            if hasattr(mw, "lock_screen") and hasattr(mw.lock_screen, "_theme_btn"):
                mw.lock_screen._theme_btn.setText("☀  LIGHT THEME")
        # Update dynamic label colors that hardcode hex values
        t = current_theme()
        self.stats_lbl.setStyleSheet(
            f"color: {t['stats_color']}; font-size: 10px; padding: 0 12px;"
        )
        self.info_lbl.setStyleSheet(
            f"color: {t['sidebar_info']}; font-size: 9px; padding: 12px; letter-spacing: 1px;"
        )
        self.drop_hint.setStyleSheet(
            f"color: {t['fg_dimmer']}; border-top: 1px solid {t['border']}; font-size: 10px;"
        )

    def _sidebar_context_menu(self, pos: QPoint):
        item = self.folder_tree.itemAt(pos)
        if not item:
            return
        folder_path = item.data(0, Qt.ItemDataRole.UserRole)
        if not folder_path:  # "All Files" root — no delete
            return
        folder_name = folder_path.split("/")[-1]
        menu = QMenu(self)
        del_act = menu.addAction(f"Delete folder '{folder_name}' and all contents")
        del_act.triggered.connect(lambda: self._delete_folder(folder_path))
        menu.exec(self.folder_tree.viewport().mapToGlobal(pos))

    # ── Folder sidebar ────────────────────────────────────────────────────

    def _folder_changed(self, current, previous):
        if not self._refreshing:
            self._refresh(rebuild_tree=False)

    def _refresh(self, rebuild_tree=True):
        self._refreshing = True
        try:
            self.__refresh(rebuild_tree)
        finally:
            self._refreshing = False

    def __refresh(self, rebuild_tree=True):
        all_files = self.vault.list_files()

        if rebuild_tree:
            self._rebuild_folder_tree(all_files)

        # Determine which folder is selected
        cur = self.folder_tree.currentItem()
        selected_path = cur.data(0, Qt.ItemDataRole.UserRole) if cur else ""
        if selected_path is None:
            selected_path = ""

        # Files directly in this folder only (not deeper), hide .keep placeholders
        direct_files = [
            f for f in all_files
            if f["folder"] == selected_path and not f.get("is_keep")
        ]

        # Direct subfolders only (one level deep)
        all_folders = set()
        for f in all_files:
            parts = f["path"].split("/")
            for i in range(1, len(parts)):
                all_folders.add("/".join(parts[:i]))

        if selected_path == "":
            # Root: direct subfolders are those with no "/" in them
            direct_subs = sorted(p for p in all_folders if "/" not in p)
        else:
            prefix = selected_path + "/"
            direct_subs = sorted(
                p for p in all_folders
                if p.startswith(prefix) and "/" not in p[len(prefix):]
            )

        self.file_list.populate(
            direct_files,
            selected_folder=selected_path,
            subfolders=direct_subs,
            navigate_cb=self._navigate_to,
        )

        # Update stats
        stats = self.vault.vault_stats()
        self.stats_lbl.setText(
            f"{stats['file_count']} files  ·  "
            f"{fmt_size(stats['total_size'])}  ·  "
            f"{stats['cipher']}  ·  {stats['kdf']}"
        )
        self.info_lbl.setText(
            f"{stats['cipher']}\n{stats['kdf']}\n\n"
            f"Vault: {Path(self.vault_path).name}\n"
            f"{fmt_size(stats['db_size'])} on disk"
        )
        self.drop_hint.setVisible(stats["file_count"] == 0)

    def _navigate_to(self, folder_path: str):
        """Navigate to a folder by double-clicking it in the file panel."""
        # Find and select the matching item in the sidebar tree
        def find_item(parent, path):
            for i in range(parent.childCount()):
                child = parent.child(i)
                if child.data(0, Qt.ItemDataRole.UserRole) == path:
                    return child
                found = find_item(child, path)
                if found:
                    return found
            return None

        root = self.folder_tree.invisibleRootItem()
        item = find_item(root, folder_path)
        if item:
            self.folder_tree.setCurrentItem(item)
            self._refresh(rebuild_tree=False)

    def _rebuild_folder_tree(self, all_files: list[dict]):
        """Build the sidebar tree from actual folder structure."""
        self.folder_tree.blockSignals(True)

        # Remember which path was selected
        cur = self.folder_tree.currentItem()
        prev_selected = cur.data(0, Qt.ItemDataRole.UserRole) if cur else None

        self.folder_tree.clear()

        # Root item = All Files
        root_item = QTreeWidgetItem(["  📂  All Files"])
        root_item.setData(0, Qt.ItemDataRole.UserRole, "")
        self.folder_tree.addTopLevelItem(root_item)

        # Collect all unique folder paths and build tree
        folder_paths = set()
        for f in all_files:
            parts = f["path"].split("/")
            # Add every ancestor path
            for i in range(1, len(parts)):
                folder_paths.add("/".join(parts[:i]))

        # Build tree nodes — map of full_path → QTreeWidgetItem
        node_map: dict[str, QTreeWidgetItem] = {"": root_item}

        for folder_path in sorted(folder_paths):
            parts = folder_path.split("/")
            parent_path = "/".join(parts[:-1])
            folder_name = parts[-1]

            parent_node = node_map.get(parent_path, root_item)
            item = QTreeWidgetItem([f"  📁  {folder_name}"])
            item.setData(0, Qt.ItemDataRole.UserRole, folder_path)
            parent_node.addChild(item)
            node_map[folder_path] = item

        self.folder_tree.expandAll()

        # Restore selection or default to root
        restore = node_map.get(prev_selected, root_item) if prev_selected is not None else root_item
        self.folder_tree.setCurrentItem(restore)

        self.folder_tree.blockSignals(False)

    # ── Drag & drop on main widget ────────────────────────────────────────

    def dragEnterEvent(self, e: QDragEnterEvent):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()

    def dropEvent(self, e: QDropEvent):
        urls  = e.mimeData().urls()
        paths = [u.toLocalFile() for u in urls if u.isLocalFile()]
        if paths:
            self._import_files(paths)

    def cleanup_temps(self):
        """Wipe all open temp files and wait for workers — call on lock/close."""
        # Wait up to 3s for any running workers to finish before closing vault
        for worker in list(self._active_workers):
            try:
                worker.wait(3000)   # 3 second timeout
            except Exception:
                pass
        self._active_workers.clear()

        for vpath, tmp in list(self._open_map.items()):
            try:
                self.vault.secure_delete_temp(tmp)
            except Exception:
                pass
        self._open_map.clear()


# ────────────────────────────────────────────────────────────────────────────
# Main window
# ────────────────────────────────────────────────────────────────────────────

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("YukiCrypt")
        self.setMinimumSize(860, 560)
        self.resize(1100, 680)

        self._vault: Vault      = None
        self._vault_path: str   = None
        self._vault_view        = None

        self._build_ui()

    def _build_ui(self):
        # Stack: lock screen / vault view
        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)

        self.lock_screen = LockScreen()
        self.lock_screen.new_vault.connect(self._new_vault)
        self.lock_screen.open_vault.connect(self._open_vault)
        self.stack.addWidget(self.lock_screen)

        # Status bar
        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self._set_status("Ready  ·  No vault open")

    def _set_status(self, msg: str):
        self.status.showMessage(f"  {msg}")

    # ── Vault operations ──────────────────────────────────────────────────

    def _new_vault(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Create New Vault", str(Path.home() / "vault.ykc"),
            "YukiCrypt Vault (*.ykc *.safebox);;All Files (*)"
        )
        if not path:
            return
        if not path.endswith(".ykc"):
            path += ".ykc"

        dlg = PasswordDialog(self, mode="create")
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return

        try:
            pw = dlg.password()
            dlg.deleteLater()   # FIX #12: destroy dialog to clear password from memory
            vault = Vault.create(path, pw)
            self._load_vault(vault, path)
        except VaultError as e:
            log.error(f"Failed to create vault at {path}: {e}")
            QMessageBox.critical(self, "Error", str(e))

    def _open_vault(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open Vault", str(Path.home()),
            "YukiCrypt Vault (*.ykc *.safebox);;All Files (*)"
        )
        if not path:
            return
        self._unlock_vault(path)

    def _unlock_vault(self, path: str):
        while True:
            dlg = PasswordDialog(self, mode="unlock", vault_path=path)
            if dlg.exec() != QDialog.DialogCode.Accepted:
                return

            try:
                pw = dlg.password()
                dlg.deleteLater()
                vault = Vault.open(path, pw)
                self._load_vault(vault, path)
                return
            except WrongPasswordError:
                dlg2 = QMessageBox.question(
                    self, "Wrong Password",
                    "Incorrect password.\n\nTry again?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                )
                if dlg2 != QMessageBox.StandardButton.Yes:
                    return
                # Loop back — show password dialog again
            except TamperedError:
                QMessageBox.critical(self, "Tampered Data",
                    "Vault data authentication failed.\n"
                    "The vault file may have been modified or corrupted.")
                return
            except VaultError as e:
                QMessageBox.critical(self, "Error", str(e))
                return

    def _load_vault(self, vault: Vault, path: str):
        # Remove old vault view if any
        if self._vault_view:
            self._vault_view.cleanup_temps()
            self.stack.removeWidget(self._vault_view)
            self._vault_view.deleteLater()
            self._vault_view = None
        if self._vault:
            self._vault.close()

        self._vault      = vault
        self._vault_path = path

        self._vault_view = VaultView(vault, path, self._set_status)
        self._vault_view.lock_requested.connect(self._lock)
        self.stack.addWidget(self._vault_view)
        self.stack.setCurrentWidget(self._vault_view)

        name = Path(path).stem
        self.setWindowTitle(f"YukiCrypt  —  {name}")
        self._set_status(f"Vault open: {Path(path).name}")

    def _lock(self):
        if self._vault_view:
            self._vault_view.cleanup_temps()
        if self._vault:
            self._vault.close()
            self._vault = None

        if self._vault_view:
            self.stack.removeWidget(self._vault_view)
            self._vault_view.deleteLater()
            self._vault_view = None

        self.stack.setCurrentWidget(self.lock_screen)
        self.setWindowTitle("YukiCrypt")
        self._set_status("Vault locked.")

    def closeEvent(self, event):
        if self._vault_view:
            self._vault_view.cleanup_temps()
        if self._vault:
            self._vault.close()
        event.accept()


# ────────────────────────────────────────────────────────────────────────────
# Entry point
# ────────────────────────────────────────────────────────────────────────────

def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    apply_theme(app, THEME_DARK)   # default: dark theme

    icon = make_icon()
    app.setWindowIcon(icon)

    win = MainWindow()
    win.setWindowIcon(icon)
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
