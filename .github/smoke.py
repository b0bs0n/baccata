"""Import everything Baccata needs from a packaged bundle, so a trimmed
PySide6 (pyproject cleanup_paths) that lost a needed piece fails CI.
    python -S .github/smoke.py <dir holding app/ and app_packages/>"""
import sys
root = sys.argv[1]
sys.path[:0] = [f'{root}/app_packages', f'{root}/app']
from PySide6 import QtCore, QtGui, QtWidgets, QtMultimedia, QtMultimediaWidgets
import baccata.editor, baccata.dialogs, baccata.knxsecure, zxingcpp, dukpy, cryptography
from PySide6.QtWidgets import QApplication
app = QApplication([])
from PySide6.QtGui import QImageReader
fmts = {bytes(f).decode() for f in QImageReader.supportedImageFormats()}
assert {'png', 'jpeg', 'svg'} <= fmts, fmts
from PySide6.QtMultimedia import QMediaDevices
print('ok', QtCore.__file__, 'cameras', len(QMediaDevices.videoInputs()))
