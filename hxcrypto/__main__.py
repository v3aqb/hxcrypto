import os
import sys
try:
    from PyQt6 import QtCore, QtWidgets
    pyqt6 = True
except ImportError:
    pyqt6 = False
    from PyQt5 import QtCore, QtWidgets
from .crypto import MainWindow


def main():
    if os.name == 'nt':
        import ctypes
        myappid = 'v3aqb.crypto'  # arbitrary string
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)

    app = QtWidgets.QApplication([])

    translator = QtCore.QTranslator()
    base_path = os.path.dirname(os.path.realpath(__file__))
    locale = QtCore.QLocale.system().name()
    path = os.path.join(base_path, 'translate', locale + '.qm')
    translator.load(path)
    app.installTranslator(translator)

    if not pyqt6:
        app.setAttribute(QtCore.Qt.AA_EnableHighDpiScaling)
        app.setAttribute(QtCore.Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    ex = MainWindow()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
