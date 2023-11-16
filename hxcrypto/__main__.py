import os
import sys
from PyQt5 import QtGui, QtCore, QtWidgets
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

    ex = MainWindow()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
