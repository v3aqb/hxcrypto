import base64
import time
import hashlib

from PyQt5 import QtWidgets, QtCore

from hxcrypto import ECC, AEncryptor, encrypt

from .ui_crypto import Ui_Crypto

CTX = b'v3aqb.hxcrypto'
METHOD = 'chacha20-ietf-poly1305'


# disable ivchecker
class DummyIVChecker:
    '''DummyIVChecker'''
    def __init__(self, size, timeout):
        pass

    def check(self, key, iv):
        pass


encrypt.IV_CHECKER = DummyIVChecker(1, 1)


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.ui = Ui_Crypto()
        self.ui.setupUi(self)

        self.__ecckey = None

        self.__key = None
        self.otherKey = ""
        self._last_active = time.time()

        self.ui.textEdit.setWordWrapMode(3)
        self.ui.psktextEdit.setWordWrapMode(3)

        self.ui.pubkeyButton.clicked.connect(self.copy_pubkey)
        self.ui.otherKeyEdit.editingFinished.connect(self.exchange)

        self.ui.encryptButton.clicked.connect(self.encrypt)
        self.ui.decryptButton.clicked.connect(self.decrypt)
        self.ui.resetPrivateButton.clicked.connect(self.resetPrivate)
        self.ui.resetExchangeButton.clicked.connect(self.resetExchange)
        self.ui.decryptButton.clicked.connect(self.decrypt)

        self.ui.PSKencryptButton.clicked.connect(self.pskencrypt)
        self.ui.PSKdecryptButton.clicked.connect(self.pskdecrypt)

        self.resetPrivate()
        self.show()

    def resetPrivate(self):
        self.__ecckey = ECC(256)
        pubk = self.get_pubkey()
        pubk_hash = hashlib.md5(pubk).digest()
        pubk_hash = base64.b64encode(pubk_hash).decode()[:8]
        _tr = QtCore.QCoreApplication.translate
        self.ui.pubkeyButton.setText(_tr('Crypto', 'Copy Public Key') + ' - ' + pubk_hash)
        self.resetExchange()
        self.ui.otherKeyEdit.setText(self.otherKey)
        self.exchange()

    def get_pubkey(self):
        return self.__ecckey.get_pub_key()

    def copy_pubkey(self):
        public_key = self.get_pubkey()
        public_key = base64.b64encode(public_key).decode()
        import pyperclip
        pyperclip.copy(public_key)

    def resetExchange(self):
        self.__key = None
        self.ui.otherKeyEdit.setText("")
        self.ui.otherKeyEdit.setReadOnly(False)

    def exchange(self):
        if self.__key:
            return
        otherkey = self.ui.otherKeyEdit.text()
        self.otherKey = otherkey
        try:
            otherkey = base64.b64decode(otherkey)
            self.__key = self.__ecckey.get_dh_key(otherkey)
        except Exception as err:
            self.statusBar().showMessage(repr(err), 10000)
        else:
            pubk_hash = hashlib.md5(otherkey).digest()
            pubk_hash = base64.b64encode(pubk_hash).decode()[:8]
            self.ui.otherKeyEdit.setText(pubk_hash)
            self.ui.otherKeyEdit.setReadOnly(True)

    def encrypt(self):
        if time.time() - self._last_active < 0.3:
            return

        crypto = AEncryptor(self.__key, METHOD, CTX)
        plain_text = self.ui.textEdit.toPlainText()
        if not plain_text:
            return
        try:
            plain_text = plain_text.encode('utf-8')
            cipher_text = crypto.encrypt(plain_text)
            cipher_text = base64.b64encode(cipher_text).decode()
        except Exception as err:
            self.statusBar().showMessage(repr(err), 10000)
            return

        self.ui.textEdit.setPlainText(cipher_text)

        self._last_active = time.time()

    def decrypt(self):
        if time.time() - self._last_active < 0.3:
            return

        cipher_text = self.ui.textEdit.toPlainText()
        if not cipher_text:
            return

        try:
            cipher_text = base64.b64decode(cipher_text.encode())
            crypto = AEncryptor(self.__key, METHOD, CTX)
            plain_text = crypto.decrypt(cipher_text)
            if not plain_text:
                return
            self.ui.textEdit.setPlainText(plain_text.decode('utf-8'))
        except Exception as err:
            self.statusBar().showMessage(repr(err), 10000)
            return

        self._last_active = time.time()

    def pskencrypt(self):
        if time.time() - self._last_active < 0.3:
            return
        key = self.ui.pskEdit.text()
        key = hashlib.sha256(key.encode('utf-8')).digest()

        plain_text = self.ui.psktextEdit.toPlainText()
        if not plain_text:
            return
        try:
            plain_text = plain_text.encode('utf-8')
            crypto = AEncryptor(key, METHOD, CTX)
            cipher_text = crypto.encrypt(plain_text)
            cipher_text = base64.b64encode(cipher_text).decode()
        except Exception as err:
            self.statusBar().showMessage(repr(err), 10000)
            return

        self.ui.psktextEdit.setPlainText(cipher_text)

        self._last_active = time.time()

    def pskdecrypt(self):
        if time.time() - self._last_active < 0.3:
            return

        key = self.ui.pskEdit.text()
        key = hashlib.sha256(key.encode('utf-8')).digest()

        cipher_text = self.ui.psktextEdit.toPlainText()
        if not cipher_text:
            return

        try:
            cipher_text = base64.b64decode(cipher_text.encode())
            crypto = AEncryptor(key, METHOD, CTX)
            plain_text = crypto.decrypt(cipher_text)
            if not plain_text:
                return
            self.ui.psktextEdit.setPlainText(plain_text.decode('utf-8'))
        except Exception as err:
            self.statusBar().showMessage(repr(err), 10000)
            return

        self._last_active = time.time()
