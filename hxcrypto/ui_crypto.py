# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file './hxcrypto\crypto.ui'
#
# Created by: PyQt5 UI code generator 5.15.5
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_Crypto(object):
    def setupUi(self, Crypto):
        Crypto.setObjectName("Crypto")
        Crypto.resize(482, 477)
        self.centralwidget = QtWidgets.QWidget(Crypto)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.centralwidget.sizePolicy().hasHeightForWidth())
        self.centralwidget.setSizePolicy(sizePolicy)
        self.centralwidget.setMaximumSize(QtCore.QSize(9999, 9999))
        self.centralwidget.setObjectName("centralwidget")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(self.centralwidget)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.tabWidget = QtWidgets.QTabWidget(self.centralwidget)
        self.tabWidget.setObjectName("tabWidget")
        self.tab_1 = QtWidgets.QWidget()
        self.tab_1.setObjectName("tab_1")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.tab_1)
        self.verticalLayout.setObjectName("verticalLayout")
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.verticalLayout_4 = QtWidgets.QVBoxLayout()
        self.verticalLayout_4.setObjectName("verticalLayout_4")
        self.label = QtWidgets.QLabel(self.tab_1)
        self.label.setObjectName("label")
        self.verticalLayout_4.addWidget(self.label)
        self.pubkeyButton = QtWidgets.QPushButton(self.tab_1)
        self.pubkeyButton.setObjectName("pubkeyButton")
        self.verticalLayout_4.addWidget(self.pubkeyButton)
        self.horizontalLayout_3.addLayout(self.verticalLayout_4)
        self.resetPrivateButton = QtWidgets.QPushButton(self.tab_1)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(30)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.resetPrivateButton.sizePolicy().hasHeightForWidth())
        self.resetPrivateButton.setSizePolicy(sizePolicy)
        self.resetPrivateButton.setMinimumSize(QtCore.QSize(120, 0))
        self.resetPrivateButton.setObjectName("resetPrivateButton")
        self.horizontalLayout_3.addWidget(self.resetPrivateButton)
        self.horizontalLayout_3.setStretch(0, 3)
        self.horizontalLayout_3.setStretch(1, 1)
        self.verticalLayout.addLayout(self.horizontalLayout_3)
        self.horizontalLayout_5 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_5.setObjectName("horizontalLayout_5")
        self.verticalLayout_6 = QtWidgets.QVBoxLayout()
        self.verticalLayout_6.setObjectName("verticalLayout_6")
        self.label_2 = QtWidgets.QLabel(self.tab_1)
        self.label_2.setObjectName("label_2")
        self.verticalLayout_6.addWidget(self.label_2)
        self.otherKeyEdit = QtWidgets.QLineEdit(self.tab_1)
        self.otherKeyEdit.setObjectName("otherKeyEdit")
        self.verticalLayout_6.addWidget(self.otherKeyEdit)
        self.horizontalLayout_5.addLayout(self.verticalLayout_6)
        self.resetExchangeButton = QtWidgets.QPushButton(self.tab_1)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(30)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.resetExchangeButton.sizePolicy().hasHeightForWidth())
        self.resetExchangeButton.setSizePolicy(sizePolicy)
        self.resetExchangeButton.setMinimumSize(QtCore.QSize(120, 0))
        self.resetExchangeButton.setObjectName("resetExchangeButton")
        self.horizontalLayout_5.addWidget(self.resetExchangeButton)
        self.horizontalLayout_5.setStretch(0, 6)
        self.horizontalLayout_5.setStretch(1, 1)
        self.verticalLayout.addLayout(self.horizontalLayout_5)
        self.label_3 = QtWidgets.QLabel(self.tab_1)
        self.label_3.setObjectName("label_3")
        self.verticalLayout.addWidget(self.label_3)
        self.textEdit = QtWidgets.QPlainTextEdit(self.tab_1)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.textEdit.sizePolicy().hasHeightForWidth())
        self.textEdit.setSizePolicy(sizePolicy)
        self.textEdit.setObjectName("textEdit")
        self.verticalLayout.addWidget(self.textEdit)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setSizeConstraint(QtWidgets.QLayout.SetMaximumSize)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.encryptButton = QtWidgets.QPushButton(self.tab_1)
        self.encryptButton.setObjectName("encryptButton")
        self.horizontalLayout.addWidget(self.encryptButton)
        self.decryptButton = QtWidgets.QPushButton(self.tab_1)
        self.decryptButton.setObjectName("decryptButton")
        self.horizontalLayout.addWidget(self.decryptButton)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.tabWidget.addTab(self.tab_1, "")
        self.tab_2 = QtWidgets.QWidget()
        self.tab_2.setObjectName("tab_2")
        self.verticalLayout_3 = QtWidgets.QVBoxLayout(self.tab_2)
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.label_4 = QtWidgets.QLabel(self.tab_2)
        self.label_4.setObjectName("label_4")
        self.verticalLayout_3.addWidget(self.label_4)
        self.pskEdit = QtWidgets.QLineEdit(self.tab_2)
        self.pskEdit.setEchoMode(QtWidgets.QLineEdit.PasswordEchoOnEdit)
        self.pskEdit.setObjectName("pskEdit")
        self.verticalLayout_3.addWidget(self.pskEdit)
        self.psktextEdit = QtWidgets.QPlainTextEdit(self.tab_2)
        self.psktextEdit.setObjectName("psktextEdit")
        self.verticalLayout_3.addWidget(self.psktextEdit)
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setSizeConstraint(QtWidgets.QLayout.SetMaximumSize)
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.PSKencryptButton = QtWidgets.QPushButton(self.tab_2)
        self.PSKencryptButton.setObjectName("PSKencryptButton")
        self.horizontalLayout_2.addWidget(self.PSKencryptButton)
        self.PSKdecryptButton = QtWidgets.QPushButton(self.tab_2)
        self.PSKdecryptButton.setObjectName("PSKdecryptButton")
        self.horizontalLayout_2.addWidget(self.PSKdecryptButton)
        self.verticalLayout_3.addLayout(self.horizontalLayout_2)
        self.tabWidget.addTab(self.tab_2, "")
        self.tab = QtWidgets.QWidget()
        self.tab.setObjectName("tab")
        self.verticalLayout_5 = QtWidgets.QVBoxLayout(self.tab)
        self.verticalLayout_5.setObjectName("verticalLayout_5")
        self.b64TextEdit = QtWidgets.QPlainTextEdit(self.tab)
        self.b64TextEdit.setObjectName("b64TextEdit")
        self.verticalLayout_5.addWidget(self.b64TextEdit)
        self.horizontalLayout_4 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")
        self.b64EncodeButton = QtWidgets.QPushButton(self.tab)
        self.b64EncodeButton.setObjectName("b64EncodeButton")
        self.horizontalLayout_4.addWidget(self.b64EncodeButton)
        self.b64DecodeButton = QtWidgets.QPushButton(self.tab)
        self.b64DecodeButton.setObjectName("b64DecodeButton")
        self.horizontalLayout_4.addWidget(self.b64DecodeButton)
        self.verticalLayout_5.addLayout(self.horizontalLayout_4)
        self.tabWidget.addTab(self.tab, "")
        self.verticalLayout_2.addWidget(self.tabWidget)
        Crypto.setCentralWidget(self.centralwidget)
        self.statusBar = QtWidgets.QStatusBar(Crypto)
        self.statusBar.setObjectName("statusBar")
        Crypto.setStatusBar(self.statusBar)

        self.retranslateUi(Crypto)
        self.tabWidget.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(Crypto)

    def retranslateUi(self, Crypto):
        _translate = QtCore.QCoreApplication.translate
        Crypto.setWindowTitle(_translate("Crypto", "hxcrypto"))
        self.label.setText(_translate("Crypto", "Step1: Send your public key to other side"))
        self.pubkeyButton.setText(_translate("Crypto", "Copy Public Key"))
        self.resetPrivateButton.setText(_translate("Crypto", "Reset Private Key"))
        self.label_2.setText(_translate("Crypto", "Step2: Paste public key from other side below"))
        self.resetExchangeButton.setText(_translate("Crypto", "Reset Key Exchange"))
        self.label_3.setText(_translate("Crypto", "Step3: Do encrypt / decrypt here"))
        self.encryptButton.setText(_translate("Crypto", "Encrypt"))
        self.decryptButton.setText(_translate("Crypto", "Decrypt"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_1), _translate("Crypto", "ECDH"))
        self.label_4.setText(_translate("Crypto", "Pre Shared Key"))
        self.PSKencryptButton.setText(_translate("Crypto", "Encrypt"))
        self.PSKdecryptButton.setText(_translate("Crypto", "Decrypt"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_2), _translate("Crypto", "AEAD"))
        self.b64EncodeButton.setText(_translate("Crypto", "Encode"))
        self.b64DecodeButton.setText(_translate("Crypto", "Decode"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab), _translate("Crypto", "Base64"))
