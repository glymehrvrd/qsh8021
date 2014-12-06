# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'aboutUI.ui'
#
# Created: Mon Sep  5 15:52:22 2011
#      by: PyQt4 UI code generator 4.8.5
#
# WARNING! All changes made in this file will be lost!

from PyQt4 import QtCore, QtGui

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    _fromUtf8 = lambda s: s

class Ui_AboutDialog(object):
    def setupUi(self, AboutDialog):
        AboutDialog.setObjectName(_fromUtf8("AboutDialog"))
        AboutDialog.resize(800, 617)
        AboutDialog.setWindowTitle(QtGui.QApplication.translate("AboutDialog", "AboutDialog", None, QtGui.QApplication.UnicodeUTF8))
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(_fromUtf8(":/logo/image/8021x.ico")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        AboutDialog.setWindowIcon(icon)
        self.gridLayout_2 = QtGui.QGridLayout(AboutDialog)
        self.gridLayout_2.setObjectName(_fromUtf8("gridLayout_2"))
        self.gridLayout = QtGui.QGridLayout()
        self.gridLayout.setObjectName(_fromUtf8("gridLayout"))
        self.label_3 = QtGui.QLabel(AboutDialog)
        self.label_3.setMinimumSize(QtCore.QSize(141, 111))
        self.label_3.setMaximumSize(QtCore.QSize(141, 111))
        self.label_3.setText(_fromUtf8(""))
        self.label_3.setPixmap(QtGui.QPixmap(_fromUtf8(":/uestc/image/uestc.gif")))
        self.label_3.setScaledContents(True)
        self.label_3.setObjectName(_fromUtf8("label_3"))
        self.gridLayout.addWidget(self.label_3, 0, 0, 1, 1)
        self.label_2 = QtGui.QLabel(AboutDialog)
        self.label_2.setText(QtGui.QApplication.translate("AboutDialog", "Welcome to use the 802.1x dialer developed by Python and PyQt\n"
"\n"
"Instructions:\n"
"\n"
"1.This program needs PyQt Library to run\n"
"\n"
"2.Error codes:\n"
"\n"
"Identity Failed: \n"
"(1) Your identity is not existed\n"
"(2) Your identity is occupied by others\n"
"(3) If you can dial campus network successfully, that means your accounts charges own\n"
"\n"
"Password Failed:\n"
"The password you entered is not correct\n"
"\n"
"Stopping at Auth Starting...:\n"
"Cannot send auth packets, please check the network interface card \n"
"you chosed is correct or check the cable is connected or not\n"
"\n"
"3.Refreshing IP Instructions:\n"
"\n"
"This program uses dbus and Network Manager to obtain new IP address after auth success. \n"
"However, in some linux distributions, the dbus and Network Manager \n"
"is not supported or default provided by the distributions.\n"
"\n"
"If the program cannot obtain IP address, please use the dhcp command \n"
"in your distribution to refresh IP address manually.\n"
"\n"
"\n"
"Contact Authoer:\n"
"\n"
"E-mail & Gtalk: chenhuan0@gmail.com", None, QtGui.QApplication.UnicodeUTF8))
        self.label_2.setObjectName(_fromUtf8("label_2"))
        self.gridLayout.addWidget(self.label_2, 0, 1, 2, 1)
        spacerItem = QtGui.QSpacerItem(20, 338, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Expanding)
        self.gridLayout.addItem(spacerItem, 1, 0, 1, 1)
        self.gridLayout_2.addLayout(self.gridLayout, 0, 0, 1, 1)
        self.horizontalLayout = QtGui.QHBoxLayout()
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        spacerItem1 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem1)
        self.OKButton = QtGui.QPushButton(AboutDialog)
        self.OKButton.setText(QtGui.QApplication.translate("AboutDialog", "OK", None, QtGui.QApplication.UnicodeUTF8))
        self.OKButton.setObjectName(_fromUtf8("OKButton"))
        self.horizontalLayout.addWidget(self.OKButton)
        spacerItem2 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem2)
        self.AboutQTButton = QtGui.QPushButton(AboutDialog)
        self.AboutQTButton.setText(QtGui.QApplication.translate("AboutDialog", "AboutQt", None, QtGui.QApplication.UnicodeUTF8))
        self.AboutQTButton.setObjectName(_fromUtf8("AboutQTButton"))
        self.horizontalLayout.addWidget(self.AboutQTButton)
        spacerItem3 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem3)
        self.gridLayout_2.addLayout(self.horizontalLayout, 1, 0, 1, 1)

        self.retranslateUi(AboutDialog)
        QtCore.QObject.connect(self.OKButton, QtCore.SIGNAL(_fromUtf8("clicked()")), AboutDialog.close)
        QtCore.QObject.connect(self.AboutQTButton, QtCore.SIGNAL(_fromUtf8("clicked()")), AboutDialog.aboutQt)
        QtCore.QMetaObject.connectSlotsByName(AboutDialog)

    def retranslateUi(self, AboutDialog):
        pass

