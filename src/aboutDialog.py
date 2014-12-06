#!/usr/bin/env python

import ui_aboutDialog
from PyQt4 import QtCore, QtGui

class AboutDialog(QtGui.QDialog, ui_aboutDialog.Ui_AboutDialog):
    
    def __init__(self, parent = None):
        super(AboutDialog, self).__init__(parent)
        self.setupUi(self)

    def aboutQt(self):
        QtGui.QMessageBox.aboutQt(self, QtGui.QApplication.translate("AboutDialog", "About Qt"))
