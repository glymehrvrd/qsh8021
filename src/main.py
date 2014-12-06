import sys
import locale
import dialWindow

from PyQt4 import QtCore, QtGui

if __name__ == '__main__':

    ownTrans = QtCore.QTranslator()
    locale = locale.getdefaultlocale()[0]
    ownTrans.load(':/translate/Langs/' + locale + '.qm')
    qtTrans = QtCore.QTranslator()
    qtTrans.load(':/translate/Langs/qt_' + locale + '.qm')

    app = QtGui.QApplication(sys.argv)
    app.installTranslator(ownTrans)
    app.installTranslator(qtTrans)
    mainWindow = dialWindow.DialWindow()
    mainWindow.show()
    app.exec_()
