#!/usr/bin/env python

import time
import os
import re
import sys
import getpass
from PyQt4 import QtCore, QtGui
import ui_dialWindow
import aboutDialog
import dot1x
from struct import pack, unpack
import array
import socket
import fcntl

AUTH_BEGIN = 4000
SEND_IDENTITY = 5000
SEND_PASSWORD = 5001
SUCCESS = 5002
IDENTITY_FAILED = 7003
PASSWORD_FAILED = 7004
DISCONNECTED = 6000
DHCP_FAILED = 8000

configFilePath = os.path.expanduser('~') + '/.802.1x'

class DialWindow(QtGui.QWidget, ui_dialWindow.Ui_MainDialWindow):
    
    configData = {}

    def __init__(self, parent = None):
        currentUser = getpass.getuser()
        # if currentUser != 'root':
        #     QtGui.QMessageBox.warning(parent, 
        #             QtGui.QApplication.translate('MainDialWindow', 
        #                 'Permission Denied'), 
        #             QtGui.QApplication.translate('MainDialWindow', 
        #                 'You are not root\nPlease be root to run this program!'))
        #     exit(1)
        super(DialWindow, self).__init__(parent)
        self.setupUi(self)
        self.createTrayIcon()
        traySignal = 'activated(QSystemTrayIcon::ActivationReason)'
        QtCore.QObject.connect(self.trayIcon, 
                QtCore.SIGNAL(traySignal), self.trayIconTriggered)
        self.initilizeConfigure()
        if self.IfDialStartup.isChecked():
            self.logOnButtonClicked()
            self.logon()
        
    def logon(self):

        username = self.UsernameInput.text()
        password = self.PasswordInput.text()
        interface = self.NICList.currentText()
        
        if self.SwitchNetwork.currentIndex() == 0:
            username = username + '@local'

        self.dot1x = dot1x.dot1x(str(username), str(password), str(interface))
        QtCore.QObject.connect(self.dot1x, QtCore.SIGNAL('statusChanged(int)'), self.statusChanged)
        
        self.dot1x.start()
#         self.dot1x.login()
        
    def logoff(self):
        if(hasattr(self, 'dot1x')):
            self.dot1x.logoff()
            self.dot1x.terminate()
    
    def initilizeConfigure(self):

        nicList = getNICList()
        for i in range(0, len(nicList)):
            self.NICList.insertItem(i, nicList[i])
       
        if os.path.exists(configFilePath):
            configFile = open(configFilePath, 'rw')
            lines = configFile.readlines()
            for i in range(0, len(lines)):
                nowLines = lines[i].split()
                if len(nowLines) == 1:
                    nowLines.append('')
                self.configData[nowLines[0]] = nowLines[1]
            if self.configData['IfStorePassword'] == 'YES':
                username = self.configData['Username']
                password = self.configData['Password']
                self.IfStorePassword.setChecked(True)
                self.UsernameInput.setText(username)
                self.PasswordInput.setText(password)
            
            self.NICList.setCurrentIndex(int(self.configData['NIC']))
            self.SwitchNetwork.setCurrentIndex(int(self.configData['Network']))
            if self.configData['IfDialStartup'] == 'YES':
                self.IfDialStartup.setChecked(True)

    def updateConfig(self):

        if self.IfStorePassword.isChecked():
            username = self.UsernameInput.text()
            password = self.PasswordInput.text()
            self.configData['IfStorePassword'] = 'YES'
            self.configData['Username'] = username
            self.configData['Password'] = password

        else:
            self.configData['IfStorePassword'] = 'NO'
            self.configData['Username'] = 'NO'
            self.configData['Password'] = 'NO'

        if self.IfDialStartup.isChecked():
            self.configData['IfDialStartup'] = 'YES'
        else:
            self.configData['IfDialStartup'] = 'NO'

        self.configData['NIC'] = self.NICList.currentIndex()
        self.configData['Network'] = self.SwitchNetwork.currentIndex()

        configFile = open(configFilePath, 'w')
        for lines in self.configData:
            configFile.write(lines + ' ' + str(self.configData[lines]) 
                    + '\n')
        configFile.close()
    
    def createTrayIcon(self):

        quitAction = QtGui.QAction(QtGui.QApplication.translate('MainDialWindow', 'Quit'), self, triggered = self.close)
        trayIconMenu = QtGui.QMenu(self)
        trayIconMenu.addAction(quitAction)

        self.trayIcon = QtGui.QSystemTrayIcon(QtGui.QIcon('/opt/py8021x/dialer.png'), self)
        self.trayIcon.setContextMenu(trayIconMenu)
        self.trayIcon.show()

    def closeEvent(self, event):

        confirmQuit = QtGui.QMessageBox.question(self, 
                QtGui.QApplication.translate('MainDialWindow', 
                    'Confirm Quit'), 
                QtGui.QApplication.translate('MainDialWindow', 
                    'Are you sure to quit?\nNetwork will be disconnected automatically'), 
                QtGui.QMessageBox.Yes, QtGui.QMessageBox.No)

        if confirmQuit == QtGui.QMessageBox.Yes:
            self.updateConfig()
            self.logoff()
            event.accept()

        else:
            event.ignore()

    def changeEvent(self, event):

        if event.type() == QtCore.QEvent.WindowStateChange and self.isVisible():   
            self.hide()
            event.accept()
	    
        else:
            super(DialWindow, self).changeEvent(event)

    def trayIconTriggered(self, reason):

        if reason == QtGui.QSystemTrayIcon.Trigger:
            if self.isVisible():
                self.hide()
            else:
                self.show()

    def statusChanged(self, status):
        if status == SEND_IDENTITY:
            self.StatusBar.setText(QtGui.QApplication.translate('MainDialWindow', 'Sending Identity...'))
        elif status == SEND_PASSWORD:
            self.StatusBar.setText(QtGui.QApplication.translate('MainDialWindow', 'Sending Password...'))
        elif status == SUCCESS:
            self.StatusBar.setText(QtGui.QApplication.translate('MainDialWindow', 'Auth Successful!'))
            self.timeStart()
        elif status == IDENTITY_FAILED:
            self.StatusBar.setText(QtGui.QApplication.translate('MainDialWindow', 'Identity Failed'))
            self.logOffButtonClicked()
        elif status == PASSWORD_FAILED:
            self.StatusBar.setText(QtGui.QApplication.translate('MainDialWindow', 'Password failed'))
            self.logOffButtonClicked()
        elif status == DISCONNECTED:
            self.StatusBar.setText(QtGui.QApplication.translate('MainDialWindow', 'Disconnected'))
            self.timeStop()
        elif status == AUTH_BEGIN:
            self.StatusBar.setText(QtGui.QApplication.translate('MainDialWindow', 'Auth starting'))
        elif status == DHCP_FAILED:
            self.StatusBar.setText(QtGui.QApplication.translate('MainDialWindow', 'Login success, please manually refresh IP address'))

    def about(self):

        aboutWindow = aboutDialog.AboutDialog(self)
        aboutWindow.show()

    def logOnButtonClicked(self):
        self.LogoffButton.setEnabled(True)
        self.LogonButton.setEnabled(False)
        self.NICList.setEnabled(False)
        self.SwitchNetwork.setEnabled(False)
        self.UsernameInput.setEnabled(False)
        self.PasswordInput.setEnabled(False)
        self.IfStorePassword.setEnabled(False)
        self.IfDialStartup.setEnabled(False)

    def logOffButtonClicked(self):
        self.LogonButton.setEnabled(True)
        self.LogoffButton.setEnabled(False)
        self.NICList.setEnabled(True)
        self.SwitchNetwork.setEnabled(True)
        self.UsernameInput.setEnabled(True)
        self.PasswordInput.setEnabled(True)
        self.IfStorePassword.setEnabled(True)
        self.IfDialStartup.setEnabled(True)

    def timeStart(self):
        self.timer = Timer()
        QtCore.QObject.connect(self.timer, 
                QtCore.SIGNAL('updateTime()'), self.updateTime)
        self.sec = 0
        self.timer.start()

    def timeStop(self):
        if(hasattr(self, 'timer')):
            self.timer.stop()

    def updateTime(self):
        if(hasattr(self, 'timer')):
            strTime = num2Time(self.sec)
            self.TimeDisplay.setText("%s" % strTime)
            self.sec += 1

class Timer(QtCore.QThread):

    def __init__(self, parent = None):
        super(Timer, self).__init__(parent)
        self.stopped = False

    def run(self):
        self.stopped = False
        while True:
            if self.stopped:
                return
            self.emit(QtCore.SIGNAL('updateTime()'))
            time.sleep(1)

    def stop(self):
        self.stopped = True

def getNICList():

    cmd = "cat /proc/net/dev|awk {'print $1'}|grep ':'|cut -d ':' -f1 > /var/tmp/NICList"
    os.system(cmd)
    listFile = open('/var/tmp/NICList')
    nicList = listFile.read()
    nicList = nicList.split()
    listFile.close()
    os.system('rm /var/tmp/NICList')
    return nicList

def num2Time(num):

    hour = str(num / 3600)
    minute = str(num % 3600 / 60)
    sec = str (num % 3600 % 60)

    if len(hour) == 1:
        hour = '0' + hour
    if len(minute) == 1:
        minute = '0' + minute
    if len(sec) == 1:
        sec = '0' + sec

    return ':'.join([hour, minute, sec])
