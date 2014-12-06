#!/usr/bin/env  python

import os
import socket
from fcntl import ioctl
from struct import pack, unpack
import logging
from hashlib import md5
import dbus
from PyQt4 import QtCore

# Destination of 802.1x authorization server
DOT1X_DST = b'\x01\x80\xc2\x00\x00\x03'
ETH_TYPE_8021X = 0x888E
SIOCGIFHWADDR = 0x8927
SIOCGIFINDEX = 0x8933
SOL_PACKET = 263
PACKET_MR_MULTICAST = 0
PACKET_ADD_MEMBERSHIP = 1
ETH_P_ALL = 0x0003

# 802.1x Protocol Codes
EAPOL_TYPE_EAP_PACKET = 0
EAPOL_TYPE_START = 1
EAPOL_TYPE_LOGOFF = 2
EAP_CODE_REQUEST = 1
EAP_CODE_RESPONSE = 2
EAP_CODE_SUCCESS = 3
EAP_CODE_FAILURE = 4
EAP_TYPE_IDENTITY = 1
EAP_TYPE_MD5CHALLENGE = 4

# State Codes
STATUS_AUTH_BEGIN = 4000
STATUS_SEND_IDENTITY = 5000
STATUS_SEND_PASSWORD = 5001
STATUS_SUCCESS = 5002
STATUS_IDENTITY_FAILED = 7003
STATUS_PASSWORD_FAILED = 7004
STATUS_DISCONNECTED = 6000
STATUS_DHCP_FAILED = 8000

def SendPacket(sock, packet, length):
    sock.send(packet)

def GetInterfaceIndex(sock, interface):

    ignore, intIndex = unpack('16sI', ioctl(sock, SIOCGIFINDEX, pack('16sI', interface, 0)))
    return intIndex

class dot1x(QtCore.QThread):

    def __init__(self, username, password, interface):
        '''initiate parametors'''

        QtCore.QThread.__init__(self)
        self.username = username
        self.password = password
        self.interface = interface
        self.idsent = False
        
#        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        self.sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        print interface
        self.sock.bind((interface, 0))
        self.hwAddr = GetHWAddr(self.sock, self.interface)
        
        self.intIndex = GetInterfaceIndex(self.sock, self.interface)
        self.sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, pack('IHH8s', self.intIndex, PACKET_MR_MULTICAST, len(DOT1X_DST), DOT1X_DST))
        
    def run(self):
        self.login()
        
    def login(self):
        '''start 802.1x authorization'''
        self.StartAuth()
        self.AuthenticationLoop()

    def logoff(self):
        '''logoff from internet'''

        self.emit(QtCore.SIGNAL('statusChanged(int)'), STATUS_DISCONNECTED)
        packet = self.MakeEthernetHeader()
        packet += self.MakeDot1XHeader(EAPOL_TYPE_LOGOFF, 0)
        SendPacket(self.sock, packet, len(packet))
        self.sock.close()

    def StartAuth(self):
        '''send authorization header'''

        packet = self.MakeEthernetHeader()
        packet += self.MakeDot1XHeader(EAPOL_TYPE_START, 0)
        SendPacket(self.sock, packet, len(packet))
        self.emit(QtCore.SIGNAL('statusChanged(int)'), STATUS_AUTH_BEGIN)

    def AuthenticationLoop(self):
        '''receive and response for 802.1x authroization'''
        
        while True:
            authData = self.sock.recv(65535)
            
            etherProtocol,  = unpack('>I', '\x00\x00' + authData[12:14])
            eapolType,  = unpack('B', str(authData[15:16]))
  
            if etherProtocol != ETH_TYPE_8021X or eapolType != EAPOL_TYPE_EAP_PACKET:
                continue

            eapCode, eapID, eapLength, eapType = unpack('>BBHB', authData[18:23])
            
            if eapCode == EAP_CODE_REQUEST:
                if eapType == EAP_TYPE_IDENTITY:
                    packet = self.MakeEthernetHeader()
                    identity = self.username
                    eapPacket = self.MakeEAPPacket(EAP_CODE_RESPONSE,
                            eapID, pack('B%ds' % len(identity),
                                EAP_TYPE_IDENTITY, identity))
                    packet += self.MakeDot1XHeader(EAPOL_TYPE_EAP_PACKET,
                            len(eapPacket))
                    packet += eapPacket

                    SendPacket(self.sock, packet, len(packet))
                    self.emit(QtCore.SIGNAL('statusChanged(int)'), STATUS_SEND_IDENTITY)
                    self.idsent = True

                elif eapType == EAP_TYPE_MD5CHALLENGE:
                    challengeCodeSize, = unpack('B', authData[23:24])
                    challengeCodeSize = authData[24:24 + challengeCodeSize]

                    md5Response = md5(authData[19:20] +
                            self.password + challengeCodeSize).digest()

                    packet = self.MakeEthernetHeader()
                    eapPacket = self.MakeEAPPacket(EAP_CODE_RESPONSE, eapID,
                            pack('BB16s', EAP_TYPE_MD5CHALLENGE,
                                16, md5Response))
                    packet += self.MakeDot1XHeader(EAPOL_TYPE_EAP_PACKET,
                            len(eapPacket))
                    packet += eapPacket
                    SendPacket(self.sock, packet, len(packet))
                    self.emit(QtCore.SIGNAL('statusChanged(int)'), STATUS_SEND_PASSWORD)

            elif eapCode == EAP_CODE_RESPONSE:
                pass

            elif eapCode == EAP_CODE_SUCCESS:
                self.emit(QtCore.SIGNAL('statusChanged(int)'), STATUS_SUCCESS)
                self.ObtainIPAddr(self.interface)
                break
            
            elif eapCode == EAP_CODE_FAILURE:
                print "fail"
                print self.idsent
                if(not self.idsent):
                    continue
                self.emit(QtCore.SIGNAL('statusChanged(int)'), STATUS_IDENTITY_FAILED)
                self.sock.close()
                break
            
            else:
                self.emit(QtCore.SIGNAL('statusChanged(int)'), STATUS_IDENTITY_FAILED)
                self.sock.close()
                break

    def MakeEthernetHeader(self):
        return pack('>6s6sH', DOT1X_DST, self.hwAddr, ETH_TYPE_8021X)

    def MakeDot1XHeader(self, authType, length=0):
        return pack('>BBH', 2, authType, length)

    def MakeEAPPacket(self, eapCode, eapID, eapData):
        return pack('>BBH%ds' % len(eapData), eapCode, eapID, len(eapData) + 4, eapData)

    def ObtainIPAddr(self, interface):
        MAX_NIC_COUNT = GetNICCount()
        bus = dbus.SystemBus()
        NM = 'org.freedesktop.NetworkManager'
        nm = bus.get_object(NM, '/org/freedesktop/NetworkManager')

        i = 0
        while i < MAX_NIC_COUNT:
            connectPath = '/org/freedesktop/NetworkManagerSettings/' + str(i)
            devicePath = '/org/freedesktop/NetworkManager/Devices/' + str(i)

            try:
                if dbus.Interface(nm, 'org.freedesktop.NetworkManager').ActivateConnection('org.freedesktop.NetworkManagerSystemSettings', connectPath, devicePath, '/'):
                    break
            except:
                i = i + 1

        if i >= MAX_NIC_COUNT:
            self.emit(QtCore.SIGNAL("statusChanged(int)"), STATUS_DHCP_FAILED)

def GetHWAddr(sock, interface):

    ignore1, ignore2, hwAddr = unpack('16sH6s', ioctl(sock, SIOCGIFHWADDR,
        pack('16sH6s', interface, 0, '')))
    return hwAddr

def GetNICCount():
    cmd = "cat /proc/net/dev|awk {'print $1'}|grep ':'|cut -d ':' -f1 > /var/tmp/NICList"
    os.system(cmd)
    listFile = open('/var/tmp/NICList')
    nicList = listFile.read()
    nicList = nicList.split()
    listFile.close()
    os.system('rm /var/tmp/NICList')
    return len(nicList)
