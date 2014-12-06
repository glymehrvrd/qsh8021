#-------------------------------------------------------------------------------
# Name:        winpcapy.py
#
# Author:      glyme
#
# Created:     01/09/2009
# Copyright:   (c) Massimo Ciani 2009
#
#-------------------------------------------------------------------------------


# -*- coding: UTF-8 -*-

import os
from struct import pack, unpack
from hashlib import md5
from winpcapy import *
from ctypes import *

# Destination of 802.1x authorization server
DOT1X_DST = b'\x01\x80\xc2\x00\x00\x03'
ETH_TYPE_8021X = 0x888E

# 802.1x Protocol Codes
EAPOL_TYPE_EAP_PACKET = 0
EAPOL_TYPE_START = 1
EAPOL_TYPE_LOGOFF = 2
EAP_CODE_REQUEST = 1
EAP_CODE_RESPONSE = 2
EAP_TYPE_IDENTITY = 1
EAP_CODE_SUCCESS = 3
EAP_CODE_FAILURE = 4
EAP_TYPE_MD5CHALLENGE = 4

# State Codes
START = 1000
IDENTITY_SENT = 1001
PASSWORD_SENT = 1002
ENDED = 1003


class Dot1X():
    '''Class including functions to login 802.1x'''

    def __init__(self, username, password, dev_name):
        '''initiate parametors'''

        self.username = username
        self.password = password
        self.dev_name = dev_name
        self.hwAddr = self.GetMacAt(dev_name)
        errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)
        self.sock = pcap_open(dev_name, 1000, PCAP_OPENFLAG_PROMISCUOUS, 20, None, errbuf)
        if(not bool(self.sock)):
            print "\nUnable to open the adapter. %s is not supported by WinPcap\n" % dev_name

    def login(self):
        '''start 802.1x authorization'''

        self.StartAuth()
        self.AuthenticationLoop()

    def logoff(self):
        '''logoff from internet'''

        packet = self.MakeEthernetHeader()
        packet += self.MakeDot1XHeader(EAPOL_TYPE_LOGOFF, 0)
        pcap_sendpacket(self.sock, self.MakePkt(packet), len(packet))

    def StartAuth(self):
        '''send authorization header'''

        packet = self.MakeEthernetHeader()
        packet += self.MakeDot1XHeader(EAPOL_TYPE_START, 0)
        pcap_sendpacket(self.sock, self.MakePkt(packet), len(packet))
        print 'Start Packet Sent'

    def AuthenticationLoop(self):
        '''receive and response for 802.1x authroization'''

        header = POINTER(pcap_pkthdr)()
        authData = POINTER(c_ubyte)()
        while True:
            res = pcap_next_ex(self.sock, byref(header), byref(authData))
            if res < 0:
                break
            elif res == 0:
                continue

            etherProtocol, = unpack('>I', str(bytearray([0, 0] + authData[12:14])))
            eapolType, = unpack('B', str(bytearray(authData[15:16])))

            if etherProtocol != ETH_TYPE_8021X or eapolType != EAPOL_TYPE_EAP_PACKET:
                continue

            eapCode, eapID, eapLength, eapType = unpack('>BBHB', str(bytearray(authData[18:23])))

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

                    pcap_sendpacket(self.sock, self.MakePkt(packet), len(packet))
                    print 'Identity sent.'

                elif eapType == EAP_TYPE_MD5CHALLENGE:
                    challengeCodeSize, = unpack('B', str(bytearray(authData[23:24])))
                    challengeCodeSize = authData[24:24 + challengeCodeSize]

                    md5Response = md5(str(bytearray(authData[19:20])) +
                            self.password + str(bytearray(challengeCodeSize))).digest()

                    packet = self.MakeEthernetHeader()
                    eapPacket = self.MakeEAPPacket(EAP_CODE_RESPONSE,
                            eapID,
                            pack('BB16s', EAP_TYPE_MD5CHALLENGE,
                                16, md5Response))
                    packet += self.MakeDot1XHeader(EAPOL_TYPE_EAP_PACKET,
                            len(eapPacket))
                    packet += eapPacket
                    pcap_sendpacket(self.sock, self.MakePkt(packet), len(packet))

            elif eapCode == EAP_CODE_RESPONSE:
                pass

            elif eapCode == EAP_CODE_SUCCESS:
                print 'suc'
                #pcap_close(self.sock)

                self.ObtainIPAddr(self.dev_name)
                break
            elif eapCode == EAP_CODE_FAILURE:
                print 'fail'
                #pcap_close(self.sock)
                break
            else:
                print 'unknown status'
                #pcap_close(self.sock)
                break

    def MakeEthernetHeader(self):
        return pack('>6s6sH', DOT1X_DST, self.hwAddr, ETH_TYPE_8021X)

    def MakeDot1XHeader(self, authType, length=0):
        return pack('>BBH', 2, authType, length)

    def MakeEAPPacket(self, eapCode, eapID, eapData):
        return pack('>BBH%ds' % len(eapData), eapCode, eapID, len(eapData) + 4, eapData)

    def ObtainIPAddr(self, dev_name):
        os.system('ipconfig /renew')

    def GetMacAt(self, dev_name):
        from ctypes import Structure, windll, sizeof
        from ctypes import POINTER, byref
        from ctypes import c_ulong, c_uint, c_ubyte, c_char
        MAX_ADAPTER_DESCRIPTION_LENGTH = 128
        MAX_ADAPTER_NAME_LENGTH = 256
        MAX_ADAPTER_ADDRESS_LENGTH = 8

        class IP_ADDR_STRING(Structure):
            pass
        LP_IP_ADDR_STRING = POINTER(IP_ADDR_STRING)
        IP_ADDR_STRING._fields_ = [
            ("next", LP_IP_ADDR_STRING),
            ("ipAddress", c_char * 16),
            ("ipMask", c_char * 16),
            ("context", c_ulong)]

        class IP_ADAPTER_INFO (Structure):
            pass
        LP_IP_ADAPTER_INFO = POINTER(IP_ADAPTER_INFO)
        IP_ADAPTER_INFO._fields_ = [
            ("next", LP_IP_ADAPTER_INFO),
            ("comboIndex", c_ulong),
            ("adapterName", c_char * (MAX_ADAPTER_NAME_LENGTH + 4)),
            ("description", c_char * (MAX_ADAPTER_DESCRIPTION_LENGTH + 4)),
            ("addressLength", c_uint),
            ("address", c_ubyte * MAX_ADAPTER_ADDRESS_LENGTH),
            ("index", c_ulong),
            ("type", c_uint),
            ("dhcpEnabled", c_uint),
            ("currentIpAddress", LP_IP_ADDR_STRING),
            ("ipAddressList", IP_ADDR_STRING),
            ("gatewayList", IP_ADDR_STRING),
            ("dhcpServer", IP_ADDR_STRING),
            ("haveWins", c_uint),
            ("primaryWinsServer", IP_ADDR_STRING),
            ("secondaryWinsServer", IP_ADDR_STRING),
            ("leaseObtained", c_ulong),
            ("leaseExpires", c_ulong)]

        GetAdaptersInfo = windll.iphlpapi.GetAdaptersInfo
        GetAdaptersInfo.restype = c_ulong
        GetAdaptersInfo.argtypes = [LP_IP_ADAPTER_INFO, POINTER(c_ulong)]

        adapterList = (IP_ADAPTER_INFO * 10)()
        buflen = c_ulong(sizeof(adapterList))
        GetAdaptersInfo(byref(adapterList[0]), byref(buflen))

        adapter = adapterList[0]
        while(adapter):
            if dev_name.find(adapter.adapterName) != -1:
                addr = map(chr, adapter.address)
                addr = ''.join(addr)
                return addr

            adapter = adapter.next
            if(not adapter):
                break
            else:
                adapter = adapter.contents
        return ''

    def MakePkt(self, packet):
        pkt = (c_ubyte * len(packet))()
        for i in range(len(packet)):
            tmp, = unpack('B', packet[i])
            pkt[i] = tmp
        return pkt
