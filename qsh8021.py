# -*- coding: UTF-8 -*-

import os
import re
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


def info(s):
    print s


class Dot1X():
    '''Class including functions to login 802.1x'''

    def __init__(self, username, password, interface, interface_index):
        '''initiate parametors'''

        self.username = username
        self.password = password
        self.interface = interface
        self.hwAddr = GetMacAt(interface_index)
        errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)
        self.sock = pcap_open(interface, 1000, PCAP_OPENFLAG_PROMISCUOUS, 20, None, errbuf)
        if(not bool(self.sock)):
            print "\nUnable to open the adapter. %s is not supported by WinPcap\n" % interface

    def run(self):
        '''start 802.1x authorization'''

        self.StartAuth()
        self.AuthenticationLoop()

    def logoff(self):
        '''logoff from internet'''

        packet = self.MakeEthernetHeader()
        packet += self.MakeDot1XHeader(EAPOL_TYPE_LOGOFF, 0)
        pcap_sendpacket(self.sock, MakePkt(packet), len(packet))

    def StartAuth(self):
        '''send authorization header'''

        packet = self.MakeEthernetHeader()
        packet += self.MakeDot1XHeader(EAPOL_TYPE_START, 0)
        pcap_sendpacket(self.sock, MakePkt(packet), len(packet))
        info('Start Packet Sent')

    def AuthenticationLoop(self):
        '''receive and response for 802.1x authroization'''

        header = POINTER(pcap_pkthdr)()
        authData = POINTER(c_ubyte)()
        while True:
            print 'authloop'
            res = pcap_next_ex(self.sock, byref(header), byref(authData))
            if res < 0:
                break
            elif res == 0:
                continue

            etherProtocol, = unpack('>I', str(bytearray([0, 0] + authData[12:14])))
            eapolType, = unpack('B', str(bytearray(authData[15:16])))

            if etherProtocol != ETH_TYPE_8021X or eapolType != EAPOL_TYPE_EAP_PACKET:
                continue

            info('Received Packet of length %d.' % header.contents.len)
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

                    pcap_sendpacket(self.sock, MakePkt(packet), len(packet))
                    info('Identity sent.')

                elif eapType == EAP_TYPE_MD5CHALLENGE:
                    challengeCodeSize = unpack('B', str(bytearray(authData[23:24])))[0]
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
                    pcap_sendpacket(self.sock, MakePkt(packet), len(packet))

            elif eapCode == EAP_CODE_RESPONSE:
                pass

            elif eapCode == EAP_CODE_SUCCESS:
                print 'suc'
                #pcap_close(self.sock)

                self.ObtainIPAddr(self.interface)
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
        return pack('>BBH', 1, authType, length)

    def MakeEAPPacket(self, eapCode, eapID, eapData):
        return pack('>BBH%ds' % len(eapData), eapCode, eapID, len(eapData) + 4, eapData)

    def ObtainIPAddr(self, interface):
        os.system('ipconfig /renew')


def GetMacAt(index):
    dirs = ['', r'c:\windows\system32', r'c:\winnt\system32']
    try:
        import ctypes
        buffer = ctypes.create_string_buffer(300)
        ctypes.windll.kernel32.GetSystemDirectoryA(buffer, 300)
        dirs.insert(0, buffer.value.decode('mbcs'))
    except:
        pass
    for dir in dirs:
        try:
            pipe = os.popen(os.path.join(dir, 'ipconfig') + ' /all')
        except IOError:
            continue
        for line in pipe:
            value = line.split(':')[-1].strip().lower()
            if re.match('([0-9a-f][0-9a-f]-){5}[0-9a-f][0-9a-f]', value):
                if(index == 0):
                    mac = int(value.replace('-', ''), 16)
                    mac = pack('Q', mac)[5::-1]
                    return mac
                else:
                    index = index - 1
    return 0


def MakePkt(packet):
    pkt = (c_ubyte * len(packet))()
    for i in range(len(packet)):
        tmp, = unpack('B', packet[i])
        pkt[i] = tmp
    return pkt


def ListInterfaces():
    alldevs = POINTER(pcap_if_t)()
    d = POINTER(pcap_if_t)
    errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)

    ## Retrieve the device list
    if (pcap_findalldevs(byref(alldevs), errbuf) == -1):
        print ("Error in pcap_findalldevs: %s\n" % errbuf.value)
        sys.exit(1)

    interfaces = []
    d = alldevs.contents
    while d:
        interfaces.append(d)
        if d.next:
            d = d.next.contents
        else:
            d = False
    return interfaces

interfaces = ListInterfaces()

cnt = 1
print 'Interfaces:'
for interface in interfaces:
    print '%d.Name:%s' % (cnt, interface.name)
    print 'Description:%s' % interface.description
    cnt += 1
interfaceIndex = int(raw_input('Choose a interface:\n')) - 1
dialer = Dot1X('02806020036@local', 'realcomp', interfaces[interfaceIndex].name, interfaceIndex)

funcswitch = raw_input('Login?(y/n)')
print type(funcswitch)
if funcswitch.lower() == 'y':
    dialer.run()
else:
    dialer.logoff()
os.system('pause')
