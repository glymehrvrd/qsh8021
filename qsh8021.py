# -*- coding: UTF-8 -*-

import os
from struct import pack, unpack
from hashlib import md5
from winpcapy import *
from ctypes import *

DOT1X_DST = b'\x01\x80\xc2\x00\x00\x03'
ETH_TYPE_8021X = 0x888E
PKT_TYPE_EAP = 0
SOL_PACKET = 263
PACKET_MR_MULTICAST = 0
PACKET_ADD_MEMBERSHIP = 1
SIOCGIFINDEX = 0x8933
SIOCGIFHWADDR = 0x8927

#802.1x Protocol Codes
AUTH_START = 1
AUTH_REQUEST = 1
AUTH_RESPONSE = 2
AUTH_SUCCESS = 3
AUTH_FAILURE = 4
AUTH_TYPE_IDENTITY = 1
AUTH_TYPE_MD5CHALLENGE = 4
AUTH_LOGOFF = 2

#State Codes
START = 1000
IDENTITY_SENT = 1001
IDENTITY_RECEIVED = 1001
PASSWORD_SENT = 1002
AUTH_ENDED = 1002

#Status Codes:
AUTH_BEGIN = 4000
SEND_IDENTITY = 5000
SEND_PASSWORD = 5001
SUCCESS = 5002
IDENTITY_FAILED = 7003
PASSWORD_FAILED = 7004
DISCONNECTED = 6000
DHCP_FAILED = 8000

def info(s):
    print s

class Dot1X():
    def __init__(self, username, password, interface, interface_index):
        self.state = AUTH_START
        self.username = username
        self.password = password
        self.interface = interface
        self.hwAddr = GetMacAt(interface_index)
        errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)
        self.sock = pcap_open_live(interface, 1000, PCAP_OPENFLAG_PROMISCUOUS, 20, errbuf)
        if(not bool(self.sock)):
            print "\nUnable to open the adapter. %s is not supported by WinPcap\n" % interface

    def run(self):
        self.StartAuth()
        self.AuthenticationLoop()

    def logoff(self, parent):
        packet = self.MakeEthernetHeader()
        packet += self.MakeDot1XHeader(AUTH_LOGOFF, 0)
        self.sock.pcap_sendpacket(packet, sizeof(packet))

    def StartAuth(self):
        packet = self.MakeEthernetHeader()
        packet += self.MakeDot1XHeader(AUTH_START, 0)
        pkt = (c_ubyte * len(packet))()
        for i in range(len(packet)):
            tmp, = unpack('B', packet[i])
            pkt[i] = tmp
        pcap_sendpacket(self.sock, pkt, len(packet))
        info('Start Packet Sent')

    def AuthenticationLoop(self):
        while True:
            header = POINTER(pcap_pkthdr)()
            authData = POINTER(c_ubyte)()
            res = pcap_next_ex(self.sock, byref(header), byref(authData))
            if(res < 0):
                break

            etherProtocol = authData[12:13]
            if(etherProtocol != ETH_TYPE_8021X):
                continue

            info('Received Packet of length %d.' % header.contents.len)
            eapCode, eapID, eapLength = unpack('>BBH', authData[18:22])

            if self.state == START:

                if eapCode == AUTH_REQUEST:

                    eapType = unpack('B', authData[22:23])[0]

                    if eapType == AUTH_TYPE_IDENTITY:
                        username = str(unpack('%ds' % (eapLength - 5), 
                            authData[23:18 + eapLength])[0])

                        packet = self.MakeEthernetHeader()
                        identity = self.username
                        eapPacket = self.MakeEAPPacket(AUTH_RESPONSE, 
                                eapID, pack('B%ds' % len(identity), 
                                    AUTH_TYPE_IDENTITY, identity))
                        packet += self.MakeDot1XHeader(PKT_TYPE_EAP, 
                                len(eapPacket))
                        packet += eapPacket

                        self.sock.pcap_sendpacket(packet, sizeof(packet))
                        info('Identity sent.')

                        self.state = IDENTITY_SENT

            elif self.state == IDENTITY_RECEIVED:

                if eapCode == AUTH_REQUEST:
                
                    eapType = unpack('B', authData[22:23])[0]
                
                    if eapType == AUTH_TYPE_MD5CHALLENGE:

                        challengeCodeSize = unpack('B', authData[23:24])[0]
                        challengeCodeSize = authData[24:24 + challengeCodeSize]

                        md5Response = md5(authData[19] + 
                                self.password + challengeCodeSize).digest()

                        packet = self.MakeEthernetHeader()
                        eapPacket = self.MakeEAPPacket(AUTH_RESPONSE,
                                eapID,
                                pack('BB16s', AUTH_TYPE_MD5CHALLENGE,
                                    16, md5Response))
                        packet += self.MakeDot1XHeader(PKT_TYPE_EAP, 
                                len(eapPacket))
                        packet += eapPacket
                        self.sock.pcap_sendpacket(packet, sizeof(packet))
    
                        self.state = PASSWORD_SENT
                

                elif eapCode == AUTH_FAILURE:
                    pass

                else:
                    pass
        
            elif self.state == AUTH_ENDED:
                if eapCode == AUTH_SUCCESS: 
                    self.ObtainIPAddr(self.interface)
                    break
                else:
                    pass
    
    def MakeEthernetHeader(self):
        return pack('>6s6sH', DOT1X_DST, self.hwAddr, ETH_TYPE_8021X)

    def MakeDot1XHeader(self, authType, length = 0):
        return pack('>BBH', 1, authType, length)

    def MakeEAPPacket(self, eapCode, eapID, eapData):
        return pack('>BBH%ds' % len(eapData), eapCode, eapID, len(eapData) + 4, eapData)

    def ObtainIPAddr(self, interface):
        pass

def GetInterfaceIndex(sock, interface):
    ignore, intIndex = unpack('16sI', ioctl(sock, SIOCGIFINDEX, pack('16sI', interface, 0)))
    return intIndex

def GetMacAt(index):
    """----add by liangzi----get mac if have more than one newwork hardware"""
    import os, re
    dirs = ['', r'c:\windows\system32', r'c:\winnt\system32']
    try:
        import ctypes
        buffer = ctypes.create_string_buffer(300)
        ctypes.windll.kernel32.GetSystemDirectoryA(buffer, 300)
        dirs.insert(0, buffer.value.decode('mbcs'))
    except:
        pass
    macad=[]
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

def ListInterfaces():
    alldevs=POINTER(pcap_if_t)()
    d=POINTER(pcap_if_t)
    errbuf= create_string_buffer(PCAP_ERRBUF_SIZE)

    ## Retrieve the device list
    if (pcap_findalldevs(byref(alldevs), errbuf) == -1):
        print ("Error in pcap_findalldevs: %s\n" % errbuf.value)
        sys.exit(1)

    interfaces = []
    d=alldevs.contents
    while d:
        interfaces.append(d.name)
        if d.next:
             d=d.next.contents
        else:
             d=False
    return interfaces

interfaces = ListInterfaces()

cnt = 1
print 'Interfaces:'
for interface in interfaces:
    print '%d.Name:%s' % (cnt, interface)
    cnt += 1
interfaceIndex = int(input('Choose a interface:\n')) - 1

dialer = Dot1X('username', 'password', interfaces[interfaceIndex], interfaceIndex)
dialer.run()