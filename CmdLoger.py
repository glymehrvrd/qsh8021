import argparse
from Dot1X import Dot1X
from winpcapy import *
from ctypes import *


def ListInterfaces():
    alldevs = POINTER(pcap_if_t)()
    d = POINTER(pcap_if_t)
    errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)

    # Retrieve the device list
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

parser = argparse.ArgumentParser('Run 8021x Authentication.')
parser.add_argument('id', type=str, help='id.')
parser.add_argument('password', type=str, help='Message to show.', default='password')
parser.add_argument('interface', type=str, help='Interface name.')
parser.add_argument('--logoff', dest='logoff', action='store_true', help='login or log off.')
args = parser.parse_args()

# Retrieve the device list
interfaces = ListInterfaces()
index = 0
for i in interfaces:
    if(i.description.find(args.interface) != -1):
        break
    index += 1
if(index == len(interfaces) or args.interface == ''):
    print "Interface %s not found" % args.interface
    sys.exit(1)

dialer = Dot1X(args.id, args.password, interfaces[index].name)
if(args.logoff):
    dialer.logoff()
else:
    dialer.login()
