#!/usr/bin/env python3
import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP

def get_if():
    ifs=get_if_list()
    iface="enp2s0"
    for i in get_if_list():
        #iface=i
        if not iface:
            print("Cannot find eth0 interface")
            exit(1)
    return iface



def main():
    if len(sys.argv)<3:
        print('pass 2 arguments: <destination> "<message>"')
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()
    print("IFACE=",iface)
    chunksize = 1460
#barlag.json
    with open('twibot20.json','r') as firstfile:
        while True : 
            chunk = firstfile.read(chunksize)
            print("Chunk=",chunk) 
            if chunk =="":
                break
            print(("sending on interface %s to %s" % (iface, str(addr))))
            pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
            pkt = pkt /IP(dst=addr) / TCP(dport=5201, sport=random.randint(49152,65535)) / chunk  
            pkt.show()
            sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()

