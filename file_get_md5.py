#!/usr/bin/env python3
import sys
import struct
import os

from scapy.all import sniff, sendp, hexdump, linehexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, TCP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR
from scapy.all import raw
from scapy.all import bytes_hex
import hashlib

maxim  = 0
congest = 0

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "enp4s0f1" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface


def yigrimi(paket):
    global maxim
    global congest
    hex_string = linehexdump(paket,onlyhex=1,dump=True)
    tokens = hex_string.split(' ')
    deq_qdepth       = ''.join(tokens[21:23])
    deq_congest_stat = ''.join(tokens[23:24])
    #enq_qdepth       = ''.join(tokens[29:32])
    #enq_congest_stat = ''.join(tokens[33:36])
    #hex  = ''.join(tokens[21:24])
    print(" orig = {} Deq_qdepth = : {} , {} deq_congest_stat={}, Max= {} max_congest = {}".format(tokens[21:24],deq_qdepth,int(deq_qdepth,16),deq_congest_stat, maxim,congest))
    
    uly = int(deq_qdepth,16)
    if uly > maxim :
        maxim = uly
    stat= int(deq_congest_stat,16)
    if stat > congest :
        congest = stat
    return paket


class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="swids",
                                  adjust=lambda pkt,l:l+4),
                    ShortField("count", 0),
                    FieldListField("swids",
                                   [],
                                   IntField("", 0),
                                   length_from=lambda pkt:pkt.count*4) ]


def handle_pkt(pkt):
    if TCP in pkt and pkt[TCP].dport == 5201:
        #print("got a packet")
        yigrimi(pkt[IP])
        setir = pkt[IP].load
        print("Load#",setir)
        print(hashlib.md5(setir).hexdigest())
        #pkt.show2()
        sys.stdout.flush()


def main():
    maxim = 0
    ifaces = [i for i in os.listdir('/sys/class/net/') ]
    iface = get_if()
    print(("sniffing on %s" % iface))
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()

