#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Created on Fri Dec  8 04:25:19 2017
@author: sharmila24
"""
import os
import sys
from scapy.all import *
import argparse
import datetime
packet_list ={}
def intersection(list1,list2):
    c=[filter(lambda x: x in list1, sublist) for sublist in list2]
    if c==[]:
        return 0
    else:
        return 1
def check_packet(pkt):
    #print pkt.show()
    if ((pkt[DNS].id,pkt[IP].dst) in packet_list.keys()):
        r_list=[pkt[DNS].an[i].rdata for i in range(pkt.ancount) if pkt[DNS].an[i].type ==1]
        packet_dict=packet_list[(pkt[DNS].id,pkt[IP].dst)]
        if (intersection( packet_dict[0],r_list))or pkt[IP].ttl==packet_list[1]:
            print datetime.datetime.fromtimestamp(pkt.time).strftime('%Y%m%d--%H:%M:%S')
            print "DNS poisioning detected"
            print "TXID- %d"%(pkt[DNS].id)
            print "Request - %s"%( pkt[DNS].qd.qname.rstrip('.'))
            #print "Response -1 "
            print "Answer-1 ",r_list
            print "Answer-2",packet_dict[0]

    else:
        r_list=[pkt[DNS].an[i].rdata for i in range(pkt.ancount) if pkt[DNS].an[i].type ==1]
        if r_list!=[]:
            packet_list[(pkt[DNS].id, pkt[IP].dst)] =  (r_list,pkt[IP].ttl )
    
    return
  
def dns_detect_spoofed_packet(pkt):
    if pkt.haslayer(DNSRR) and pkt[DNS].qr==1:
        print "checking packet"
        packet=check_packet(pkt)
        return
    #check for protocal, IP layer, DNS 
    #sr1(IP(dst='8.8.8.8')/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname='www.thepacketgeek.com')), verbose=0)
    #the above is packet format. So, check for the layers, IP, UDP, DNS, DNSQR


def argument_parser():
    ter_parser = argparse.ArgumentParser(description=" DNS - DETECTION ")
    ter_parser.add_argument("-i")
    ter_parser.add_argument("-r") 
    ter_parser.add_argument('bpf_filter', nargs='*',type =str)
    arg_all = ter_parser.parse_args()
    return arg_all.i, arg_all.r, arg_all.bpf_filter

if __name__ == '__main__':
    network, tracefile, bpf_filter = argument_parser()
    string = ""
    for i in bpf_filter:
        string =string + i
    bpf_filter =string
    #print "sniffing now "

    if tracefile or network:
        if tracefile:
            #print "its sniffing"
            bpf_filter = bpf_filter + " udp port 53"
            sniff(filter=bpf_filter, offline = tracefile, store=0, prn=dns_detect_spoofed_packet)
        if network:
            bpf_filter = +bpf_filter + " udp port 53"
            #print "its sniffing"
            sniff(filter=bpf_filter, iface=network, store=0, prn=dns_detect_spoofed_packet)
    
    else:
        #print "sniff on everything"
        #sniff on everything
        bpf_filter = bpf_filter + " udp port 53"
        sniff(filter=bpf_filter, store=0, prn=dns_detect_spoofed_packet)
  
