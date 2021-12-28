#!/usr/bin/env python

import scapy.all as scapy
import optparse


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Target IP or IP Range")
    (options, arguments) = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify IP address")
    return options


def print_result(answered_list):
    print("IP\t\t\tMAC Address\n-----------------------------------------")
    for answer in answered_list:
        print(answer[1].psrc+"\t\t"+answer[1].hwsrc)


def scan(ip):
    # scapy.arping(ip)
    arp_req = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broadcast = broadcast/arp_req
    (answered_list, unanswered_list) = scapy.srp(arp_req_broadcast, timeout=1, verbose=False)
    print_result(answered_list)


options = get_arguments()
scan(options.target)