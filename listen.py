#!/usr/bin/python2
# -*- coding: utf-8 -*-
from scapy.all import sniff, ARP
from datetime import datetime, timedelta
from subprocess import call
# import requests  # Use requests to trigger the ITTT webhook
#from send_mail import send_mail  # This function sends mails directly
pampers_last_press = datetime.now() - timedelta(seconds=10)
still_start_last_press = datetime.now() - timedelta(seconds=10)
still_stop_last_press = datetime.now() - timedelta(seconds=10)


def arp_received(packet):
    if packet[ARP].op == 1 and packet[ARP].hwdst == '00:00:00:00:00:00':
        if packet[ARP].hwsrc.upper() == 'FC:65:DE:81:25:74':  # Pampers
            print("Pampers Button pressed!")
            triggerAlexa()

        elif packet[ARP].hwsrc.upper() == 'FC:A6:67:B9:B8:75':  # Durex
            print("Durex Button pressed!")

        elif packet[ARP].hwsrc.upper() == '50:F5:DA:3B:1B:30':  # Finish
            print("Finish Button pressed!")

def triggerAlexa():
    print("Alexa triggered")
    call(["./alexa_remote_control.sh", "-a"])

if __name__ == "__main__":
    triggerAlexa()

    #print("Listening for ARP packets...")
    #sniff(prn=arp_received, iface="wlan0", filter="arp", store=0, count=0)
