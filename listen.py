#!/usr/bin/python2
# -*- coding: utf-8 -*-
from scapy.all import sniff, ARP
from datetime import datetime, timedelta
from phue import Bridge

def arp_received(packet):
    if packet[ARP].op == 1 and packet[ARP].hwdst == '00:00:00:00:00:00':
        if packet[ARP].hwsrc.upper() == 'FC:65:DE:81:25:74':  # Pampers
            print("Pampers Button pressed!")
            setHueWickelnStart()

        elif packet[ARP].hwsrc.upper() == 'FC:A6:67:B9:B8:75':  # Durex
            print("Durex Button pressed!")

        elif packet[ARP].hwsrc.upper() == '50:F5:DA:3B:1B:30':  # Finish
            print("Finish Button pressed!")
            setHueWickelnStop()

def setHueWickelnStart():
    print("Hue Wickeln Start")
    b = initHue()
    b.set_light('Flur 1', 'on', True)
    b.set_light('Flur 1', 'bri', 10)
    b.set_light('Flur 2', 'on', True)
    b.set_light('Flur 2', 'bri', 10)
    b.set_light('Flur 3', 'on', True)
    b.set_light('Flur 3', 'bri', 10)
    b.set_light('Flur 4', 'on', True)
    b.set_light('Flur 4', 'bri', 10)
    b.set_light('Küche Decke', 'on', True)
    b.set_light('Küche Decke', 'bri', 10)
    b.set_light('Küche Lightstrip', 'on', True)
    b.set_light('Küche Lightstrip', 'bri', 20)

def setHueWickelnStop():
    print("Hue Wickeln Stop")
    b = initHue()
    b.set_light('Flur 1', 'on', False)
    b.set_light('Flur 2', 'on', False)
    b.set_light('Flur 3', 'on', False)
    b.set_light('Flur 4', 'on', False)
    b.set_light('Küche Decke', 'bri', 255)
    b.set_light('Küche Decke', 'on', False)
    b.set_light('Küche Lightstrip', 'bri', 255)
    b.set_light('Küche Lightstrip', 'on', False)

def initHue():
    b = Bridge('192.168.178.39')
    b.connect()
    b.get_api()
    lights = b.lights
    for l in lights:
        print(l)
    return b    

if __name__ == "__main__":
    print("Listening for ARP packets...")
    sniff(prn=arp_received, iface="wlan0", filter="arp", store=0, count=0)
