#!/usr/bin/python2
# -*- coding: utf-8 -*-
from scapy.all import sniff, ARP
from datetime import datetime, timedelta
from phue import Bridge

last_state = "off"

def arp_received(packet):
    if packet[ARP].op == 1 and packet[ARP].hwdst == '00:00:00:00:00:00':
        # Replace the Dash button addresses with yours
        if packet[ARP].hwsrc.upper() == 'FC:65:DE:81:25:74':  # Pampers
            print("Pampers Button pressed!")
            toggleOnOff()

        elif packet[ARP].hwsrc.upper() == '50:F5:DA:3B:1B:30':  # Finish
            print("Finish Button pressed!")
            toggleOnOff()

        elif packet[ARP].hwsrc.upper() == 'FC:A6:67:B9:B8:75':  # Durex
            print("Durex Button pressed!")
            switchBrightness()


def toggleOnOff():
    print("toggleOnOff")
    global last_state
    if last_state == 'off':
        setOn()
        last_state = 'on'
    else:
        setOff()
        last_state = 'off'

# Replace the Hue light names with yours and implement the desired logic.
# initHue() below prints the list of lights.
def setOn():
    print("setOn")
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

def setOff():
    print("setOff")
    b = initHue()
    b.set_light('Flur 1', 'on', False)
    b.set_light('Flur 2', 'on', False)
    b.set_light('Flur 3', 'on', False)
    b.set_light('Flur 4', 'on', False)
    b.set_light('Küche Decke', 'bri', 255)
    b.set_light('Küche Decke', 'on', False)
    b.set_light('Küche Lightstrip', 'bri', 255)
    b.set_light('Küche Lightstrip', 'on', False)


def switchBrightness():
    print "switchBrightness"
    b = initHue()
    curBri = b.get_light('Wohnzimmer Decke')['state']['bri']
    print "current brightness: " + str(curBri)
    if curBri > 200:
        b.set_light('Wohnzimmer Decke', 'bri', 5)
        b.set_light('Wohnzimmer Farbe', 'bri', 5)
        b.set_light('Wohnzimmer Tür', 'bri', 5)
        b.set_light('Flur 1', 'bri', 5)
        b.set_light('Flur 2', 'bri', 5)
        b.set_light('Flur 3', 'bri', 5)
        b.set_light('Flur 4', 'bri', 5)
        b.set_light('Küche Decke', 'bri', 5)
        b.set_light('Küche Lightstrip', 'bri', 5)
    else:
        b.set_light('Wohnzimmer Decke', 'bri', 255)
        b.set_light('Wohnzimmer Farbe', 'bri', 255)
        b.set_light('Wohnzimmer Tür', 'bri', 255)
        b.set_light('Flur 1', 'bri', 255)
        b.set_light('Flur 2', 'bri', 255)
        b.set_light('Flur 3', 'bri', 255)
        b.set_light('Flur 4', 'bri', 255)
        b.set_light('Küche Decke', 'bri', 255)
        b.set_light('Küche Lightstrip', 'bri', 255)


def initHue():
    b = Bridge('192.168.178.39') # Replace with the IP of your Hue Bridge
    b.connect()
    b.get_api()
    lights = b.lights
    print("Available lights:")
    for l in lights:
        print(l)
    return b    

if __name__ == "__main__":
    print("Listening for ARP packets...")
    sniff(prn=arp_received, iface="wlan0", filter="arp", store=0, count=0)
