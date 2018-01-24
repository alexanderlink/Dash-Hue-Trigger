#!/usr/bin/python2
# -*- coding: utf-8 -*-
from scapy.all import sniff, ARP
from datetime import datetime, timedelta
# import requests  # Use requests to trigger the ITTT webhook
#from send_mail import send_mail  # This function sends mails directly
pampers_last_press = datetime.now() - timedelta(seconds=10)
still_start_last_press = datetime.now() - timedelta(seconds=10)
still_stop_last_press = datetime.now() - timedelta(seconds=10)


def arp_received(packet):
    if packet[ARP].op == 1 and packet[ARP].hwdst == '00:00:00:00:00:00':
        if packet[ARP].hwsrc == 'fc:65:de:81:25:74':  # This is the MAC of the first dash button
            print("Pampers Button pressed!")
            global pampers_last_press
            now = datetime.now()
            if pampers_last_press + timedelta(seconds=5) <= now:
                print("Gewickelt um " + str(now))
                with open("../Node-Still-Wickel/static/wickel.dat", "a") as myfile:
                    myfile.write("START " + str(now) + "\n")
                pampers_last_press = now
                # requests.get("https://maker.ifttt.com/trigger/dash_button_pressed/with/key/bVTfJ-_fhDejXSGgGnLdfU")
                #send_mail("jme@ct.de", subject="Dash button gedrückt",
                #          text="Hallo,\n\nder Dash-Button wurde gerade gedrückt.\n\nViele Grüße,\n  dein Raspi")
        elif packet[ARP].hwsrc == 'TODO-Still-Start':  # This is the MAC of the first dash button
            print("Still-Start Button pressed!")
            global still_start_last_press
            now = datetime.now()
            if still_start_last_press + timedelta(seconds=5) <= now:
                print("Stillen angefangen um " + str(now))
                with open("../Node-Still-Wickel/static/still.dat", "a") as myfile:
                    myfile.write("START " + str(now) + "\n")
                still_start_last_press = now
        elif packet[ARP].hwsrc == 'TODO-Still-Stop':  # This is the MAC of the first dash button
            print("Still-Stop Button pressed!")
            global still_stop_last_press
            now = datetime.now()
            if still_stop_last_press + timedelta(seconds=5) <= now:
                print("Stillen gestoppt um " + str(now))
                with open("../Node-Still-Wickel/static/still.dat", "a") as myfile:
                    myfile.write("STOP " + str(now) + "\n")
                still_stop_last_press = now
        elif packet[ARP].hwsrc != 'b8:27:eb:f1:e6:bc':  # If it is not the MAC of the Raspi it could be another button
            print("                (Other Device connecting: " + packet[ARP].hwsrc + ")")


if __name__ == "__main__":
    print("Listening for ARP packets...")
    sniff(prn=arp_received, iface="wlan0", filter="arp", store=0, count=0)
