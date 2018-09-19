# Trigger Philips Hue from an Amazon Dash Button

This project is based on
- [**pinae/dashbutton**](https://github.com/pinae/dashbutton) &ndash; a python script to listen to Amazon Dash buttons
- [**studioimaginaire/phue**](https://github.com/studioimaginaire/phue) &ndash; a python library for Philips Hue

The script on a Raspberry Pi reacts when the Amazon Dash button is pressed, communicates with the Philips Hue Bridge and activates/deactivates specific lights, sets the brightness level, etc.

Here you find an [**example video**](https://www.youtube.com/watch?v=MSXT9lLoVYw).

## Amazon Dash button
The script `listen.py` registers ARP-packets in the local network. 
If you enter the MAC of your Amazon Dash button it registers if the
button is pressed. It can act on this event with a request to a ITTT 
webhook (ITTT maker channel) or by writing a mail using a 
Gmail-account.

## Installation
Activate your dash button with the Amazon smartphone app. You do not 
need to select a product to order. The script will register if the 
button is pressed even if no product was selected.

The script uses scapy to sniff the ARP-packets the button sends when 
connecting to your wifi. Because of that it only works with Python 2.7.
If you want to trigger the webhook you also need requests, the mail
part uses smtplib.

:warning: To prevent the Dash button orders stuff all the time you have to block Internet access for the Dash button in your router once it is registered properly. This will block communication with Amazon, still the event is recognized by the raspi in your network.

Install python dependencies via pip:   
```shell
# Install pip
sudo apt-get install python-pip
# Install required dependencies
sudo pip install -r requirements.txt
```

The script probably needs root-privileges:
```shell
sudo python2 listen.py
```

## Setup Service
To run the script as service [see here](huedash-service-readme.md)
