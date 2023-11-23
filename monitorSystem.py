import sqlite3
from datetime import datetime
import re
import subprocess
from time import sleep

def nmap_scan():
    # Run nmap command to scan for devices
    nmap_cmd = ['nmap', '-sn', '192.168.0.0/24', "-e", "eth0"] 
    #nmap_cmd = ['nmap', '-sn', '192.168.0.0/24', "-e", "wlan0"] 
    try:
        # Execute nmap command and capture output
        # print("Executing nmap command: ", nmap_cmd)
        output = subprocess.check_output(nmap_cmd, universal_newlines=True)
        return output
    except subprocess.CalledProcessError as e:
        print("Error: ", e)
        return None

def parse_devices_up(nmap_output):

    if nmap_output:
        # Use regular expressions to find IP addresses and MAC addresses
        device_pattern = r"Nmap scan report for (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\nHost is up(.*\n)*?MAC Address: (([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})).*?\((.*?)\)"
        
        # Find all matches in the output
        matches = re.finditer(device_pattern, nmap_output)
        
        devices_up = []
       # print("===============================================================================")


        # Extract and print IP and MAC addresses for devices that are up
        for match in matches:
            ip_address = match.group(1)
            mac_address = match.group(3)
            mac_vendor = match.group(6)
            # create a list of UP devices
            devices_up = devices_up + [(mac_address.upper(), mac_vendor)]

            # print(f"> IP Address: {ip_address}, MAC Address: {mac_address}, MAC Vendor: {mac_vendor}")


        return devices_up




# declare main function


if __name__ == "__main__":
    

   

    while True:
         # connect to a db in sqllite3 and get all devices
        conn = sqlite3.connect('espresso.db')

        cursor = conn.cursor()
        #print("===============================================================================")

        devices_up = parse_devices_up(nmap_scan())

        for device_up in devices_up:
            mac, vendor = device_up
            cursor.execute("INSERT OR IGNORE INTO devices (mac_source, description, events_detected, is_banned, is_suspicious, is_ignored) VALUES (?, ?, 0, 0, 0, 0)", (mac, vendor))
            cursor.execute("UPDATE devices SET last_up_detected = ? WHERE mac_source == ?", (datetime.now(), mac))

        conn.commit()
        conn.close()   
        #print("===============================================================================")
       # print("Dispositivos actualizados en la base de datos")
        
        sleep(30) 








