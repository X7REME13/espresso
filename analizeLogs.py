import os
from time import sleep
import pyshark
import sqlite3
from datetime import datetime
import json
import subprocess

# connect to a db in sqllite3 and get all devices


# get value from a json config.json
# with open('config.json') as json_file:
#     data = json.load(json_file)
#     sensibility = data['sensibility']

while True:
    conn = sqlite3.connect('espresso.db')

    cursor = conn.cursor()
    cursor.execute("SELECT * FROM devices WHERE events_detected > ? and is_banned == 0 and is_ignored == 0", (3,)) 

    devices = cursor.fetchall()

    for device in devices:

        # get the severity of the events ocurred today
        cursor.execute("SELECT td.severity FROM events e INNER JOIN types_detection td on td.id = e.id_type_detection WHERE mac_source = ? AND timestamp > ?", (device[1], datetime.now().strftime("%Y-%m-%d 00:00:00")))

        # sum all severity
        severity = 0
        for event in cursor.fetchall():
            severity += event[0]
        
        # if severity is higher than 5, delete the device
        if severity > 3:
            
            # update is_banned to 1
            cursor.execute("UPDATE devices SET is_banned = 1, time_of_ban = ? WHERE id = ?", (datetime.now().strftime("%Y-%m-%d %H:%M:%S") ,device[0],))


            # insert in devices_balcklist if not in devices_blacklist
            # cursor.execute("SELECT id FROM devices_blacklist WHERE mac_source = ?", (device[1],))
            # deviceExist = cursor.fetchone()

            # if deviceExist is None:
            #     cursor.execute("INSERT INTO devices_blacklist (mac_source, description, events_detected, timestamp_of_ban) VALUES (?, ?, ?, ?)", (device[1], device[2], device[3], device[4]))   
            
            # delete in devices
            # cursor.execute("DELETE FROM devices WHERE id = ?", (device[0],))

            conn.commit()      
            # log the transaction
            print(f"Device {device[2]} | {device[1]} inserted in devices_blacklist")
            
            subprocess.run(['python', 'sendMail.py', device[1]])

    
    conn.close()
    sleep(30)
        
    

