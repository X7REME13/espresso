import pyshark
import sys
import sqlite3
from datetime import datetime


archivo_captura = "/home/kali/Espresso/captures/filteredReducidoMonitor/filterD.pcap"

# print(">> CARGANDO ARCHIVO: ")

# load the capture file
cap = pyshark.FileCapture(archivo_captura, only_summaries=False) # type: ignore

def increment_events(mac):
    try:
        # Verifica si la dirección MAC ya existe en la tabla
        cursor.execute("SELECT id FROM devices WHERE mac_source = ?", (mac,))
        result = cursor.fetchone()

        if result is not None:
            # La dirección MAC ya existe, incrementa events
            cursor.execute("UPDATE devices SET events_detected = events_detected + 1, last_attack_detected = ?, last_up_detected = ? WHERE mac_source = ?", (datetime.now(), datetime.now(), mac.upper()))
        else:
            # La dirección MAC no existe, agrégala
            cursor.execute("INSERT INTO devices (mac_source, description, events_detected, last_attack_detected, last_up_detected, is_suspicious, is_ignored)) VALUES (?, 1, ?, ?, 0, 0)", (mac.upper(), datetime.now(),  datetime.now()))
        
        conn.commit()
        # print("Actualización exitosa")
    except sqlite3.Error as e:
        print("Error al actualizar/agregar:", e)

wlan_sa_devices = {}

#cap.load_packets()

#print(len(cap))

try:
    # Assuming 'cap' is a list of captured packets
    for paquete in cap:
        wlan_sa = paquete['wlan'].get_field_value('wlan.sa')
        type_subtype = paquete['wlan'].get_field_value('wlan.fc.type_subtype')
        timestamp = paquete.sniff_time 
        # print(f"Timestamp: {timestamp}, Source Address: {wlan_sa}, Type_Subtype: {type_subtype}")
        if wlan_sa not in wlan_sa_devices:
            wlan_sa_devices[wlan_sa] = {'first_packet_timestamp': timestamp, 'subtype_counts': {}}

        # Update the first packet timestamp only if this is the first encounter of the device
        elif timestamp < wlan_sa_devices[wlan_sa]['first_packet_timestamp']:
            wlan_sa_devices[wlan_sa]['first_packet_timestamp'] = timestamp

        if type_subtype not in wlan_sa_devices[wlan_sa]['subtype_counts']:
            wlan_sa_devices[wlan_sa]['subtype_counts'][type_subtype] = 0

        wlan_sa_devices[wlan_sa]['subtype_counts'][type_subtype] += 1

    conn = sqlite3.connect('espresso.db')
    cursor = conn.cursor()


    # Display the count of each unique_type_subtypes for each device along with the first packet timestamp
    for wlan_sa, device_info in wlan_sa_devices.items():
        total = 0
        print(f"Device {wlan_sa} - First Packet Timestamp: {device_info['first_packet_timestamp']}:")
        for subtype, count in device_info['subtype_counts'].items():
            print(f"   Type_Subtype: {subtype}, Count: {count}")
            total += count
        
        
        cursor.execute("SELECT description, is_suspicious FROM devices WHERE mac_source = ?", (wlan_sa.upper(),))
        resultado = cursor.fetchone()
        
        valor_is_suspicious = False
        
        if resultado:
            # Si se encontró un resultado, obtener 'description' y 'is_suspicious'
            description, valor_is_suspicious = resultado
        
        if valor_is_suspicious and total < 100:
            
            continue

        if not valor_is_suspicious and total < 250:
            continue
            
        print(valor_is_suspicious)
        cursor.execute("""
            INSERT INTO events (oui_source, mac_source, id_type_detection, cant_packets_detect, "timestamp")
            VALUES (?, ?, ?, ?, ?)
        """, (
            description,
            wlan_sa.upper(),
            5,
            total,
            device_info['first_packet_timestamp']
        ))
        conn.commit()       
        
        increment_events(wlan_sa.upper())
            
except Exception as e:
    print(e)
    print("Hubo un error, continuando...")


cap.close()

exit()
