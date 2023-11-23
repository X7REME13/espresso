import os
import pyshark
import sqlite3
from datetime import datetime
import json
import nest_asyncio
nest_asyncio.apply()


directorio = '/home/kali/Espresso/captures/filteredReducido/'

tamano_minimo = 400 

archivos_detectados = []
# print("Recorriendo carpetas")
for archivo in os.listdir(directorio):
    ruta_archivo = os.path.join(directorio, archivo)
    
    if os.path.isfile(ruta_archivo) and os.path.getsize(ruta_archivo) > tamano_minimo:
        archivos_detectados.append(ruta_archivo)

conn = sqlite3.connect('espresso.db')
cursor = conn.cursor()

def increment_events(mac, oui):
    try:
        # Verifica si la dirección MAC ya existe en la tabla
        cursor.execute("SELECT id FROM devices WHERE mac_source = ?", (mac,))
        result = cursor.fetchone()

        if result is not None:
            # La dirección MAC ya existe, incrementa events
            cursor.execute("UPDATE devices SET events_detected = events_detected + 1, last_attack_detected = ?, last_up_detected = ?,  is_suspicious = 1 WHERE mac_source = ?", (datetime.now(), datetime.now(), mac.upper()))
        else:
            # La dirección MAC no existe, agrégala
            cursor.execute("INSERT INTO devices (mac_source, description, events_detected, last_attack_detected, last_up_detected, is_suspicious, is_ignored) VALUES (?, ?, 1, ?, ?, 0, 0)", (mac.upper(), oui, datetime.now(),  datetime.now()))
        
        conn.commit()
        # print("Actualización exitosa")
    except sqlite3.Error as e:
        print("Error al actualizar/agregar:", e)

for archivo in archivos_detectados:
    cap = pyshark.FileCapture(archivo, only_summaries=False) # type: ignore
    print(">>>>>>> ", archivo)
    combination_data = {}
    
    for packet in cap:

        if 'ARP' in packet and 'ETH' in packet and not 'IP' in packet:
            src_ip = packet['ARP'].src_proto_ipv4
            src_mac = packet['ARP'].src_hw_mac.upper()

            # print()
            # print(packet['ETH'].get('eth.dst_oui_resolved'))
            # print(packet['ETH'].get('eth.src.oui_resolved'))
            
            # Crea una combinación IP/MAC única como clave del diccionario
            combination_key = f"{src_ip}/{src_mac}"
            
            # Inicializa los datos para la combinación si es la primera vez que se encuentra
            if combination_key not in combination_data:

                desc = packet['ETH'].get('eth.src_oui_resolved')

                if desc is None:
                    #open a json file
                    with open('mac-vendors-export.json') as json_file:
                        data = json.load(json_file)
                        # find the mac in the json file
                        print(src_mac[0:8].upper()) 

                        for p in data:
                            # print(p['macPrefix']) 

                            if p['macPrefix'] == src_mac[0:8].upper():
                                desc = p['vendorName']
                                break

                if desc is None:
                    desc = ""
                        
                combination_data[combination_key] = {
                    'ip_source': packet['ARP'].src_proto_ipv4,
                    'mac_source': packet['ARP'].src_hw_mac.upper(),
                    'oui_source': desc,
                    # 'ip_destination': "dest_ip",
                    # 'mac_destination': "dest_mac",
                    # 'oui_destination': "packet['ETH'].get('eth.dst.oui_resolved')",
                    'id_type_detection': (os.path.splitext(os.path.basename(archivo))[0]).split("_")[0],
                    'cant_packets_detect': 0,
                    'timestamp': None
                }
            
            # Incrementa el contador para la combinación IP/MAC
            combination_data[combination_key]['cant_packets_detect'] += 1
            
            # Actualiza el timestamp si es necesario (puedes personalizar esto según tus necesidades)
            if combination_data[combination_key]['timestamp'] is None:
                combination_data[combination_key]['timestamp'] = packet.sniff_time
        
        if 'IP' in packet and 'ETH' in packet:
            src_ip = packet['IP'].src
            src_mac = packet['ETH'].src.upper()

            # print(packet)
            
            # Crea una combinación IP/MAC única como clave del diccionario
            combination_key = f"{src_ip}/{src_mac}"
            
            # Inicializa los datos para la combinación si es la primera vez que se encuentra
            if combination_key not in combination_data:
                combination_data[combination_key] = {
                    'ip_source': packet['IP'].src,
                    'mac_source': packet['ETH'].src.upper(),
                    'oui_source': packet['ETH'].get('eth.src.oui_resolved'),
                    # 'ip_destination': packet['IP'].dst,
                    # 'mac_destination': packet['ETH'].dst,
                    # 'oui_destination': packet['ETH'].get('eth.dst.oui_resolved'),
                    'id_type_detection': (os.path.splitext(os.path.basename(archivo))[0]).split("_")[0],
                    'cant_packets_detect': 0,
                    'timestamp': None
                }
            
            # Incrementa el contador para la combinación IP/MAC
            combination_data[combination_key]['cant_packets_detect'] += 1
            
            # Actualiza el timestamp si es necesario (puedes personalizar esto según tus necesidades)
            if combination_data[combination_key]['timestamp'] is None:
                combination_data[combination_key]['timestamp'] = packet.sniff_time
    
    for combination, data in combination_data.items():

        if data['cant_packets_detect'] < 5:
            continue

        if data['cant_packets_detect'] < 300 and data['id_type_detection'] == "3":
            continue
           
        if data['cant_packets_detect'] < 30 and data['id_type_detection'] == "0":
            continue


        cursor.execute("""
            INSERT INTO events (ip_source, mac_source, oui_source, id_type_detection, cant_packets_detect, "timestamp")
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            data['ip_source'],
            data['mac_source'].upper(),
            data['oui_source'],
            # data['ip_destination'],
            # data['mac_destination'],
            # data['oui_destination'],
            data['id_type_detection'],
            data['cant_packets_detect'],
            data['timestamp']
        ))
        conn.commit()       
        
        increment_events(data['mac_source'].upper(), data['oui_source'])




conn.close()
exit()
