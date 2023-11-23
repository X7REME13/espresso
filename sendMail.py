import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
import os
import sqlite3
from datetime import datetime, timedelta
import sys


def generar_correo_con_imagen(nombre_destinatario, nombre_dispositivo, actividad_sospechosa, fecha_hora, ruta_imagen):
    # Cuerpo del correo en formato HTML
    cuerpo_correo_html = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        
        <h2>Notificación de Actividades Extrañas en la Red</h2>
        <p>Estimado/a {nombre_destinatario},</p>
        <p>Se ha detectado que uno de los dispositivos conectados a la red está mostrando actividades inusuales o potencialmente riesgosas. </p>
        <p>Por lo que se lo ha agregado a la lista de dispositivos no admitidos en la red.</p>
        <h4>Detalles de la actividad sospechosa:</h4>
        <ul>
            <li>Dispositivo: <strong>{nombre_dispositivo}</strong> </li>
            <li>Actividad detectada: <strong>{actividad_sospechosa}</strong></li>
            <li>Fecha y hora: <strong>{fecha_hora[0:19]}</strong></li>
        </ul>
        
        <p>Si necesita más detalles o asistencia adicional, no dude en contactar al equipo de soporte técnico o a nuestros técnicos especialistas en seguridad.</p>
        
        <p>Atentamente,<br>El Equipo de Seguridad de Espresso</p>
        <img src="cid:imagen_1" style="width: 100%; height: auto;">
    </div>
    """

    return cuerpo_correo_html

def enviar_correo_html_con_imagen(destinatario, asunto, cuerpo_html, ruta_imagen):
    # Crear el mensaje
    mensaje = MIMEMultipart()
    mensaje['From'] = 'espresso.ips@gmail.com'  # Remitente
    mensaje['To'] = destinatario
    mensaje['Subject'] = asunto

    # Adjuntar la imagen
    if os.path.exists(ruta_imagen):
        with open(ruta_imagen, 'rb') as archivo_imagen:
            imagen = MIMEImage(archivo_imagen.read())
            imagen.add_header('Content-Disposition', 'inline', filename=os.path.basename(ruta_imagen))
            imagen.add_header('Content-ID', '<imagen_1>')
            mensaje.attach(imagen)

    # Agregar el cuerpo del correo como HTML
    mensaje.attach(MIMEText(cuerpo_html, 'html'))

    # Establecer conexión con el servidor SMTP
    servidor_smtp = smtplib.SMTP('smtp.gmail.com', 587)  # Ejemplo con Gmail
    servidor_smtp.starttls()

    # Iniciar sesión en tu cuenta de correo
    servidor_smtp.login('espresso.ips', 'cevy bhey sccu jurn')

    # Enviar el correo
    servidor_smtp.send_message(mensaje)

    # Cerrar la conexión con el servidor SMTP
    servidor_smtp.quit()




# Obtener la dirección MAC como argumento desde la línea de comandos
if len(sys.argv) < 2:
    print("Por favor, ingresa la dirección MAC como argumento.")
    print("Ejemplo: python tu_programa.py 00:1A:2B:3C:4D:5E")
else:
    mac_address = sys.argv[1]
    



    conn = sqlite3.connect('espresso.db')

    cursor = conn.cursor()
    
    print(mac_address)

    cursor.execute("SELECT * FROM events e INNER JOIN types_detection td on td.id = e.id_type_detection WHERE mac_source == ? ORDER BY e.timestamp DESC;", (mac_address, ))

    device = cursor.fetchone()
    #print(device)
    
    if device is not None:
        
        if device[3] is not None and device[3] != '':
            nombre = device[3] 
            
        else:  
            nombre = device[2]
            
        print(">>------------>>>Mail enviado para: ", nombre)
        

        cuerpo_correo_html = generar_correo_con_imagen("cliente de Espresso", nombre, device[8], device[5], "./Logo1.png")
        enviar_correo_html_con_imagen("matiasgpicon@gmail.com", "Alerta de actividades sospechosas en la red", cuerpo_correo_html, "./Logo1.png")
