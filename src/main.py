import socket
import threading
import sqlite3
import datetime
import requests
import json
import time
import ipaddress
import os
from dotenv import load_dotenv

load_dotenv()

# --- CONFIGURACIÓN Y CLAVES ---
API_KEY_VT    = os.environ["API_KEY_VT"]
API_KEY_ABUSE = os.environ["API_KEY_ABUSE"]
TOKEN_IPINFO  = os.environ["TOKEN_IPINFO"]

BIND_IP = "0.0.0.0"
BIND_PORT = 2222 

# --- BASE DE DATOS (VERSIÓN 2.0 CON GPS) ---
def init_db():
    conn = sqlite3.connect('honeypot.db', check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute('PRAGMA journal_mode=WAL;')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ataques (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_origen TEXT,
            puerto_origen INTEGER,
            payload TEXT,
            fecha TEXT,
            pais TEXT,
            isp TEXT,
            abuse_score INTEGER,
            lat REAL,
            lon REAL
        )
    ''')
    conn.commit()
    conn.close()

def guardar_ataque(ip, port, payload, pais, isp, score, lat, lon):
    try:
        conn = sqlite3.connect('honeypot.db', check_same_thread=False)
        cursor = conn.cursor()
        fecha_actual = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute('''
            INSERT INTO ataques (ip_origen, puerto_origen, payload, fecha, pais, isp, abuse_score, lat, lon)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (ip, port, payload, fecha_actual, pais, isp, score, lat, lon))
        conn.commit()
        conn.close()
        print(f"[DB] Ataque registrado: IP {ip} | País: {pais} | Score: {score}")
    except Exception as e:
        print(f"[!] Error guardando en BD: {e}")

# --- INTELIGENCIA ---
def obtener_datos_ip(ip):
    """Consulta IPinfo para Geo y AbuseIPDB para Score"""
    lat, lon = 0.0, 0.0
    pais, isp = "Unknown", "Unknown"
    score = 0
    
    # 1. GEO (IPinfo)
    try:
        url = f"https://ipinfo.io/{ip}?token={TOKEN_IPINFO}"
        r = requests.get(url, timeout=5).json()
        pais = r.get("country", "Unknown")
        isp = r.get("org", "Unknown")
        loc = r.get("loc", "0,0").split(',')
        lat, lon = float(loc[0]), float(loc[1])
    except:
        pass

    # 2. REPUTACIÓN (AbuseIPDB)
    try:
        is_private = ipaddress.ip_address(ip).is_private
    except ValueError:
        is_private = True # Si la IP es inválida, evitamos la consulta

    if not is_private and ip != "127.0.0.1":
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {'Key': API_KEY_ABUSE, 'Accept': 'application/json'}
            r = requests.get(url, headers=headers, params={"ipAddress": ip, "maxAgeInDays": "90"}, timeout=5)
            if r.status_code == 200:
                score = r.json()["data"]["abuseConfidenceScore"]
        except:
            pass
            
    return pais, isp, score, lat, lon

# --- HILO DE ANÁLISIS ---
def analizar_y_guardar(ip, port, payload):
    print(f"[*] Analizando IP: {ip}...")
    pais, isp, score, lat, lon = obtener_datos_ip(ip)
    guardar_ataque(ip, port, payload, pais, isp, score, lat, lon)

# --- SENSOR ---
def handle_client(client, addr):
    ip, port = addr
    try:
        client.send(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n")
        client.settimeout(5)
        payload = client.recv(1024).decode('utf-8', errors='ignore').strip()
        threading.Thread(target=analizar_y_guardar, args=(ip, port, payload)).start()
    except socket.timeout:
        pass
    except Exception as e:
        print(f"[!] Error en handle_client ({ip}): {e}")
    finally:
        client.close()

def start_server():
    init_db()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((BIND_IP, BIND_PORT))
    server.listen(5)
    print(f"[*] Honeypot 2.0 (con GPS) escuchando en puerto {BIND_PORT}...")
    while True:
        client, addr = server.accept()
        threading.Thread(target=handle_client, args=(client, addr)).start()

if __name__ == "__main__":
    start_server()