import json
import sqlite3
import requests
import datetime
import os
from dotenv import load_dotenv

load_dotenv()

# ============================================================
# CONFIGURACIÓN
# ============================================================

COWRIE_JSON = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
HONEYPOT_DB = "/root/honeypot.db"
PROCESSED_LOG = "/root/cowrie_processed.txt"

API_KEY_ABUSE = os.environ["API_KEY_ABUSE"]
TOKEN_IPINFO  = os.environ["TOKEN_IPINFO"]

# ============================================================
# CACHE DE IPs ya consultadas (evita gastar cuota de API)
# ============================================================

cache_geo = {}
cache_abuse = {}

def obtener_datos_ip(ip):
    if ip in cache_geo:
        pais, isp, lat, lon = cache_geo[ip]
        score = cache_abuse.get(ip, 0)
        return pais, isp, score, lat, lon

    lat, lon = 0.0, 0.0
    pais, isp, score = "Unknown", "Unknown", 0

    try:
        url = f"https://ipinfo.io/{ip}?token={TOKEN_IPINFO}"
        r = requests.get(url, timeout=5).json()
        pais = r.get("country", "Unknown")
        isp = r.get("org", "Unknown")
        loc = r.get("loc", "0,0").split(",")
        lat, lon = float(loc[0]), float(loc[1])
    except:
        pass

    cache_geo[ip] = (pais, isp, lat, lon)

    if not ip.startswith("192.168") and not ip.startswith("10.") and ip != "127.0.0.1":
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {"Key": API_KEY_ABUSE, "Accept": "application/json"}
            r = requests.get(url, headers=headers,
                             params={"ipAddress": ip, "maxAgeInDays": "90"},
                             timeout=5)
            if r.status_code == 200:
                score = r.json()["data"]["abuseConfidenceScore"]
        except:
            pass

    cache_abuse[ip] = score
    return pais, isp, score, lat, lon

# ============================================================
# CARGA DE EVENTOS YA PROCESADOS
# ============================================================

def cargar_procesados():
    if not os.path.exists(PROCESSED_LOG):
        return set()
    with open(PROCESSED_LOG, "r") as f:
        return set(line.strip() for line in f.readlines())

def marcar_procesado(event_id):
    with open(PROCESSED_LOG, "a") as f:
        f.write(event_id + "\n")

# ============================================================
# INSERCIÓN EN SQLITE
# ============================================================

def guardar_evento(ip, port, payload, pais, isp, score, lat, lon):
    try:
        conn = sqlite3.connect(HONEYPOT_DB)
        cursor = conn.cursor()
        fecha = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute('''
            INSERT INTO ataques (ip_origen, puerto_origen, payload, fecha, pais, isp, abuse_score, lat, lon)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (ip, port, payload, fecha, pais, isp, score, lat, lon))
        conn.commit()
        conn.close()
        print(f"[+] Cowrie → DB: {ip} ({pais}) | Score: {score} | {payload[:50]}")
    except Exception as e:
        print(f"[!] Error insertando: {e}")

# ============================================================
# PROCESAMIENTO DEL JSON DE COWRIE
# ============================================================

def procesar_cowrie():
    if not os.path.exists(COWRIE_JSON):
        print(f"[!] No existe {COWRIE_JSON} todavía.")
        return

    procesados = cargar_procesados()
    nuevos = 0

    with open(COWRIE_JSON, "r") as f:
        for linea in f:
            linea = linea.strip()
            if not linea:
                continue
            try:
                evento = json.loads(linea)
            except:
                continue

            # Solo procesamos intentos de login
            event_id = evento.get("session", "") + "_" + evento.get("timestamp", "")
            tipo = evento.get("eventid", "")

            # Filtrar solo eventos relevantes
            if tipo not in ["cowrie.login.failed", "cowrie.login.success",
                            "cowrie.session.connect", "cowrie.command.input"]:
                continue

            if event_id in procesados:
                continue

            ip = evento.get("src_ip", "")
            port = evento.get("src_port", 0)

            # Construir payload descriptivo según el tipo de evento
            if tipo == "cowrie.login.failed":
                usuario = evento.get("username", "")
                password = evento.get("password", "")
                payload = f"[COWRIE] LOGIN FAILED: {usuario}/{password}"
            elif tipo == "cowrie.login.success":
                usuario = evento.get("username", "")
                password = evento.get("password", "")
                payload = f"[COWRIE] LOGIN SUCCESS: {usuario}/{password}"
            elif tipo == "cowrie.command.input":
                cmd = evento.get("input", "")
                payload = f"[COWRIE] CMD: {cmd}"
            else:
                payload = f"[COWRIE] {tipo}"

            if not ip:
                continue

            print(f"[*] Procesando {ip} ({tipo})...")
            pais, isp, score, lat, lon = obtener_datos_ip(ip)
            guardar_evento(ip, port, payload, pais, isp, score, lat, lon)
            marcar_procesado(event_id)
            nuevos += 1

    print(f"\n[✓] Procesados {nuevos} eventos nuevos de Cowrie.")

if __name__ == "__main__":
    procesar_cowrie()