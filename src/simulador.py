import sqlite3
import random
import datetime

# Coordenadas reales aproximadas de países "calientes" en ciberseguridad
PAISES = [
    ("China", "China Telecom", 35.8617, 104.1954, "114.114.114.114"),
    ("Russia", "Rostelecom", 61.5240, 105.3188, "95.173.136.72"),
    ("USA", "Google Cloud", 37.0902, -95.7129, "8.8.8.8"),
    ("Brazil", "Claro", -14.2350, -51.9253, "177.12.10.1"),
    ("Germany", "Deutsche Telekom", 51.1657, 10.4515, "80.187.100.10")
]

PAYLOADS = ["admin", "root", "123456", "password", "test"]

def generar_datos():
    conn = sqlite3.connect('honeypot.db')
    cursor = conn.cursor()

    # Crea la tabla si todavía no existe (así el simulador funciona sin ejecutar main.py antes)
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

    print("Generando tráfico simulado...")
    for _ in range(50):
        pais, isp, lat, lon, ip_base = random.choice(PAISES)
        # Variamos ligeramente la lat/lon para que no salgan todos los puntos unos encima de otros
        lat_fuzz = lat + random.uniform(-1, 1)
        lon_fuzz = lon + random.uniform(-1, 1)
        
        cursor.execute('''
            INSERT INTO ataques (ip_origen, puerto_origen, payload, fecha, pais, isp, abuse_score, lat, lon)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (ip_base, random.randint(1024, 65000), random.choice(PAYLOADS), 
              datetime.datetime.now(), pais, isp, random.randint(0, 100), lat_fuzz, lon_fuzz))
    
    conn.commit()
    conn.close()
    print("✅ ¡50 ataques simulados inyectados! Revisa el mapa.")

if __name__ == "__main__":
    generar_datos()