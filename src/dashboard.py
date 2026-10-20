import streamlit as st
import pandas as pd
import sqlite3
import pydeck as pdk
import time

# --- CONFIGURACIÓN ---
st.set_page_config(page_title="Honeypot Dashboard - UAH", layout="wide", page_icon="🛡️")
st.sidebar.title("Configuración")
auto_refresh = st.sidebar.checkbox("🔄 Auto-refresco (Activo)", value=True)

# Coordenadas de la EPS de la UAH (Alcalá de Henares)
UAH_LAT = 40.513126
UAH_LON = -3.349615

# --- CARGA DE DATOS ---
def cargar_datos():
    try:
        conn = sqlite3.connect('honeypot.db', check_same_thread=False)
        df = pd.read_sql_query("SELECT * FROM ataques ORDER BY id DESC", conn)
        conn.close()
        # Añadimos columna de destino fijo (UAH) para dibujar los arcos
        df['dest_lat'] = UAH_LAT
        df['dest_lon'] = UAH_LON
        # Colores dinámicos: Rojo si el riesgo > 50, Amarillo si < 50
        df['color_r'] = df['abuse_score'].apply(lambda x: 255 if x > 50 else 255)
        df['color_g'] = df['abuse_score'].apply(lambda x: 0 if x > 50 else 200)
        df['color_b'] = 0
        return df
    except:
        return pd.DataFrame()

# --- INTERFAZ ---
st.title("🛡️ Amenazas Globales en Tiempo Real")
st.markdown(f"### 📍 Objetivo Protegido: EPS UAH (Lat: {UAH_LAT}, Lon: {UAH_LON})")

df = cargar_datos()

if df.empty:
    st.warning("⚠️ Sin datos. Ejecuta 'python simulador.py'.")
else:
    # --- MÉTRICAS ---
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Ataques Totales", len(df))
    col2.metric("Orígenes Únicos", df['ip_origen'].nunique())
    col3.metric("Principal Atacante", df['pais'].mode()[0] if not df['pais'].empty else "N/A")
    col4.metric("Riesgo Promedio", f"{df['abuse_score'].mean():.1f}/100")

    # --- MAPA DE ARCOS (WAR ROOM STYLE) ---
    st.subheader("🌐 Trayectoria de Ataques")

    map_data = df[(df['lat'] != 0.0) & (df['lon'] != 0.0)]

    if not map_data.empty:
        # Capa de Arcos: Dibuja líneas desde Origen -> Madrid
        arc_layer = pdk.Layer(
            "ArcLayer",
            data=map_data,
            get_source_position=["lon", "lat"],
            get_target_position=["dest_lon", "dest_lat"],
            get_source_color=["color_r", "color_g", "color_b", 160], # Color según riesgo
            get_target_color=[0, 255, 0, 100], # Verde en EPS UAH (Defensor)
            get_width=3,
            get_tilt=15,
            get_height=0.5, # Altura del arco
        )

        # Vista inicial: Centrada en el Atlántico para ver América y Europa
        view_state = pdk.ViewState(
            longitude=-20,
            latitude=30,
            zoom=1.5,
            pitch=40, # Inclinación para ver el efecto 3D de los arcos
        )

        st.pydeck_chart(pdk.Deck(
            map_style=None,
            initial_view_state=view_state,
            layers=[arc_layer],
            tooltip={"text": "Origen: {pais}\nIP: {ip_origen}\nRiesgo: {abuse_score}"}
        ))
    else:
        st.info("Solo se detectan ataques locales (localhost).")

    # --- DATOS CRUDOS ---
    with st.expander("Ver Logs en Bruto"):
        st.dataframe(df[['fecha', 'ip_origen', 'pais', 'payload', 'abuse_score']].head(20))

# --- REFRESCO ---
if auto_refresh:
    time.sleep(3)
    st.rerun()