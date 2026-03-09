# backend/app.py
import sqlite3
from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime

app = Flask(__name__)
CORS(app)

# ── Base de datos ────────────────────────────────────────
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS registros (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            dispositivos INTEGER,
            intentos     INTEGER,
            ip           TEXT,
            mac          TEXT,
            tipo         TEXT DEFAULT 'normal',
            canal        INTEGER DEFAULT 0,
            fecha        TEXT
        )
    ''')

    # Migración: agregar columna canal si ya existe la tabla sin ella
    try:
        c.execute("ALTER TABLE registros ADD COLUMN canal INTEGER DEFAULT 0")
        print("[DB] Columna 'canal' agregada correctamente.")
    except sqlite3.OperationalError:
        pass  # Ya existía, no hacer nada

    conn.commit()
    conn.close()

init_db()

# ── Estado en memoria ────────────────────────────────────
datos = {
    "dispositivos":    0,
    "intentos":        0,
    "ips_sospechosas": [],
    "macs_detectadas": [],
    "canal":           6,
    "frecuencia":      "2.4GHz",
    "timestamp":       datetime.now().isoformat()
}

# ══════════════════════════════════════════════════════════
#  ENDPOINTS — ESP32
# ══════════════════════════════════════════════════════════

@app.route('/api/update', methods=['POST'])
def update():
    """Endpoint original del ESP32 — compatible hacia atrás."""
    global datos
    payload = request.get_json()
    if not payload:
        return jsonify({"error": "No data"}), 400

    datos["dispositivos"]    = payload.get("dispositivos", 0)
    datos["intentos"]        = payload.get("intentos", 0)
    datos["ips_sospechosas"] = payload.get("ips_sospechosas", [])
    datos["macs_detectadas"] = payload.get("macs", [])
    datos["canal"]           = payload.get("canal", 6)
    datos["timestamp"]       = datetime.now().isoformat()

    ip    = datos["ips_sospechosas"][0] if datos["ips_sospechosas"] else None
    mac   = datos["macs_detectadas"][0] if datos["macs_detectadas"] else None
    tipo  = _classify(datos["intentos"], datos["ips_sospechosas"])
    canal = datos["canal"]

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute(
        "INSERT INTO registros (dispositivos, intentos, ip, mac, tipo, canal, fecha) VALUES (?,?,?,?,?,?,?)",
        (datos["dispositivos"], datos["intentos"], ip, mac, tipo, canal, datos["timestamp"])
    )
    conn.commit()
    conn.close()

    return jsonify({"status": "ok", "timestamp": datos["timestamp"]})


@app.route('/api/esp32/report', methods=['POST'])
def esp32_report():
    """Alias nuevo — mismo comportamiento."""
    return update()


# ══════════════════════════════════════════════════════════
#  ENDPOINTS — DASHBOARD ANGULAR
# ══════════════════════════════════════════════════════════

@app.route('/api/status', methods=['GET'])
def status():
    return jsonify(datos)


@app.route('/api/history', methods=['GET'])
def history():
    limit = int(request.args.get("limit", 50))
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute(
        "SELECT id, dispositivos, intentos, ip, mac, tipo, canal, fecha FROM registros ORDER BY id DESC LIMIT ?",
        (limit,)
    )
    rows = c.fetchall()
    conn.close()

    result = [
        {
            "id":           r[0],
            "dispositivos": r[1],
            "intentos":     r[2],
            "ip":           r[3],
            "mac":          r[4],
            "tipo":         r[5] or "normal",
            "canal":        r[6] or 0,
            "fecha":        r[7]
        }
        for r in rows
    ]
    return jsonify(result)


@app.route('/api/alerts', methods=['GET'])
def alerts():
    """Últimas filas con intentos > 5 como alertas."""
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute(
        "SELECT id, intentos, ip, mac, tipo, canal, fecha FROM registros WHERE intentos > 5 ORDER BY id DESC LIMIT 20"
    )
    rows = c.fetchall()
    conn.close()

    result = [
        {
            "id":        str(r[0]),
            "tipo":      "DEAUTH" if r[4] == "deauth" else "IP_SOSPECHOSA",
            "mensaje":   f"Detectados {r[1]} intentos de deauth en canal {r[5] or '?'}",
            "ip":        r[2],
            "mac":       r[3],
            "timestamp": r[6],
            "nivel":     "critical" if r[1] > 10 else "warning"
        }
        for r in rows
    ]
    return jsonify(result)


@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "timestamp": datetime.now().isoformat()})


# ── Helper ───────────────────────────────────────────────
def _classify(intentos: int, ips: list) -> str:
    if intentos > 5: return "deauth"
    if ips:          return "probe"
    return "normal"


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)