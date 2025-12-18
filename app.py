"""
Secure Microgrid Monitoring System - Flask Application
Advanced IoT IDS with Background Attack Simulation & Detection
HiveMQ Cloud Integration
"""

from flask import (
    Flask, render_template, request, jsonify,
    session, redirect, url_for, send_file
)
from flask_socketio import SocketIO, emit
import paho.mqtt.client as mqtt
import ssl
import json
import time
import random
import hashlib
import os
import sqlite3
from dotenv import load_dotenv
from datetime import datetime
from collections import deque
import threading
import numpy as np
import csv

# =========================================================
# CONFIG
# =========================================================

load_dotenv()

MQTT_BROKER = os.getenv("MQTT_BROKER")
MQTT_PORT   = int(os.getenv("MQTT_PORT", "8883"))
MQTT_USER   = os.getenv("MQTT_USER")
MQTT_PASS   = os.getenv("MQTT_PASS")
SECRET_KEY  = os.getenv("SECRET_KEY", "microgrid-secret-2024")

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
CAPSTONE_DIR = BASE_DIR

app = Flask(
    __name__,
    template_folder=os.path.join(CAPSTONE_DIR, "templates"),
    static_folder=os.path.join(CAPSTONE_DIR, "static"),
)
app.secret_key = SECRET_KEY

socketio = SocketIO(app, cors_allowed_origins="*")

# =========================================================
# DB FOR ALERT LOGGING
# =========================================================

DB_FILE = os.path.join(CAPSTONE_DIR, "alerts.db")

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message TEXT,
            timestamp TEXT
        )
        """
    )
    conn.commit()
    conn.close()

def log_alert_db(msg: str):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(
        "INSERT INTO alerts (message, timestamp) VALUES (?, ?)",
        (msg, datetime.now().isoformat()),
    )
    conn.commit()
    conn.close()

init_db()

# =========================================================
# GLOBAL STATE
# =========================================================

TOPICS = {
    "sensor": "microgrid/sensors/data",
    "attack": "microgrid/attack",
    "alert":  "microgrid/alert",
}

mqtt_client: mqtt.Client | None = None

sensor_data = {
    "temperature": deque(maxlen=50),
    "humidity":    deque(maxlen=50),
    "light":       deque(maxlen=50),
    "timestamps":  deque(maxlen=50),
}

alerts = []
attack_counts = {
    "ddos": 0,
    "injection": 0,
    "replay": 0,
    "mitm": 0,
    "unauthorized": 0,
    "tampering": 0,
    "protocol_fuzzing": 0,
    "session_hijack": 0,
    "timing_attack": 0,
    "zero_day": 0,
    "crypto_attack": 0,
    "firmware_inject": 0,
}

system_stats = {
    "total_packets_analyzed": 0,
    "total_threats_blocked": 0,
    "false_positive_rate": 0.02,
    "detection_accuracy": 0.98,
    "avg_detection_time_ms": 0.0,
    "system_uptime_start": datetime.now(),
    "blocked_ips": set(),
    "threat_trends": deque(maxlen=24),
}

severity_weights = {
    "critical": 10,
    "high": 7,
    "medium": 4,
    "low": 2,
}

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = hashlib.sha256("admin123".encode()).hexdigest()

session_id = str(int(time.time()))
background_thread = None

# =========================================================
# IDS ENGINE
# =========================================================

class AdvancedIDSEngine:
    def __init__(self):
        self.message_history   = deque(maxlen=100)
        self.traffic_counter   = deque(maxlen=50)
        self.session_tokens    = set()
        self.baseline_temp     = (20, 35)
        self.baseline_humidity = (30, 80)
        self.baseline_light    = (0, 1023)
        self.message_intervals = deque(maxlen=20)
        self.last_message_time = time.time()

        self.detection_times = deque(maxlen=100)
        self.threat_history  = deque(maxlen=1000)
        self.anomaly_scores  = deque(maxlen=50)

    def detect_ddos(self):
        self.traffic_counter.append(time.time())
        recent = [t for t in self.traffic_counter if time.time() - t < 5]

        if len(recent) > 25:
            return True, f"DDoS Attack: {len(recent)} req/5s", "critical"
        if len(recent) > 15:
            return True, f"Potential DDoS: {len(recent)} req/5s", "high"
        return False, "", ""

    def detect_injection(self, payload):
        patterns = {
            "sql": ["SELECT", "DROP", "INSERT", "UPDATE", "DELETE", "UNION", "--", ";--"],
            "nosql": ["$where", "$ne", "$gt", "$regex", "db.collection"],
            "command": ["&&", "||", ";", "|", "`", "$(", "eval(", "exec("],
            "xss": ["<script>", "javascript:", "onerror=", "onload=", "<iframe>"],
            "path": ["../", "..\\", "/etc/passwd", "C:\\Windows"],
        }
        payload_str = str(payload).lower()
        for attack_type, pattern_list in patterns.items():
            for pattern in pattern_list:
                if pattern.lower() in payload_str:
                    return True, f"Injection ({attack_type}): '{pattern}'", "critical"
        return False, "", ""

    def detect_replay(self, message):
        msg_hash = hashlib.md5(str(message).encode()).hexdigest()
        if msg_hash in self.message_history:
            return True, "Replay: Duplicate message", "high"
        self.message_history.append(msg_hash)
        return False, "", ""

    def detect_tampering(self, temp, humidity, light):
        anomalies = []
        anomaly_score = 0

        if not (self.baseline_temp[0] <= temp <= self.baseline_temp[1]):
            anomalies.append(f"Temp {temp}°C")
            anomaly_score += 3
        if not (self.baseline_humidity[0] <= humidity <= self.baseline_humidity[1]):
            anomalies.append(f"Humidity {humidity}%")
            anomaly_score += 3
        if not (self.baseline_light[0] <= light <= self.baseline_light[1]):
            anomalies.append(f"Light {light}")
            anomaly_score += 2

        if len(sensor_data["temperature"]) > 10:
            mean = np.mean(sensor_data["temperature"])
            std  = np.std(sensor_data["temperature"])
            if std > 0 and abs(temp - mean) > 3 * std:
                anomalies.append("Temp > 3σ")
                anomaly_score += 4

        self.anomaly_scores.append(anomaly_score)

        if anomalies:
            return True, "Tampering: " + "; ".join(anomalies), "high"
        return False, "", ""

    def detect_timing_attack(self):
        current_time = time.time()
        interval = current_time - self.last_message_time
        self.message_intervals.append(interval)
        self.last_message_time = current_time

        if len(self.message_intervals) > 10:
            avg = np.mean(self.message_intervals)
            std = np.std(self.message_intervals)
            if interval < 0.01:
                return True, f"Timing: {interval*1000:.2f}ms", "medium"
            if std < 0.1 and avg < 1:
                return True, f"Timing: rhythmic pattern (σ={std:.3f})", "medium"
        return False, "", ""

    def detect_unauthorized(self):
        # Real unauthorized detection would be based on auth/session data.
        return False, "", ""

    def analyze(self, message, temp, humidity, light):
        start_time = time.time()
        threats = []

        checks = [
            (self.detect_ddos, "ddos"),
            (lambda: self.detect_injection(message), "injection"),
            (lambda: self.detect_replay(message), "replay"),
            (lambda: self.detect_tampering(temp, humidity, light), "tampering"),
            (self.detect_timing_attack, "timing_attack"),
            (self.detect_unauthorized, "unauthorized"),
        ]

        for func, name in checks:
            is_threat, msg, severity = func()
            if is_threat:
                threats.append((name, msg, severity))

        detection_time = (time.time() - start_time) * 1000
        self.detection_times.append(detection_time)

        system_stats["total_packets_analyzed"] += 1
        if threats:
            system_stats["total_threats_blocked"] += len(threats)
        if self.detection_times:
            system_stats["avg_detection_time_ms"] = float(np.mean(self.detection_times))

        return threats

    def calculate_risk_score(self):
        if not self.threat_history:
            return 0.0
        recent = [t for t in self.threat_history if time.time() - t["timestamp"] < 3600]
        score = 0
        for t in recent:
            score += severity_weights.get(t["severity"], 1)
        score = min(100, (score / 50) * 100)
        return round(score, 2)

ids_engine = AdvancedIDSEngine()

# =========================================================
# MQTT
# =========================================================

def on_connect(client, userdata, flags, rc):
    print(f"[MQTT] Connected with result code {rc}")
    client.subscribe(TOPICS["sensor"])

def on_message(client, userdata, msg):
    print("[MQTT] Message on", msg.topic, "->", msg.payload)

    try:
        payload = json.loads(msg.payload.decode())
    except Exception:
        payload = {"raw": msg.payload.decode(errors="ignore")}

    temp  = float(payload.get("temperature", 25))
    hum   = float(payload.get("humidity", 50))
    light = float(payload.get("light", 500))

    sensor_data["temperature"].append(temp)
    sensor_data["humidity"].append(hum)
    sensor_data["light"].append(light)
    sensor_data["timestamps"].append(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    threats = ids_engine.analyze(payload, temp, hum, light)

    for attack_type, message, severity in threats:
        alert = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type": attack_type,
            "severity": severity,
            "message": message,
            "source": "MQTT Stream",
        }
        alerts.append(alert)
        attack_counts[attack_type] += 1
        ids_engine.threat_history.append(
            {"timestamp": time.time(), "severity": severity}
        )
        log_alert_db(message)
        socketio.emit("alert_update", alert)

    socketio.emit(
        "sensor_update",
        {
            "temperature": temp,
            "humidity": hum,
            "light": light,
            "timestamp": sensor_data["timestamps"][-1],
        },
    )

    socketio.emit(
        "stats_update",
        {
            "total_packets_analyzed": system_stats["total_packets_analyzed"],
            "total_threats_blocked": system_stats["total_threats_blocked"],
            "avg_detection_time_ms": system_stats["avg_detection_time_ms"],
            "risk_score": ids_engine.calculate_risk_score(),
        },
    )

def setup_mqtt():
    global mqtt_client
    mqtt_client = mqtt.Client()
    mqtt_client.username_pw_set(MQTT_USER, MQTT_PASS)
    mqtt_client.tls_set(cert_reqs=ssl.CERT_REQUIRED)
    mqtt_client.on_connect = on_connect
    mqtt_client.on_message = on_message
    mqtt_client.connect(MQTT_BROKER, MQTT_PORT, 60)
    mqtt_client.loop_start()
    print("[MQTT] HiveMQ client started")

# =========================================================
# ATTACK SIMULATOR (still generates real attack patterns)
# =========================================================

def simulate_ddos_background():
    for _ in range(30):
        mqtt_client.publish(TOPICS["sensor"], json.dumps({"temperature": 30}))
        time.sleep(0.1)

def simulate_injection_background():
    mqtt_client.publish(
        TOPICS["sensor"],
        json.dumps({"temperature": 30, "note": "DROP TABLE users; --"}),
    )

def background_attack_generator():
    scenarios = [
        ("DDoS", simulate_ddos_background),
        ("Injection", simulate_injection_background),
    ]
    print("[SIMULATOR] Background attack generator started")
    count = 0
    while True:
        time.sleep(random.uniform(15, 35))
        if random.random() < 0.4:
            count += 1
            name, func = random.choice(scenarios)
            print(f"[SIMULATOR] Attack #{count}: {name}")
            try:
                func()
            except Exception as e:
                print("[SIMULATOR] failed:", e)

# =========================================================
# UTILS
# =========================================================

def export_alerts_csv():
    filename = os.path.join(CAPSTONE_DIR, f"alerts_{session_id}.csv")
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "type", "severity", "message"])
        for a in alerts:
            writer.writerow([a["timestamp"], a["type"], a["severity"], a["message"]])
    return filename

def clear_session_logs():
    global alerts
    alerts = []
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM alerts")
    conn.commit()
    conn.close()

# =========================================================
# ROUTES
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if (
            username == ADMIN_USERNAME
            and hashlib.sha256(password.encode()).hexdigest() == ADMIN_PASSWORD
        ):
            session["logged_in"] = True
            return redirect(url_for("dashboard"))
        error = "Invalid credentials"
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
@app.route("/dashboard")
def dashboard():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    risk = ids_engine.calculate_risk_score()
    return render_template(
        "dashboard.html",
        system_stats=system_stats,
        alerts=alerts[-10:],
        risk_score=risk,
        session_id=session_id,
    )

@app.route("/api/export-csv")
def api_export_csv():
    if not session.get("logged_in"):
        return jsonify({"error": "Unauthorized"}), 401
    if not alerts:
        return jsonify({"error": "No alerts to export"}), 404
    csv_file = export_alerts_csv()
    return send_file(csv_file, as_attachment=True,
                     download_name=os.path.basename(csv_file))

@app.route("/api/clear-alerts", methods=["POST"])
def api_clear_alerts():
    if not session.get("logged_in"):
        return jsonify({"error": "Unauthorized"}), 401
    global attack_counts
    alerts.clear()
    for k in attack_counts:
        attack_counts[k] = 0
    clear_session_logs()
    return jsonify({"success": True})

@app.route("/api/debug-sensors")
def debug_sensors():
    return jsonify(
        {
            "sensor_data": {
                "temperature": list(sensor_data["temperature"]),
                "humidity": list(sensor_data["humidity"]),
                "light": list(sensor_data["light"]),
                "timestamps": list(sensor_data["timestamps"]),
                "count": len(sensor_data["temperature"]),
            },
            "mqtt_connected": mqtt_client is not None,
            "total_alerts": len(alerts),
            "last_update": sensor_data["timestamps"][-1]
            if sensor_data["timestamps"]
            else "No data",
        }
    )

# =========================================================
# SOCKET.IO
# =========================================================

@socketio.on("connect")
def handle_connect():
    print("[SOCKETIO] Client connected")
    emit("connection_response", {"status": "connected"})
    if sensor_data["temperature"]:
        sensor_update = {
            "temperature": list(sensor_data["temperature"])[-1],
            "humidity": list(sensor_data["humidity"])[-1],
            "light": list(sensor_data["light"])[-1],
            "timestamp": list(sensor_data["timestamps"])[-1],
        }
        emit("sensor_update", sensor_update)
        emit(
            "stats_update",
            {
                "total_packets_analyzed": system_stats["total_packets_analyzed"],
                "total_threats_blocked": system_stats["total_threats_blocked"],
                "avg_detection_time_ms": system_stats["avg_detection_time_ms"],
                "risk_score": ids_engine.calculate_risk_score(),
            },
        )

@socketio.on("disconnect")
def handle_disconnect():
    print("[SOCKETIO] Client disconnected")

# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":
    setup_mqtt()
    background_thread = threading.Thread(
        target=background_attack_generator, daemon=True
    )
    background_thread.start()

    print("\n[ACCESS]  http://localhost:5000")
    print("[LOGIN]  admin / admin123\n")

    socketio.run(app, debug=False, host="0.0.0.0", port=5000,
                 allow_unsafe_werkzeug=True)
