import json, sqlite3, threading, time
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
import ssl
import numpy as np
import paho.mqtt.client as mqtt
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from pydantic import BaseModel

DB = "gridshield.db"
BROKER = "127.0.0.1"
PORT = 8883
JWT_SECRET = "gridshield-hackathon-secret-change-me"
JWT_ALG = "HS256"
DEVICES = [f"METER-{i:03d}" for i in range(1, 6)]
DEVICE_KEYS = {d: f"GRID-{d}-KEY" for d in DEVICES}
OFFLINE_AFTER = 5
lock = threading.RLock()
status = {d: {"id": d, "status": "offline", "power": 0.0, "voltage": 230.0, "frequency": 50.0,
              "threat": 0, "last_seen": None, "message_rate": 0.0, "authenticated": False} for d in DEVICES}
quarantined = set()
alerts = deque(maxlen=100)
rates = defaultdict(deque)
history = defaultdict(lambda: deque(maxlen=60))

app = FastAPI(title="GridShield API", version="2.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"], allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])
security = HTTPBearer()

class DeviceAction(BaseModel):
    device_id: str
class LoginRequest(BaseModel):
    username: str
    password: str

def db():
    c = sqlite3.connect(DB, check_same_thread=False)
    c.execute("CREATE TABLE IF NOT EXISTS telemetry (id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT, ts REAL, power REAL, voltage REAL, frequency REAL)")
    c.execute("CREATE TABLE IF NOT EXISTS incidents (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, device_id TEXT, kind TEXT, score INTEGER, detail TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS device_registry (device_id TEXT PRIMARY KEY, device_key TEXT, active INTEGER DEFAULT 1)")
    for device, key in DEVICE_KEYS.items():
        c.execute("INSERT OR IGNORE INTO device_registry(device_id,device_key,active) VALUES(?,?,1)", (device, key))
    c.commit()
    return c
conn = db()

def require_operator(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALG])
        if payload.get("sub") != "operator": raise HTTPException(401, "Invalid operator token")
        return payload
    except JWTError:
        raise HTTPException(401, "Invalid or expired token")

def log_incident(device, kind, score, detail):
    ts = time.time()
    event = {"timestamp": datetime.fromtimestamp(ts, timezone.utc).isoformat(), "device_id": device,
             "type": kind, "score": score, "detail": detail}
    alerts.appendleft(event)
    conn.execute("INSERT INTO incidents(ts,device_id,kind,score,detail) VALUES(?,?,?,?,?)", (ts, device, kind, score, detail))
    conn.commit()
    print(f"[SECURITY] {kind} device={device} score={score} detail={detail}")

def authenticate_device(device, device_key):
    row = conn.execute("SELECT device_key, active FROM device_registry WHERE device_id=?", (device,)).fetchone()
    ok = bool(row and row[1] and row[0] == device_key)
    if not ok:
        log_incident(device or "UNKNOWN", "AUTH_FAILURE", 80, "Device authentication failed")
    return ok

def score_event(device, power, rate, voltage, frequency):
    score = 0
    reasons = []

    # Strong energy anomaly
    if power > 5000:
        score += 80
        reasons.append("abnormal power consumption")

    # Strong traffic anomaly
    if rate > 15:
        score += 80
        reasons.append("MQTT traffic flood")

    # Electrical anomalies
    if not 210 <= voltage <= 250:
        score += 10
        reasons.append("voltage anomaly")

    if not 49 <= frequency <= 51:
        score += 10
        reasons.append("frequency anomaly")

    score = min(score, 100)

    # CRITICAL -> automatically quarantine
    if score >= 70 and device not in quarantined:
        quarantined.add(device)

        log_incident(
            device,
            "CRITICAL",
            score,
            ", ".join(reasons)
        )

    # Warning
    elif score >= 30 and device not in quarantined:
        log_incident(
            device,
            "WARNING",
            score,
            ", ".join(reasons)
        )

    return score, reasons

def on_connect(client, userdata, flags, reason_code, properties=None):
    print(f"[MQTT] Backend connected: {reason_code}")
    client.subscribe("grid/meter/+/telemetry", qos=1)

def on_message(client, userdata, msg):
    try:
        data = json.loads(msg.payload.decode())
        device = data.get("device_id")
        device_key = data.get("device_key")
        if not device or not authenticate_device(device, device_key):
            if device in status:
                status[device]["status"] = "blocked"
                status[device]["authenticated"] = False
            return
        now = time.time()
        power = float(data.get("power", 0)); voltage = float(data.get("voltage", 230)); frequency = float(data.get("frequency", 50))
        with lock:
            rates[device].append(now)
            while rates[device] and now - rates[device][0] > 1:
                rates[device].popleft()
            rate = len(rates[device])
            history[device].append(power)
            score, _ = score_event(device, power, rate, voltage, frequency)
            if device in quarantined:
                device_status = "quarantined"
            else:
                device_status = "online"
            status[device].update(power=power, voltage=voltage, frequency=frequency,
                                  threat=score, last_seen=datetime.fromtimestamp(now, timezone.utc).isoformat(),
                                  message_rate=rate, authenticated=True, status=device_status)
            conn.execute("INSERT INTO telemetry(device_id,ts,power,voltage,frequency) VALUES(?,?,?,?,?)", (device,now,power,voltage,frequency))
            conn.commit()
        print(f"[TELEMETRY] {device} power={power:.0f}W rate={rate}/s status={device_status}")
    except Exception as e:
        print("[MQTT] message error:", e)

mqttc = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="gridshield-backend")
mqttc.tls_set(
    ca_certs="../certs/ca.crt",
    cert_reqs=ssl.CERT_REQUIRED,
    tls_version=ssl.PROTOCOL_TLS_CLIENT
)

mqttc.on_connect = on_connect
mqttc.on_message = on_message
try:
    mqttc.connect(BROKER, PORT, 60)
    mqttc.loop_start()
except Exception as e:
    print("[MQTT] Backend connection failed:", e)

def offline_monitor():
    while True:
        now = time.time()
        with lock:
            for device, s in status.items():
                if s["last_seen"]:
                    try:
                        last = datetime.fromisoformat(s["last_seen"]).timestamp()
                        if now - last > OFFLINE_AFTER and device not in quarantined:
                            s["status"] = "offline"
                    except Exception:
                        pass
        time.sleep(2)
threading.Thread(target=offline_monitor, daemon=True).start()

@app.get("/api/health")
def health():
    return {"ok": True, "mqtt": mqttc.is_connected(), "authenticated_devices": sum(x["authenticated"] for x in status.values())}

@app.post("/api/login")
def login(body: LoginRequest):
    if body.username != "admin" or body.password != "gridshield":
        raise HTTPException(401, "Invalid credentials")
    token = jwt.encode({"sub":"operator", "exp":datetime.now(timezone.utc)+timedelta(hours=12)}, JWT_SECRET, algorithm=JWT_ALG)
    return {"access_token": token, "token_type":"bearer"}

@app.get("/api/devices")
def devices(_=Depends(require_operator)):
    with lock: return list(status.values())

@app.get("/api/registry")
def registry(_=Depends(require_operator)):
    rows = conn.execute("SELECT device_id, active FROM device_registry ORDER BY device_id").fetchall()
    return [{"device_id": r[0], "active": bool(r[1])} for r in rows]

@app.get("/api/alerts")
def get_alerts(_=Depends(require_operator)):
    with lock: return list(alerts)

@app.get("/api/energy")
def energy(_=Depends(require_operator)):
    with lock:
        total = sum(v["power"] for v in status.values() if v["status"] != "quarantined")
        points = [{"device":d,"power":round(v["power"],1)} for d,v in status.items()]
    return {"total_power": round(total,1), "points": points}

@app.get("/api/forecast")
def forecast(_=Depends(require_operator)):
    vals=[]
    with lock:
        for h in history.values(): vals.extend(list(h))
    current=float(np.mean(vals[-10:])) if vals else 0
    return {"current":round(current,1), "forecast":[round(max(0,current*(1+0.05*i)),1) for i in range(1,4)], "unit":"W", "note":"prototype trend forecast"}

@app.post("/api/simulate/anomaly")
def simulate_anomaly(a: DeviceAction, _=Depends(require_operator)):
    if a.device_id not in DEVICES:
        raise HTTPException(404, "Unknown device")

    info = mqttc.publish(
        f"grid/meter/{a.device_id}/command",
        json.dumps({
            "attack": "energy_anomaly"
        }),
        qos=1
    )

    if info.rc != mqtt.MQTT_ERR_SUCCESS:
        raise HTTPException(
            503,
            f"MQTT publish failed: {info.rc}"
        )

    print(f"[ATTACK] Energy anomaly requested for {a.device_id}")

    return {
        "ok": True,
        "device_id": a.device_id,
        "attack": "energy_anomaly",
        "message": "Energy attack command sent"
    }

@app.post("/api/simulate/flood")
def simulate_flood(a: DeviceAction, _=Depends(require_operator)):
    if a.device_id not in DEVICES:
        raise HTTPException(404, "Unknown device")

    info = mqttc.publish(
        f"grid/meter/{a.device_id}/command",
        json.dumps({
            "attack": "traffic_flood"
        }),
        qos=1
    )

    if info.rc != mqtt.MQTT_ERR_SUCCESS:
        raise HTTPException(
            503,
            f"MQTT publish failed: {info.rc}"
        )

    print(f"[ATTACK] Traffic flood requested for {a.device_id}")

    return {
        "ok": True,
        "device_id": a.device_id,
        "attack": "traffic_flood",
        "message": "Traffic attack command sent"
    }

@app.post("/api/recover")
def recover(a: DeviceAction, _=Depends(require_operator)):
    quarantined.discard(a.device_id)
    with lock:
        if a.device_id in status:
            status[a.device_id]["status"]="online"; status[a.device_id]["threat"]=0
    mqttc.publish(f"grid/meter/{a.device_id}/command", json.dumps({"attack":"normal"}), qos=1)
    return {"ok":True}
