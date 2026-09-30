import json, random, threading, time
import ssl
import paho.mqtt.client as mqtt

BROKER = "127.0.0.1"
PORT = 8883
DEVICES = [f"METER-{i:03d}" for i in range(1, 6)]
DEVICE_KEYS = {d: f"GRID-{d}-KEY" for d in DEVICES}
MODES = {d: "normal" for d in DEVICES}
CLIENTS = {}
LOCK = threading.Lock()

def make_client(device):
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"gridshield-{device}", clean_session=True)

    client.tls_set(
    ca_certs="../certs/ca.crt",
    cert_reqs=ssl.CERT_REQUIRED,
    tls_version=ssl.PROTOCOL_TLS_CLIENT
)

    def on_connect(c, userdata, flags, reason_code, properties=None):
        print(f"[{device}] MQTT connected: {reason_code}")
        c.subscribe(f"grid/meter/{device}/command", qos=1)
        c.publish(f"grid/meter/{device}/status", json.dumps({"device_id": device, "status": "online"}), qos=1)

    def on_message(c, userdata, msg):
        try:
            payload = json.loads(msg.payload.decode())
            mode = payload.get("attack", "normal")
            if mode not in {"normal", "energy_anomaly", "traffic_flood"}:
                mode = "normal"
            with LOCK:
                MODES[device] = mode
            print(f"[{device}] mode -> {mode}")
        except Exception as e:
            print(f"[{device}] command error: {e}")

    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(BROKER, PORT, 60)
    client.loop_start()
    return client

def run_device(device):
    client = CLIENTS[device]
    while True:
        with LOCK:
            mode = MODES[device]
        if mode == "traffic_flood":
            count = 40
        else:
            count = 1
        for _ in range(count):
            power = random.uniform(500, 1500)
            if mode == "energy_anomaly":
                power = random.uniform(9000, 15000)
            payload = {
                "device_id": device,
                "device_key": DEVICE_KEYS[device],
                "power": power,
                "voltage": 230 + random.uniform(-2, 2),
                "frequency": 50 + random.uniform(-0.05, 0.05),
                "timestamp": time.time(),
            }
            info = client.publish(f"grid/meter/{device}/telemetry", json.dumps(payload), qos=1)
            if info.rc != mqtt.MQTT_ERR_SUCCESS:
                print(f"[{device}] publish failed rc={info.rc}")
        time.sleep(1)

print("Starting 5 independent smart-meter MQTT clients...")
for device in DEVICES:
    try:
        CLIENTS[device] = make_client(device)
    except Exception as e:
        print(f"[{device}] CONNECTION FAILED: {e}")

for device in DEVICES:
    if device in CLIENTS:
        threading.Thread(target=run_device, args=(device,), daemon=True).start()

print("Devices:", ", ".join(DEVICES))
print("Each meter now has its own MQTT client ID. Keep this terminal open.")

while True:
    time.sleep(60)
