# GridShield MVP v2.1

## Fix in this version
Each smart meter now has its **own MQTT client ID and connection**. This avoids a common MQTT simulator problem where one shared client can make the dashboard appear to receive only one meter reliably.

## Run
1. Terminal 1: `mosquitto -c mosquitto.conf -v`
2. Terminal 2: `cd backend && python -m venv .venv && .venv\\Scripts\\activate && pip install -r requirements.txt && uvicorn main:app --reload --port 8000`
3. Terminal 3: `cd simulator && python -m venv .venv && .venv\\Scripts\\activate && pip install -r requirements.txt && python meter.py`
4. Terminal 4: `cd frontend && npm install && npm run dev`

Open http://localhost:5173 and login with `admin` / `gridshield`.

The simulator terminal should print five separate connection lines, one for each meter.
