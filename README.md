# SDN Firewall

Programable LAN network with firewall capabilities, built on the SDN paradigm.

## Structure

```
sdn-firewall/
├── server/          # Controller (FastAPI) — control plane
├── client/          # Replicable node (Python) — data plane
├── traffic_gen/     # UDP/TCP traffic generator
├── interface/       # Admin UI (HTML/CSS/JS)
└── data/            # Runtime JSON storage (gitignored)
```

## Setup

```bash
# From sdn-firewall/
python -m venv .venv
.venv\Scripts\activate        # Windows
pip install -r server/requirements.txt
```

Initialize data files (required on first run, do once per machine):
```bash
echo [] > data/rules.json
echo [] > data/nodes.json
echo [] > data/events.json
```

## Running

**Server** (run on the main machine):
```bash
cd server
uvicorn main:app --host 0.0.0.0 --port 5000
```
- API docs: `http://localhost:5000/docs`
- Admin UI: `http://<server-ip>:5000/ui`

**Client** (run on each node — edit `config.json` only):
```bash
cd client
python client.py
```

`config.json` fields:
| Field | Description |
|---|---|
| `node_id` | Unique name for this node |
| `server_url` | Controller IP, e.g. `http://192.168.1.100:5000` |
| `listen_port` | Port to receive traffic on |
| `poll_interval` | Seconds between rule syncs |
| `log_allowed` | `true` to log allowed traffic as events |

**Traffic generator:**
```bash
cd traffic_gen
python generator.py --ip <client-ip> --port 9000 --protocol UDP --count 10
python generator.py --help   # all options
```

## Flow rules

Each rule has: match fields (IP, protocol, port — blank = wildcard `*`), an action, and a priority. Higher priority wins on conflict.

| Action | Effect |
|---|---|
| `allow` | Packet accepted |
| `block` | Packet dropped, event sent to server |
| `report` | Packet accepted, event sent to server |
