# Controller — Server Guide

The controller is the **control plane**: it registers nodes, stores flow rules and distributes them, collects events from clients, and serves the admin UI. Run it once, on the main machine of the LAN.

> Built with FastAPI. See [README.md](README.md) for the overall architecture.

## Prerequisites

From `sdn-firewall/`, with the virtual environment created (see [README quick start](README.md#quick-start)):

```powershell
pip install -r server/requirements.txt
```

Dependencies: `fastapi`, `uvicorn[standard]`, `pydantic`. (The server uses no HTTP client — `requests` is a client-side dependency.)

The `data/` directory (runtime JSON storage) is **created automatically** the first time the server imports `storage.py` — no manual setup. The `rules.json`, `nodes.json`, and `events.json` files are likewise created on first write.

> **Do not** pre-create the JSON files with `echo [] > data/rules.json`. In Windows PowerShell, `>` writes **UTF-16** with a BOM, but the server reads them as **UTF-8** — that crashes the JSON parser on startup. If you want to reset state, delete the files and let the server recreate them, or write them with `Set-Content -Encoding utf8`.

## Running

```powershell
cd server
uvicorn main:app --host 0.0.0.0 --port 5000
```

`--host 0.0.0.0` is required so other LAN machines can reach the controller. Once running:

| Resource | URL |
|---|---|
| Admin UI | `http://<server-ip>:5000/ui` |
| Interactive API docs | `http://<server-ip>:5000/docs` |
| Health check | `http://<server-ip>:5000/health` |

Find `<server-ip>` with `ipconfig`. Clients use this address in their `config.json` `server_url`.

## Recommended: default-deny posture

A firewall should **deny by default** — drop anything not explicitly permitted. The rule engine's built-in fallback is `allow` (fail-open), so for correct firewall behavior, create a **catch-all deny rule** as the first rule:

| Field | Value |
|---|---|
| Name | `Default deny (catch-all)` |
| Priority | `0` — the lowest; every real rule outranks it |
| Action | `Block` |
| Match fields | *all left blank* — wildcards every packet |

**Via the Admin UI:** open **New Flow Rule**, set the name, priority `0`, action **Block**, leave every match field empty, and submit.

**Via the API** (PowerShell):

```powershell
Invoke-RestMethod -Uri http://localhost:5000/rules -Method Post -ContentType 'application/json' `
  -Body '{"name":"Default deny (catch-all)","priority":0,"action":"block","enabled":true,"match":{}}'
```

Because it is an ordinary rule, it can be disabled or deleted at any time — e.g. if you need to demonstrate default-allow behavior. Any higher-priority `allow` rule you add permits its traffic above this floor.

## REST API reference

All endpoints accept/return JSON. CORS is open (`*`) so the UI can be served from anywhere.

### Nodes

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/nodes/register` | Register a node, or refresh an existing one. Body: `{node_id, ip, listen_port}`. **403** if the node was previously revoked |
| `GET` | `/nodes` | List all nodes. `?status=active\|inactive\|revoked` to filter |
| `POST` | `/nodes/{node_id}/heartbeat` | Keepalive — refreshes `last_seen`, marks node active. **403** if revoked |
| `POST` | `/nodes/{node_id}/revoke` | Mark the node as revoked. Future register/heartbeat is refused with 403. Idempotent |
| `POST` | `/nodes/{node_id}/admit` | Lift a revocation — node returns to `inactive` until it next heartbeats. **409** if not currently revoked |
| `DELETE` | `/nodes/{node_id}` | **Forget** the node — wipes the record. A still-running client may rejoin freely. Use `/revoke` instead to block rejoin |
| `DELETE` | `/nodes` | Bulk forget. `?status=inactive` clears stale nodes; no filter clears all *non-revoked* nodes (tombstones survive) |

Nodes that miss heartbeats for **10 s** are automatically marked `inactive` by a background task (checked every 2 s). **Revoked** is a sticky admin state — it is never demoted by the stale loop.

#### Admission control (revoke vs. forget)

The controller distinguishes two ways to remove a node, matching the SDN convention that the controller — not the node — owns fabric membership:

- **Forget** (`DELETE /nodes/{id}`): clean decommission. The record is deleted. A node process that is still running will simply re-register on its next heartbeat and reappear in the registry. Use this for stale rows you want to tidy up.
- **Revoke** (`POST /nodes/{id}/revoke`): admin ejection. The record is kept as a tombstone with `status="revoked"` and a `revoked_at` timestamp. Subsequent `/register` and `/heartbeat` calls from that `node_id` return **403**, and the client exits cleanly on its end. Use **Admit** (`POST /nodes/{id}/admit`) to allow it back; the node operator must restart the client process for it to rejoin.

Identity is keyed on `node_id` only. This is consistent with the rest of the system's trust model (self-reported MAC/VLAN headers) — it is an admin convenience, not a security boundary. A determined operator on a revoked node can rename their `node_id` in `config.json` and reconnect.

### Rules

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/rules` | List rules, sorted by priority (desc). `?enabled_only=true` returns only enabled — this is what clients poll |
| `POST` | `/rules` | Create a rule. Body: `{name, priority, action, enabled, match}` |
| `GET` | `/rules/{rule_id}` | Fetch one rule |
| `DELETE` | `/rules/{rule_id}` | Delete a rule |
| `PATCH` | `/rules/{rule_id}/toggle` | Flip `enabled` on/off |
| `POST` | `/rules/{rule_id}/hit` | Increment match counters. `?byte_count=N` — called by clients |

### Events

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/events` | Record an event. Body: `{node_id, rule_id, action, packet}` — posted by clients |
| `GET` | `/events` | List events. `?node_id=`, `?action=`, `?limit=` (1–1000, default 100) |
| `DELETE` | `/events` | Clear the event log |

### Meta

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | `{status, rules, nodes, events}` counts |

## The flow-rule model

A rule (`server/models.py` → `FlowRule`):

| Field | Notes |
|---|---|
| `id` | UUID, generated by the server |
| `name` | Human label |
| `priority` | `0`–`65535`; higher is evaluated first |
| `match` | Match fields — all optional, blank = wildcard |
| `action` | `allow` \| `block` \| `report` |
| `enabled` | Disabled rules are skipped and not sent to clients |
| `created_at` | ISO 8601 timestamp |
| `stats` | `{packet_count, byte_count, last_match}` — updated via `/rules/{id}/hit` |

Match fields: `src_ip`, `dst_ip` (CIDR allowed), `protocol` (`TCP`/`UDP`), `src_port`, `dst_port`, `in_port`, `src_mac`, `dst_mac`, `eth_type`, `vlan_id`, `vlan_priority`, `tos`. How clients enforce each is covered in [CLIENT.md](CLIENT.md#match-field-enforcement).

## Admin UI

Served at `/ui`. Polls the API every 5 s. Four tabs:

- **Flow Table** — create rules (form on the left), see them with live hit/byte counters, a natural-language interpretation per rule, and enable/disable or delete. Scenario presets bulk-load common rule sets (incl. a priority-conflict set).
- **Nodes** — registered nodes with status and last-seen; clear inactive nodes.
- **Event Log** — every allowed/blocked/reported event, filterable by action.
- **Topology** — radial graph of the controller and its nodes, with a pulse on each new event.

The dashboard strip shows live counts of allowed / blocked / reported traffic, active nodes, and active rules.

## Data persistence

State lives in `data/` as three JSON files (`rules.json`, `nodes.json`, `events.json`), written in UTF-8. They are gitignored (runtime state, not source). In-memory state is loaded on startup and flushed back on change and on shutdown.
