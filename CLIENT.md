# Client Guide

The client is the **data plane**: a replicable node that registers with the controller, pulls active rules, listens for UDP/TCP traffic, evaluates each packet, and applies an action. The same code runs on every node - only `config.json` changes.

> See [README.md](README.md) for the overall architecture.

## Prerequisites

Python 3 plus the `requests` library (the only dependency, listed in `client/requirements.txt`). If a client runs on the same machine where the project's virtual environment is set up, `requests` is already installed. To deploy a client on a **separate** machine, just copy the `client/` folder and install it:

```powershell
pip install -r requirements.txt
```

Everything else the client uses (`socket`, `threading`, `json`, `uuid`) is in the Python standard library.

## Configuration

All per-node settings live in `client/config.json`.

```json
{
  "node_id":       "node-9002",
  "server_url":    "http://127.0.0.1:5000",
  "listen_port":   9000,
  "poll_interval": 5,
  "log_allowed":   true,
  "show_message":  true
}
```

| Field | Description |
|---|---|
| `node_id` | Unique name for this node (e.g. `node-lab-1`). Must differ on every node. |
| `server_url` | Controller address, e.g. `http://192.168.1.100:5000` (get the IP with `ipconfig` on the server). |
| `listen_port` | UDP and TCP port this node receives traffic on. |
| `poll_interval` | Seconds between rule syncs and heartbeats. |
| `log_allowed` | `true` also logs *allowed* traffic as events (audit trail); `false` logs only block/report. |
| `show_message` | `true` echoes the received payload text on each packet decision in the client's console log. The same text (truncated to 80 chars) is always reported to the controller and shown in the UI's Event Log, regardless of this flag. |

The node's IP and MAC are detected automatically — they are not configured.

## Running

```powershell
cd client
python client.py
```

The client registers with the controller, then runs until `Ctrl+C`. On startup it logs its UDP and TCP listeners; thereafter it logs every packet decision.

If the controller **revokes** the node (admin action from the UI or `POST /nodes/{id}/revoke`), the client receives a `403` on its next register or heartbeat, logs `Node revoked by controller — shutting down`, and exits. To rejoin, the controller must **Admit** the node *and* the operator must restart `python client.py`. Until both happen, the listeners are down and the cached rule set is no longer being refreshed, so the node enforces nothing.

## Replicability

To run N nodes (the spec asks for 3–4):

1. Copy the `client/` folder to each machine — or run several copies on one machine.
2. In each copy's `config.json`, set a **unique** `node_id` and a **unique** `listen_port` (if on the same host), and point `server_url` at the controller.
3. Run `python client.py`.

No code edits, ever. The controller shows each node in the **Nodes** tab and the **Topology** graph.

## What the client does

After registering, the client runs four background threads:

- **Rule sync** — every `poll_interval`, `GET /rules?enabled_only=true`; the rule set is cached locally.
- **Heartbeat** — every `poll_interval`, `POST /nodes/{id}/heartbeat`; re-registers automatically if the controller has forgotten it.
- **UDP listener** — receives datagrams on `listen_port`.
- **TCP listener** — accepts connections on `listen_port`, each handled in its own thread.

## Rule evaluation

The matching engine (`client/rule_engine.py` → `evaluate()`):

1. Considers only **enabled** rules.
2. Sorts them by **priority, descending**.
3. Returns the **first rule that matches** the packet — higher priority therefore wins a conflict.
4. If **no rule matches**, the default is `allow` (see the default-deny note below).

A rule matches only when **every field it specifies** matches the packet; blank fields are wildcards. IP fields accept a single address or a **CIDR** range (e.g. `192.168.1.0/24`).

> **Default policy.** The built-in no-match fallback is `allow` (fail-open). For correct firewall behavior, add a catch-all `block` rule on the controller — see [SERVER.md](SERVER.md#recommended-default-deny-posture).

## Match-field enforcement

The engine evaluates all 12 match fields, but they differ in *what the client can actually observe*:

- **Observed from the socket** — the 5 core fields (`src_ip`, `dst_ip`, `protocol`, `src_port`, `dst_port`), plus `in_port` (the client's listening port) and `eth_type` (always `IPv4` for the IP-socket data plane). Enforced for **all** traffic.
- **Self-reported by the generator** — `src_mac` and `vlan_id`. The traffic generator prepends a header to each packet (`SDN1|src_mac=…;vlan=…|<payload>`); the client parses it and matches against it. `dst_mac` is the receiving node's own MAC, auto-detected. This is **self-reported and trustless** — only the project's generator carries the header, and a sender could announce any value. It demonstrates matching mechanics; it is **not** a security control. (The OS strips real link-layer headers before a socket-based client can see them.) MAC comparison is case-insensitive and accepts `:` or `-` separators.
- **Not available** — `vlan_priority` and `tos`. There is no socket-based source for these, so a rule constraining one of them will never match — it is *not* silently ignored.

## How actions are applied

| Action | UDP | TCP | Reported to controller? |
|---|---|---|---|
| `allow` | Packet accepted | Connection accepted, replies `OK` | Only if `log_allowed` is `true` |
| `block` | Packet silently dropped | Connection closed, no reply | Yes — as a `blocked` event |
| `report` | Packet accepted | Connection accepted, replies `OK` | Yes — as a `reported` event |

On **every rule match** the client also calls `POST /rules/{id}/hit`, so the rule's packet/byte counters stay current in the UI. Each event carries the full packet summary (IPs, protocol, ports, size) so the controller has evidence of the decision.
