# Traffic Generator Guide

The generator produces configurable UDP or TCP traffic aimed at a client node, so you can verify experimentally that rules really affect traffic — the spec's required proof that the firewall works.

> See [README.md](README.md) for the overall architecture.

## Prerequisites

Python 3 only — the generator uses just the standard library (`socket`, `argparse`, `uuid`). No `pip install` needed. It can run from any machine on the LAN.

## Usage

```powershell
cd traffic_gen
python generator.py --ip <client-ip> --port <listen-port> [options]
```

`--ip` and `--port` must point at a client node's address and its `listen_port`.

| Flag | Default | Description |
|---|---|---|
| `--ip` | *(required)* | Destination IP — the target client node |
| `--port` | *(required)* | Destination port — the node's `listen_port` |
| `--protocol` | `UDP` | `UDP` or `TCP` |
| `--count` | `10` | Number of packets to send; `0` = infinite (Ctrl+C to stop) |
| `--interval` | `1.0` | Seconds between sends |
| `--message` | `SDN-TEST` | Payload string |
| `--src-port` | *(auto)* | Bind to a specific source port before sending (UDP only) |
| `--src-mac` | *(this machine's MAC)* | Source MAC to announce in the header |
| `--vlan` | *(none)* | VLAN ID to announce in the header |

The generator prints the announced MAC and VLAN on startup, then one line per packet sent.

> The receiving client can also echo the `--message` text in its own console log — enable `show_message` in the client's `config.json` (see [CLIENT.md](CLIENT.md#configuration)).

## Examples

```powershell
# 10 UDP packets to port 9000, one every 0.5 s
python generator.py --ip 192.168.1.101 --port 9000 --protocol UDP --count 10 --interval 0.5

# 5 TCP connections with a custom message
python generator.py --ip 192.168.1.101 --port 9000 --protocol TCP --count 5 --message "hello"

# Continuous UDP flood (Ctrl+C to stop)
python generator.py --ip 192.168.1.101 --port 9000 --protocol UDP --count 0 --interval 0.1

# Bind a specific source port (UDP only) — useful for src_port rules
python generator.py --ip 192.168.1.101 --port 9000 --protocol UDP --src-port 4444

# Announce a VLAN / a specific source MAC — for VLAN and MAC rule tests
python generator.py --ip 192.168.1.101 --port 9000 --protocol UDP --vlan 20
python generator.py --ip 192.168.1.101 --port 9000 --protocol UDP --src-mac aa:bb:cc:dd:ee:ff
```

## The metadata header

Every packet's payload is prefixed with a small self-reported header:

```
SDN1|src_mac=<mac>;vlan=<id>|<your --message>
```

`src_mac` is always present (this machine's MAC, or `--src-mac`); `vlan` appears only when `--vlan` is given. The receiving client strips this header before evaluating, and matches `src_mac` / `vlan_id` rules against it.

This exists because a socket-based client cannot observe link-layer fields (MAC, VLAN) — the OS strips them. The header lets MAC/VLAN rules be **demonstrated**, but it is **self-reported and trustless**: only this generator emits it, and any value can be announced. It shows matching mechanics, not real enforcement. See [CLIENT.md](CLIENT.md#match-field-enforcement).

## Testing rules

Point the generator at a node whose `listen_port` has a rule, and observe:

| Rule action | What you see |
|---|---|
| `allow` | UDP: no feedback (fire-and-forget). TCP: the generator prints `response='OK'`. |
| `block` | UDP: silently dropped — no feedback. TCP: connection closed, the generator prints an empty/failed response. |
| `report` | Same as `allow` on the wire — plus an event appears in the controller's Event Log. |

In every case the authoritative evidence is the controller's **Event Log** and the rule's **hit counters** in the UI. The [test suite](README.md#test-suite) in the README lists concrete scenarios (T1–T12) with the exact rule and command for each.
