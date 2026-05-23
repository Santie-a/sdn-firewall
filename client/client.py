"""
SDN Firewall — Replicable Client Node
Configure via config.json only — no code changes needed between nodes.
Run with:  python client.py
"""
from __future__ import annotations

import json
import logging
import socket
import threading
import time
import uuid
from pathlib import Path

import requests

from rule_engine import evaluate

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

CONFIG_FILE = Path(__file__).parent / "config.json"

_ACTION_LABEL = {"allow": "allowed", "block": "blocked", "report": "reported"}


def _load_config() -> dict:
    with open(CONFIG_FILE, encoding="utf-8") as f:
        return json.load(f)


def _own_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "127.0.0.1"


def _own_mac() -> str:
    """This machine's MAC as lowercase aa:bb:cc:dd:ee:ff."""
    mac = uuid.getnode()
    return ":".join(f"{(mac >> b) & 0xff:02x}" for b in range(40, -1, -8))


_META_MAGIC = b"SDN1"


def _parse_meta(data: bytes) -> tuple[bytes, str | None, int | None]:
    """Extract the SDN metadata header if present.

    Generator traffic is prefixed with  SDN1|<k=v;...>|<payload> . The MAC and
    VLAN are self-reported by the sender (the wire cannot show them to a
    socket-based client). Returns (payload, src_mac, vlan_id); non-instrumented
    traffic yields the whole datagram as payload and both fields None.
    """
    if not data.startswith(_META_MAGIC + b"|"):
        return data, None, None
    parts = data.split(b"|", 2)
    if len(parts) < 3:
        return data, None, None

    src_mac: str | None = None
    vlan_id: int | None = None
    for kv in parts[1].decode(errors="replace").split(";"):
        key, _, value = kv.partition("=")
        if key == "src_mac" and value:
            src_mac = value
        elif key == "vlan" and value.isdigit():
            vlan_id = int(value)
    return parts[2], src_mac, vlan_id


class SDNClient:
    def __init__(self, config: dict) -> None:
        self.node_id      = config["node_id"]
        self.server_url   = config["server_url"].rstrip("/")
        self.listen_port  = config["listen_port"]
        self.poll_interval = config.get("poll_interval", 10)
        self.ip           = _own_ip()
        self.mac          = _own_mac()
        self.log_allowed  = config.get("log_allowed", False)
        self.show_message = config.get("show_message", False)
        self._rules: list[dict] = []
        self._lock = threading.Lock()
        self._registered = False
        # Set to True if the controller returns 403 on register/heartbeat.
        # All background threads (and run()) check this flag and exit.
        self._revoked = False

    # ------------------------------------------------------------------
    # Server communication
    # ------------------------------------------------------------------

    def _post(self, path: str, **kwargs) -> requests.Response | None:
        try:
            r = requests.post(f"{self.server_url}{path}", timeout=5, **kwargs)
            r.raise_for_status()
            return r
        except Exception as e:
            log.warning("POST %s failed: %s", path, e)
            return None

    def _get(self, path: str, **kwargs) -> requests.Response | None:
        try:
            r = requests.get(f"{self.server_url}{path}", timeout=5, **kwargs)
            r.raise_for_status()
            return r
        except Exception as e:
            log.warning("GET %s failed: %s", path, e)
            return None

    def register(self) -> bool:
        """Attempt to register with the controller. Returns True on success.
        On 403 (revoked), sets self._revoked and gives up permanently."""
        try:
            r = requests.post(
                f"{self.server_url}/nodes/register",
                json={"node_id": self.node_id, "ip": self.ip, "listen_port": self.listen_port},
                timeout=5,
            )
            if r.status_code == 403:
                log.error("Node revoked by controller — shutting down")
                self._revoked = True
                return False
            r.raise_for_status()
        except requests.RequestException as e:
            log.warning("POST /nodes/register failed: %s", e)
            self._registered = False
            return False

        if not self._registered:
            log.info("Registered as '%s' (%s)", self.node_id, self.ip)
        self._registered = True
        return True

    def _poll_rules(self) -> None:
        while not self._revoked:
            r = self._get("/rules", params={"enabled_only": True})
            if r:
                with self._lock:
                    self._rules = r.json()
                log.info("Rules synced: %d active", len(self._rules))
            time.sleep(self.poll_interval)

    def _heartbeat(self) -> None:
        while not self._revoked:
            if not self._registered:
                self.register()
            else:
                try:
                    r = requests.post(
                        f"{self.server_url}/nodes/{self.node_id}/heartbeat",
                        timeout=5,
                    )
                    if r.status_code == 403:
                        log.error("Node revoked by controller — shutting down")
                        self._revoked = True
                        return
                    if r.status_code == 404:
                        log.info("Server no longer knows this node — re-registering")
                        self._registered = False
                        continue
                    r.raise_for_status()
                except Exception as e:
                    log.warning("Heartbeat failed: %s", e)
            time.sleep(self.poll_interval)

    def _report_event(self, rule_id: str | None, action: str, packet: dict) -> None:
        self._post(
            "/events",
            json={
                "node_id": self.node_id,
                "rule_id": rule_id,
                "action":  _ACTION_LABEL[action],
                "packet":  packet,
            },
        )

    def _record_hit(self, rule_id: str, byte_count: int) -> None:
        try:
            requests.post(
                f"{self.server_url}/rules/{rule_id}/hit",
                params={"byte_count": byte_count},
                timeout=3,
            )
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Packet handling
    # ------------------------------------------------------------------

    def _handle(self, data: bytes, src_ip: str, src_port: int, protocol: str) -> str:
        """Evaluate packet against rules. Returns the action taken."""
        # Generator traffic carries a self-reported MAC/VLAN header; strip it
        # so 'size' reflects the real payload, not the instrumentation.
        payload, ann_mac, ann_vlan = _parse_meta(data)

        # Decode + truncate once so the same preview goes to both the console
        # log and the controller's Event Log. Bound at 80 chars to keep
        # events.json small; attacker-controlled, so the UI must esc() it.
        text = payload.decode("utf-8", errors="replace") if payload else ""
        message = (text[:80] + "…") if len(text) > 80 else text

        packet = {
            "src_ip":   src_ip,
            "dst_ip":   self.ip,
            "protocol": protocol,
            "src_port": src_port,
            "dst_port": self.listen_port,
            "size":     len(payload),
            "message":  message or None,
            # Observed from the socket.
            "in_port":  str(self.listen_port),
            "eth_type": "IPv4",
            # src_mac / vlan_id are self-reported by the generator; dst_mac is
            # this node's own MAC. None when traffic is not instrumented.
            "src_mac":  ann_mac,
            "dst_mac":  self.mac,
            "vlan_id":  ann_vlan,
        }

        with self._lock:
            rules_snapshot = list(self._rules)

        action, rule_id = evaluate(packet, rules_snapshot)

        msg = '  msg="%s"' % message if self.show_message and message else ""

        log.info(
            "[%s] %s:%s -> %s  (rule=%s)%s",
            protocol, src_ip, src_port, action.upper(), rule_id or "default", msg,
        )

        if rule_id:
            threading.Thread(
                target=self._record_hit, args=(rule_id, len(data)), daemon=True
            ).start()

        if action in ("block", "report") or (action == "allow" and self.log_allowed):
            threading.Thread(
                target=self._report_event, args=(rule_id, action, packet), daemon=True
            ).start()

        return action

    # ------------------------------------------------------------------
    # Socket listeners
    # ------------------------------------------------------------------

    def _listen_udp(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", self.listen_port))
        log.info("UDP listener ready on port %d", self.listen_port)
        while True:
            try:
                data, (src_ip, src_port) = sock.recvfrom(65535)
                self._handle(data, src_ip, src_port, "UDP")
            except Exception as e:
                log.error("UDP error: %s", e)

    def _listen_tcp(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", self.listen_port))
        sock.listen(16)
        log.info("TCP listener ready on port %d", self.listen_port)
        while True:
            try:
                conn, (src_ip, src_port) = sock.accept()
                threading.Thread(
                    target=self._handle_tcp_conn,
                    args=(conn, src_ip, src_port),
                    daemon=True,
                ).start()
            except Exception as e:
                log.error("TCP accept error: %s", e)

    def _handle_tcp_conn(self, conn: socket.socket, src_ip: str, src_port: int) -> None:
        try:
            data = conn.recv(4096) or b""
            action = self._handle(data, src_ip, src_port, "TCP")
            if action == "block":
                conn.close()
                return
            conn.sendall(b"OK\n")
        except Exception as e:
            log.error("TCP conn error: %s", e)
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def run(self) -> None:
        # Try once on startup; heartbeat thread retries indefinitely on failure.
        # If the controller refuses (403 revoked), exit immediately so the
        # operator sees the rejection rather than a silent retry loop.
        self.register()
        if self._revoked:
            return

        for target in (self._poll_rules, self._heartbeat, self._listen_udp, self._listen_tcp):
            threading.Thread(target=target, daemon=True).start()

        log.info("SDN client running. Press Ctrl+C to stop.")
        try:
            while not self._revoked:
                time.sleep(1)
            log.info("Exiting: revoked by controller.")
        except KeyboardInterrupt:
            log.info("Shutting down.")


if __name__ == "__main__":
    client = SDNClient(_load_config())
    client.run()
