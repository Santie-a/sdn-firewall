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


class SDNClient:
    def __init__(self, config: dict) -> None:
        self.node_id      = config["node_id"]
        self.server_url   = config["server_url"].rstrip("/")
        self.listen_port  = config["listen_port"]
        self.poll_interval = config.get("poll_interval", 10)
        self.ip           = _own_ip()
        self.log_allowed  = config.get("log_allowed", False)
        self._rules: list[dict] = []
        self._lock = threading.Lock()
        self._registered = False

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
        """Attempt to register with the controller. Returns True on success."""
        r = self._post(
            "/nodes/register",
            json={"node_id": self.node_id, "ip": self.ip, "listen_port": self.listen_port},
        )
        if r:
            if not self._registered:
                log.info("Registered as '%s' (%s)", self.node_id, self.ip)
            self._registered = True
            return True
        self._registered = False
        return False

    def _poll_rules(self) -> None:
        while True:
            r = self._get("/rules", params={"enabled_only": True})
            if r:
                with self._lock:
                    self._rules = r.json()
                log.info("Rules synced: %d active", len(self._rules))
            time.sleep(self.poll_interval)

    def _heartbeat(self) -> None:
        while True:
            if not self._registered:
                self.register()
            else:
                try:
                    r = requests.post(
                        f"{self.server_url}/nodes/{self.node_id}/heartbeat",
                        timeout=5,
                    )
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
        packet = {
            "src_ip":   src_ip,
            "dst_ip":   self.ip,
            "protocol": protocol,
            "src_port": src_port,
            "dst_port": self.listen_port,
            "size":     len(data),
        }

        with self._lock:
            rules_snapshot = list(self._rules)

        action, rule_id = evaluate(packet, rules_snapshot)

        log.info(
            "[%s] %s:%s -> %s  (rule=%s)",
            protocol, src_ip, src_port, action.upper(), rule_id or "default",
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
        # Try once on startup; heartbeat thread retries indefinitely on failure
        self.register()

        for target in (self._poll_rules, self._heartbeat, self._listen_udp, self._listen_tcp):
            threading.Thread(target=target, daemon=True).start()

        log.info("SDN client running. Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            log.info("Shutting down.")


if __name__ == "__main__":
    client = SDNClient(_load_config())
    client.run()
