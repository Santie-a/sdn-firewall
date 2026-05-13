"""
Rule matching engine — runs on each client node.
Evaluates a packet dict against a list of rule dicts (from the server API).
Rules are sorted by priority descending; first match wins.
Returns (action, rule_id). Default action when nothing matches: 'allow'.
"""
from __future__ import annotations
import ipaddress


def _match_ip(rule_ip: str | None, packet_ip: str) -> bool:
    if rule_ip is None:
        return True
    try:
        return ipaddress.ip_address(packet_ip) in ipaddress.ip_network(rule_ip, strict=False)
    except ValueError:
        return rule_ip == packet_ip


def _match_port(rule_port: int | None, packet_port: int | None) -> bool:
    if rule_port is None:
        return True
    return rule_port == packet_port


def _match_proto(rule_proto: str | None, packet_proto: str) -> bool:
    if rule_proto is None:
        return True
    return rule_proto.upper() == packet_proto.upper()


def evaluate(packet: dict, rules: list[dict]) -> tuple[str, str | None]:
    """
    packet keys: src_ip, dst_ip, protocol, src_port, dst_port
    Returns (action, rule_id) where action is 'allow' | 'block' | 'report'.
    """
    sorted_rules = sorted(
        (r for r in rules if r.get("enabled", True)),
        key=lambda r: r["priority"],
        reverse=True,
    )

    for rule in sorted_rules:
        m = rule.get("match", {})
        if (
            _match_ip(m.get("src_ip"),    packet["src_ip"])
            and _match_ip(m.get("dst_ip"),  packet["dst_ip"])
            and _match_proto(m.get("protocol"), packet["protocol"])
            and _match_port(m.get("src_port"), packet.get("src_port"))
            and _match_port(m.get("dst_port"), packet.get("dst_port"))
        ):
            return rule["action"], rule["id"]

    return "allow", None
