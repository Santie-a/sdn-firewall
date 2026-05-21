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


def _match_exact(rule_value: object, packet_value: object) -> bool:
    """Generic exact match for fields without special semantics.

    A None rule value is a wildcard. When a rule constrains a field the
    socket-based client cannot observe (VLAN priority, ToS), packet_value is
    None, so the comparison fails and the rule correctly does not match
    instead of being silently ignored.
    """
    if rule_value is None:
        return True
    return rule_value == packet_value


def _norm_mac(mac: str) -> str:
    """Normalise a MAC for comparison: lowercase, ':' separators, no spaces."""
    return mac.strip().lower().replace("-", ":")


def _match_mac(rule_mac: str | None, packet_mac: str | None) -> bool:
    """Case-insensitive MAC match, tolerant of ':' or '-' separators.

    A None rule value is a wildcard. If the rule constrains a MAC but the
    packet carries none (non-instrumented traffic), the rule does not match.
    """
    if rule_mac is None:
        return True
    if packet_mac is None:
        return False
    return _norm_mac(rule_mac) == _norm_mac(packet_mac)


def evaluate(packet: dict, rules: list[dict]) -> tuple[str, str | None]:
    """
    packet keys: src_ip, dst_ip, protocol, src_port, dst_port,
                 in_port, eth_type, src_mac, dst_mac, vlan_id
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
            and _match_exact(m.get("in_port"),       packet.get("in_port"))
            and _match_exact(m.get("eth_type"),      packet.get("eth_type"))
            and _match_mac(m.get("src_mac"),         packet.get("src_mac"))
            and _match_mac(m.get("dst_mac"),         packet.get("dst_mac"))
            and _match_exact(m.get("vlan_id"),       packet.get("vlan_id"))
            and _match_exact(m.get("vlan_priority"), packet.get("vlan_priority"))
            and _match_exact(m.get("tos"),           packet.get("tos"))
        ):
            return rule["action"], rule["id"]

    return "allow", None
