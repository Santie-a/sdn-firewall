from __future__ import annotations
from typing import Optional, Literal
from datetime import datetime, timezone
from pydantic import BaseModel, Field
import uuid


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _uuid() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Match fields
# ---------------------------------------------------------------------------

class MatchFields(BaseModel):
    src_ip:        Optional[str] = None
    dst_ip:        Optional[str] = None
    protocol:      Optional[Literal["TCP", "UDP", "ICMP"]] = None
    src_port:      Optional[int] = None
    dst_port:      Optional[int] = None
    # extended / optional
    in_port:       Optional[str] = None
    src_mac:       Optional[str] = None
    dst_mac:       Optional[str] = None
    eth_type:      Optional[str] = None
    vlan_id:       Optional[int] = None
    vlan_priority: Optional[int] = None
    tos:           Optional[str] = None


# ---------------------------------------------------------------------------
# Flow rule
# ---------------------------------------------------------------------------

class RuleStats(BaseModel):
    packet_count: int = 0
    byte_count:   int = 0
    last_match:   Optional[str] = None


class FlowRule(BaseModel):
    id:         str = Field(default_factory=_uuid)
    name:       str
    priority:   int = Field(ge=0, le=65535)
    match:      MatchFields
    action:     Literal["allow", "block", "report"]
    enabled:    bool = True
    created_at: str  = Field(default_factory=_now)
    stats:      RuleStats = Field(default_factory=RuleStats)


class FlowRuleCreate(BaseModel):
    """Payload accepted when creating a rule (no id/stats/created_at needed)."""
    name:     str
    priority: int = Field(ge=0, le=65535)
    match:    MatchFields
    action:   Literal["allow", "block", "report"]
    enabled:  bool = True


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------

class Node(BaseModel):
    node_id:       str
    ip:            str
    listen_port:   int
    status:        Literal["active", "inactive"] = "active"
    registered_at: str = Field(default_factory=_now)
    last_seen:     str  = Field(default_factory=_now)


class NodeRegister(BaseModel):
    """Payload sent by a client when registering."""
    node_id:     str
    ip:          str
    listen_port: int


# ---------------------------------------------------------------------------
# Event
# ---------------------------------------------------------------------------

class PacketInfo(BaseModel):
    src_ip:   str
    dst_ip:   str
    protocol: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    size:     int = 0


class Event(BaseModel):
    event_id:  str  = Field(default_factory=_uuid)
    timestamp: str  = Field(default_factory=_now)
    node_id:   str
    rule_id:   Optional[str] = None
    action:    Literal["allowed", "blocked", "reported"]
    packet:    PacketInfo


class EventCreate(BaseModel):
    """Payload sent by a client when reporting an event."""
    node_id:  str
    rule_id:  Optional[str] = None
    action:   Literal["allowed", "blocked", "reported"]
    packet:   PacketInfo
