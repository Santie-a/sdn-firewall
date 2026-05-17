"""
SDN Firewall — Controller Server
Run with:  uvicorn main:app --host 0.0.0.0 --port 5000 --reload
Docs at:   http://localhost:5000/docs
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pathlib import Path

import storage
from models import (
    FlowRule, FlowRuleCreate,
    Node, NodeRegister,
    Event, EventCreate,
)

# ---------------------------------------------------------------------------
# In-memory state (loaded from JSON on startup)
# ---------------------------------------------------------------------------

rules:  list[FlowRule] = []
nodes:  list[Node]     = []
events: list[Event]    = []

# Stale detection
STALE_THRESHOLD_SECS = 10
STALE_CHECK_INTERVAL = 2


async def _stale_node_loop() -> None:
    """Periodically mark nodes as inactive when last_seen is older than the threshold."""
    while True:
        try:
            await asyncio.sleep(STALE_CHECK_INTERVAL)
            now = datetime.now(timezone.utc)
            changed = False
            for node in nodes:
                last = datetime.fromisoformat(node.last_seen)
                age  = (now - last).total_seconds()
                new_status = "inactive" if age > STALE_THRESHOLD_SECS else "active"
                if node.status != new_status:
                    node.status = new_status
                    changed = True
            if changed:
                storage.save_nodes(nodes)
        except asyncio.CancelledError:
            break
        except Exception:
            # Never let an exception kill the background loop
            await asyncio.sleep(STALE_CHECK_INTERVAL)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global rules, nodes, events
    rules  = storage.load_rules()
    nodes  = storage.load_nodes()
    events = storage.load_events()

    stale_task = asyncio.create_task(_stale_node_loop())
    yield
    stale_task.cancel()

    storage.save_rules(rules)
    storage.save_nodes(nodes)
    storage.save_events(events)


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="SDN Firewall Controller",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve the HTML interface at /ui
_interface_dir = Path(__file__).parent.parent / "interface"
if _interface_dir.exists():
    app.mount("/ui", StaticFiles(directory=str(_interface_dir), html=True), name="ui")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------

@app.post("/nodes/register", response_model=Node, tags=["nodes"])
def register_node(payload: NodeRegister, bg: BackgroundTasks):
    existing = next((n for n in nodes if n.node_id == payload.node_id), None)
    if existing:
        existing.ip          = payload.ip
        existing.listen_port = payload.listen_port
        existing.status      = "active"
        existing.last_seen   = _now()
        bg.add_task(storage.save_nodes, nodes)
        return existing

    node = Node(**payload.model_dump())
    nodes.append(node)
    bg.add_task(storage.save_nodes, nodes)
    return node


@app.get("/nodes", response_model=list[Node], tags=["nodes"])
def list_nodes(status: Optional[str] = Query(None, description="Filter by status: active | inactive")):
    if status:
        return [n for n in nodes if n.status == status]
    return nodes


@app.post("/nodes/{node_id}/heartbeat", tags=["nodes"])
def heartbeat(node_id: str, bg: BackgroundTasks):
    node = next((n for n in nodes if n.node_id == node_id), None)
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")
    node.last_seen = _now()
    node.status    = "active"
    bg.add_task(storage.save_nodes, nodes)
    return {"ok": True, "last_seen": node.last_seen}


@app.delete("/nodes/{node_id}", status_code=204, tags=["nodes"])
def delete_node(node_id: str, bg: BackgroundTasks):
    global nodes
    node = next((n for n in nodes if n.node_id == node_id), None)
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")
    nodes = [n for n in nodes if n.node_id != node_id]
    bg.add_task(storage.save_nodes, nodes)


@app.delete("/nodes", status_code=204, tags=["nodes"])
def delete_nodes(bg: BackgroundTasks,
                 status: Optional[str] = Query(None, description="Only delete nodes with this status")):
    """Bulk delete. With ?status=inactive cleans up stale nodes; with no filter clears all."""
    global nodes
    if status:
        nodes = [n for n in nodes if n.status != status]
    else:
        nodes = []
    bg.add_task(storage.save_nodes, nodes)


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

@app.get("/rules", response_model=list[FlowRule], tags=["rules"])
def list_rules(enabled_only: bool = Query(False)):
    result = [r for r in rules if r.enabled] if enabled_only else rules
    return sorted(result, key=lambda r: r.priority, reverse=True)


@app.post("/rules", response_model=FlowRule, status_code=201, tags=["rules"])
def create_rule(payload: FlowRuleCreate, bg: BackgroundTasks):
    rule = FlowRule(**payload.model_dump())
    rules.append(rule)
    bg.add_task(storage.save_rules, rules)
    return rule


@app.get("/rules/{rule_id}", response_model=FlowRule, tags=["rules"])
def get_rule(rule_id: str):
    rule = next((r for r in rules if r.id == rule_id), None)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule


@app.delete("/rules/{rule_id}", status_code=204, tags=["rules"])
def delete_rule(rule_id: str, bg: BackgroundTasks):
    global rules
    rule = next((r for r in rules if r.id == rule_id), None)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    rules = [r for r in rules if r.id != rule_id]
    bg.add_task(storage.save_rules, rules)


@app.patch("/rules/{rule_id}/toggle", response_model=FlowRule, tags=["rules"])
def toggle_rule(rule_id: str, bg: BackgroundTasks):
    rule = next((r for r in rules if r.id == rule_id), None)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    rule.enabled = not rule.enabled
    bg.add_task(storage.save_rules, rules)
    return rule


# ---------------------------------------------------------------------------
# Rule stats (updated by clients after a match)
# ---------------------------------------------------------------------------

@app.post("/rules/{rule_id}/hit", tags=["rules"])
def record_hit(rule_id: str, bg: BackgroundTasks, byte_count: int = Query(0)):
    rule = next((r for r in rules if r.id == rule_id), None)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    rule.stats.packet_count += 1
    rule.stats.byte_count   += byte_count
    rule.stats.last_match    = _now()
    bg.add_task(storage.save_rules, rules)
    return {"packet_count": rule.stats.packet_count, "byte_count": rule.stats.byte_count}


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

@app.post("/events", response_model=Event, status_code=201, tags=["events"])
def create_event(payload: EventCreate, bg: BackgroundTasks):
    event = Event(**payload.model_dump())
    events.append(event)
    bg.add_task(storage.save_events, events)
    return event


@app.get("/events", response_model=list[Event], tags=["events"])
def list_events(
    node_id: Optional[str] = Query(None),
    action:  Optional[str] = Query(None),
    limit:   int           = Query(100, ge=1, le=1000),
):
    result = events
    if node_id:
        result = [e for e in result if e.node_id == node_id]
    if action:
        result = [e for e in result if e.action == action]
    return result[-limit:]


@app.delete("/events", status_code=204, tags=["events"])
def clear_events(bg: BackgroundTasks):
    global events
    events = []
    bg.add_task(storage.save_events, events)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health", tags=["meta"])
def health():
    return {
        "status": "ok",
        "rules":  len(rules),
        "nodes":  len(nodes),
        "events": len(events),
    }
