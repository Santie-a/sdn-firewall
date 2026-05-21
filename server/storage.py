"""
JSON-backed persistence for rules, nodes and events.
Each collection is a single JSON file under the data/ directory.
Reads happen once (on access); writes flush the full collection to disk.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import TypeVar, Type
from pydantic import BaseModel

from models import FlowRule, Node, Event

T = TypeVar("T", bound=BaseModel)

DATA_DIR = Path(__file__).parent.parent / "data"
# Auto-create the storage directory on import: a no-op if it already exists,
# and it never touches existing files. Removes the manual "mkdir data" step.
DATA_DIR.mkdir(parents=True, exist_ok=True)

_RULES_FILE  = DATA_DIR / "rules.json"
_NODES_FILE  = DATA_DIR / "nodes.json"
_EVENTS_FILE = DATA_DIR / "events.json"


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def _load(path: Path, model: Type[T]) -> list[T]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    return [model.model_validate(item) for item in raw]


def _save(path: Path, items: list[BaseModel]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump([item.model_dump() for item in items], f, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

def load_rules() -> list[FlowRule]:
    return _load(_RULES_FILE, FlowRule)


def save_rules(rules: list[FlowRule]) -> None:
    _save(_RULES_FILE, rules)


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------

def load_nodes() -> list[Node]:
    return _load(_NODES_FILE, Node)


def save_nodes(nodes: list[Node]) -> None:
    _save(_NODES_FILE, nodes)


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

def load_events() -> list[Event]:
    return _load(_EVENTS_FILE, Event)


def save_events(events: list[Event]) -> None:
    _save(_EVENTS_FILE, events)
