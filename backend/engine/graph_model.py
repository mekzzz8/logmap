from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class NodeType(str, Enum):
    IP = "IP"
    USER = "USER"
    PROCESS = "PROCESS"
    HOST = "HOST"
    TECHNIQUE = "TECHNIQUE"
    SERVICE = "SERVICE"
    TASK = "TASK"


class RelationType(str, Enum):
    AUTHENTICATED_AS = "AUTHENTICATED_AS"
    SPAWNED = "SPAWNED"
    EXECUTED = "EXECUTED"
    CONNECTED_FROM = "CONNECTED_FROM"
    LOGGED_INTO = "LOGGED_INTO"
    MAPS_TO = "MAPS_TO"
    CREATED = "CREATED"


@dataclass
class Node:
    id: str
    type: NodeType
    label: str
    risk_level: RiskLevel = RiskLevel.LOW
    risk_score: float = 0.0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    event_count: int = 0
    mitre_techniques: list[str] = field(default_factory=list)
    is_suspicious: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.type.value,
            "label": self.label,
            "risk_level": self.risk_level.value,
            "risk_score": round(self.risk_score, 3),
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "event_count": self.event_count,
            "mitre_techniques": self.mitre_techniques,
            "is_suspicious": self.is_suspicious,
            "metadata": self.metadata,
        }


@dataclass
class Edge:
    id: str
    source: str
    target: str
    relation: RelationType
    weight: int = 1
    risk_level: RiskLevel = RiskLevel.LOW
    timestamps: list[datetime] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "source": self.source,
            "target": self.target,
            "relation": self.relation.value,
            "weight": self.weight,
            "risk_level": self.risk_level.value,
            "timestamps": [t.isoformat() for t in self.timestamps],
            "metadata": self.metadata,
        }


@dataclass
class GraphModel:
    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
        }
