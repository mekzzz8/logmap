from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class EventSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class LogEvent:
    event_id: str = ""
    timestamp: datetime | None = None
    source: str = ""
    severity: EventSeverity = EventSeverity.LOW
    description: str = ""
    username: str = ""
    domain: str = ""
    src_ip: str = ""
    dest_ip: str = ""
    dest_port: int = 0
    process_name: str = ""
    process_id: str = ""
    parent_process: str = ""
    mitre_techniques: list[str] = field(default_factory=list)
    is_suspicious: bool = False
    raw: str = ""
    extra: dict[str, Any] = field(default_factory=dict)
