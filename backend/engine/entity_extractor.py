from __future__ import annotations
import hashlib
from datetime import datetime
from ..parsers.base_model import LogEvent, EventSeverity
from .graph_model import Node, NodeType, RiskLevel

_SEVERITY_SCORE = {
    EventSeverity.LOW: 0.1,
    EventSeverity.MEDIUM: 0.35,
    EventSeverity.HIGH: 0.65,
    EventSeverity.CRITICAL: 0.9,
}

_RISK_THRESHOLDS = [
    (0.75, RiskLevel.CRITICAL),
    (0.50, RiskLevel.HIGH),
    (0.25, RiskLevel.MEDIUM),
    (0.0,  RiskLevel.LOW),
]


def _exe_basename(path: str) -> str:
    """Extract just the executable filename from a full command line."""
    exe = path.split()[0]          # strip arguments first
    exe = exe.replace('"', '')
    exe = exe.split("\\")[-1]      # Windows path separator
    exe = exe.split("/")[-1]       # Unix path separator
    return exe or path.split()[0]


def _node_id(node_type: NodeType, label: str) -> str:
    return hashlib.md5(f"{node_type.value}:{label}".encode()).hexdigest()[:16]


def _risk_level(score: float) -> RiskLevel:
    for threshold, level in _RISK_THRESHOLDS:
        if score >= threshold:
            return level
    return RiskLevel.LOW


def _frequency_multiplier(count: int) -> float:
    if count >= 50:
        return 1.5
    if count >= 20:
        return 1.3
    if count >= 10:
        return 1.15
    return 1.0


def _update_node(node: Node, event: LogEvent) -> None:
    node.event_count += 1

    ts = event.timestamp
    if ts:
        if node.first_seen is None or ts < node.first_seen:
            node.first_seen = ts
        if node.last_seen is None or ts > node.last_seen:
            node.last_seen = ts

    new_score = _SEVERITY_SCORE.get(event.severity, 0.1)
    raw = max(node.risk_score, new_score)
    raw = min(raw * _frequency_multiplier(node.event_count), 1.0)
    node.risk_score = raw
    node.risk_level = _risk_level(raw)

    for tech in event.mitre_techniques:
        if tech not in node.mitre_techniques:
            node.mitre_techniques.append(tech)

    if event.is_suspicious:
        node.is_suspicious = True


def extract_entities(events: list[LogEvent]) -> dict[str, Node]:
    nodes: dict[str, Node] = {}

    def get_or_create(ntype: NodeType, label: str) -> Node:
        nid = _node_id(ntype, label)
        if nid not in nodes:
            nodes[nid] = Node(id=nid, type=ntype, label=label)
        return nodes[nid]

    for event in events:
        if event.src_ip and event.src_ip not in ("-", "::1", ""):
            ip_node = get_or_create(NodeType.IP, event.src_ip)
            _update_node(ip_node, event)

        if event.dest_ip and event.dest_ip not in ("-", "::1", ""):
            dest_node = get_or_create(NodeType.IP, event.dest_ip)
            _update_node(dest_node, event)

        if event.username and event.username not in ("-", ""):
            user_node = get_or_create(NodeType.USER, event.username)
            _update_node(user_node, event)

        if event.process_name and event.process_name not in ("-", ""):
            proc_label = _exe_basename(event.process_name)
            proc_node = get_or_create(NodeType.PROCESS, proc_label)
            _update_node(proc_node, event)

        if event.extra.get("hostname") or event.extra.get("workstation"):
            host = event.extra.get("hostname") or event.extra.get("workstation")
            if host and host not in ("-", ""):
                host_node = get_or_create(NodeType.HOST, host)
                _update_node(host_node, event)

        if event.extra.get("service_name"):
            svc = event.extra["service_name"]
            if svc and svc not in ("-", ""):
                svc_node = get_or_create(NodeType.SERVICE, svc)
                _update_node(svc_node, event)

        if event.extra.get("task_name"):
            task = event.extra["task_name"]
            if task and task not in ("-", ""):
                task_node = get_or_create(NodeType.TASK, task)
                _update_node(task_node, event)

        for tech in event.mitre_techniques:
            tech_node = get_or_create(NodeType.TECHNIQUE, tech)
            _update_node(tech_node, event)

    return nodes
