from __future__ import annotations
import hashlib
from ..parsers.base_model import LogEvent, EventSeverity
from .graph_model import Edge, Node, NodeType, RelationType, RiskLevel
from .entity_extractor import _node_id, _risk_level, _SEVERITY_SCORE, _exe_basename


def _edge_id(src: str, tgt: str, relation: RelationType) -> str:
    key = f"{src}:{tgt}:{relation.value}"
    return hashlib.md5(key.encode()).hexdigest()[:16]


def _get_risk(severity: EventSeverity) -> RiskLevel:
    score = _SEVERITY_SCORE.get(severity, 0.1)
    return _risk_level(score)


def _upsert_edge(
    edges: dict[str, Edge],
    src_id: str,
    tgt_id: str,
    relation: RelationType,
    event: LogEvent,
) -> None:
    eid = _edge_id(src_id, tgt_id, relation)
    if eid not in edges:
        edges[eid] = Edge(
            id=eid,
            source=src_id,
            target=tgt_id,
            relation=relation,
            weight=0,
            risk_level=RiskLevel.LOW,
        )
    edge = edges[eid]
    edge.weight += 1
    if event.timestamp:
        edge.timestamps.append(event.timestamp)

    new_risk = _get_risk(event.severity)
    _RISK_ORDER = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
    if _RISK_ORDER.index(new_risk) > _RISK_ORDER.index(edge.risk_level):
        edge.risk_level = new_risk


def build_edges(events: list[LogEvent], nodes: dict[str, Node]) -> dict[str, Edge]:
    edges: dict[str, Edge] = {}

    def nid(ntype: NodeType, label: str) -> str | None:
        nid_ = _node_id(ntype, label)
        return nid_ if nid_ in nodes else None

    for event in events:
        ip_id   = nid(NodeType.IP,   event.src_ip)   if event.src_ip   not in ("", "-", "::1") else None
        user_id = nid(NodeType.USER, event.username) if event.username not in ("", "-")          else None

        proc_label = _exe_basename(event.process_name) if event.process_name else ""
        proc_id_node = nid(NodeType.PROCESS, proc_label) if proc_label else None

        parent_label = _exe_basename(event.parent_process) if event.parent_process else ""
        parent_id_node = nid(NodeType.PROCESS, parent_label) if parent_label else None

        host_label = event.extra.get("hostname") or event.extra.get("workstation") or ""
        host_id = nid(NodeType.HOST, host_label) if host_label and host_label not in ("-", "") else None

        # IP → USER : AUTHENTICATED_AS
        if ip_id and user_id:
            _upsert_edge(edges, ip_id, user_id, RelationType.AUTHENTICATED_AS, event)

        # IP → HOST : CONNECTED_FROM
        if ip_id and host_id:
            _upsert_edge(edges, ip_id, host_id, RelationType.CONNECTED_FROM, event)

        # USER → HOST : LOGGED_INTO
        if user_id and host_id:
            _upsert_edge(edges, user_id, host_id, RelationType.LOGGED_INTO, event)

        # PARENT_PROCESS → PROCESS : SPAWNED
        if parent_id_node and proc_id_node and parent_id_node != proc_id_node:
            _upsert_edge(edges, parent_id_node, proc_id_node, RelationType.SPAWNED, event)

        # USER → PROCESS : EXECUTED
        if user_id and proc_id_node:
            _upsert_edge(edges, user_id, proc_id_node, RelationType.EXECUTED, event)

        # SERVICE / TASK : CREATED
        svc = event.extra.get("service_name", "")
        if user_id and svc and svc not in ("-", ""):
            svc_id = nid(NodeType.SERVICE, svc)
            if svc_id:
                _upsert_edge(edges, user_id, svc_id, RelationType.CREATED, event)

        task = event.extra.get("task_name", "")
        if user_id and task and task not in ("-", ""):
            task_id = nid(NodeType.TASK, task)
            if task_id:
                _upsert_edge(edges, user_id, task_id, RelationType.CREATED, event)

        # * → TECHNIQUE : MAPS_TO
        for tech in event.mitre_techniques:
            tech_id = nid(NodeType.TECHNIQUE, tech)
            if not tech_id:
                continue
            if ip_id:
                _upsert_edge(edges, ip_id, tech_id, RelationType.MAPS_TO, event)
            if user_id:
                _upsert_edge(edges, user_id, tech_id, RelationType.MAPS_TO, event)
            if proc_id_node:
                _upsert_edge(edges, proc_id_node, tech_id, RelationType.MAPS_TO, event)

    return edges
