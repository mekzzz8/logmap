from __future__ import annotations
import uuid
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .parsers import parse_logs
from .engine import build_graph
from .engine.pattern_detector import detect_patterns
from .engine.risk_scorer import calculate_risk

app = FastAPI(title="LogMap API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory session store: session_id → analysis result
_SESSIONS: dict[str, dict[str, Any]] = {}


class IngestRequest(BaseModel):
    raw_logs: str
    filename: str = "unknown"


class IngestResponse(BaseModel):
    session_id: str
    format: str
    total_events: int
    suspicious_events: int
    risk_score: int
    risk_level: str
    node_count: int
    edge_count: int
    pattern_count: int


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "version": "1.0.0"}


@app.post("/api/ingest", response_model=IngestResponse)
def ingest(req: IngestRequest) -> IngestResponse:
    if not req.raw_logs.strip():
        raise HTTPException(status_code=400, detail="raw_logs is empty")

    fmt, events = parse_logs(req.raw_logs)
    if not events:
        raise HTTPException(status_code=422, detail="No events could be parsed from the provided logs")

    graph = build_graph(events)
    patterns = detect_patterns(events)
    report = calculate_risk(graph, patterns, events)

    session_id = str(uuid.uuid4())
    _SESSIONS[session_id] = {
        "format": fmt,
        "events": events,
        "graph": graph,
        "patterns": patterns,
        "report": report,
    }

    return IngestResponse(
        session_id=session_id,
        format=fmt,
        total_events=len(events),
        suspicious_events=sum(1 for e in events if e.is_suspicious),
        risk_score=report.global_score,
        risk_level=report.risk_level,
        node_count=len(graph.nodes),
        edge_count=len(graph.edges),
        pattern_count=len(patterns),
    )


@app.get("/api/graph/{session_id}")
def get_graph(session_id: str) -> dict:
    session = _get_session(session_id)
    graph = session["graph"]
    return graph.to_dict()


@app.get("/api/timeline/{session_id}")
def get_timeline(session_id: str) -> dict:
    session = _get_session(session_id)
    events = session["events"]

    timeline = []
    for e in events:
        timeline.append({
            "event_id": e.event_id,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "source": e.source,
            "severity": e.severity.value if hasattr(e.severity, "value") else e.severity,
            "description": e.description,
            "username": e.username,
            "src_ip": e.src_ip,
            "process_name": e.process_name,
            "mitre_techniques": e.mitre_techniques,
            "is_suspicious": e.is_suspicious,
        })

    timeline.sort(key=lambda x: (x["timestamp"] or ""))
    return {"events": timeline, "total": len(timeline)}


@app.get("/api/risk/{session_id}")
def get_risk(session_id: str) -> dict:
    session = _get_session(session_id)
    report = session["report"]
    patterns = session["patterns"]
    result = report.to_dict()
    result["patterns"] = [p.to_dict() for p in patterns]
    return result


def _get_session(session_id: str) -> dict:
    if session_id not in _SESSIONS:
        raise HTTPException(status_code=404, detail=f"Session {session_id!r} not found")
    return _SESSIONS[session_id]
