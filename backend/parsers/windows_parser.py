from __future__ import annotations
import re
from datetime import datetime
from typing import Optional
from .base_model import LogEvent, EventSeverity

# Event ID → (description, MITRE techniques, base severity)
EVENT_MAP: dict[str, tuple[str, list[str], EventSeverity]] = {
    "4624": ("Successful Logon", [], EventSeverity.LOW),
    "4625": ("Failed Logon", ["T1110"], EventSeverity.MEDIUM),
    "4634": ("Logoff", [], EventSeverity.LOW),
    "4648": ("Logon with Explicit Credentials", ["T1078", "T1550.002"], EventSeverity.HIGH),
    "4672": ("Special Privileges Assigned", ["T1078.002"], EventSeverity.HIGH),
    "4688": ("New Process Created", ["T1059"], EventSeverity.LOW),
    "4698": ("Scheduled Task Created", ["T1053.005"], EventSeverity.HIGH),
    "4720": ("User Account Created", ["T1136.001"], EventSeverity.HIGH),
    "4732": ("User Added to Group", ["T1098"], EventSeverity.HIGH),
    "4776": ("Credential Validation", ["T1110.002"], EventSeverity.MEDIUM),
    "7045": ("New Service Installed", ["T1543.003"], EventSeverity.HIGH),
}

SUSPICIOUS_PROCESSES = {
    "mimikatz", "procdump", "mshta", "certutil", "wmic",
    "psexec", "psexesvc", "wce", "fgdump", "pwdump",
    "lsass", "ntdsutil", "vssadmin", "reg",
}

_SEP = r"[=:\s]+"   # accepts = : or whitespace separators

_RE_FIELDS: list[tuple[str, re.Pattern]] = [
    ("timestamp", re.compile(
        r"(?:Date/Time[=:\s]+)?"
        r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
    )),
    ("event_id",      re.compile(r"EventID" + _SEP + r"(\d{4,5})", re.IGNORECASE)),
    ("username",      re.compile(r"Account Name" + _SEP + r"([^\s\n\r=]+)", re.IGNORECASE)),
    ("domain",        re.compile(r"Account Domain" + _SEP + r"([^\s\n\r=]+)", re.IGNORECASE)),
    ("src_ip",        re.compile(r"Source Network Address" + _SEP + r"([\d.]+|::1|-)", re.IGNORECASE)),
    ("workstation",   re.compile(r"Workstation Name" + _SEP + r"([^\s\n\r=]+)", re.IGNORECASE)),
    ("logon_type",    re.compile(r"Logon Type" + _SEP + r"(\d+)", re.IGNORECASE)),
    ("process_name",  re.compile(r"New Process Name" + _SEP + r"(.+?)(?:\r?\n|$)", re.IGNORECASE)),
    ("process_id",    re.compile(r"New Process ID" + _SEP + r"(0x[0-9a-fA-F]+|\d+)", re.IGNORECASE)),
    ("parent_process",re.compile(r"Creator Process Name" + _SEP + r"(.+?)(?:\r?\n|$)", re.IGNORECASE)),
    ("service_name",  re.compile(r"Service Name" + _SEP + r"([^\s\n\r=]+)", re.IGNORECASE)),
    ("task_name",     re.compile(r"Task Name" + _SEP + r"([^\s\n\r=]+)", re.IGNORECASE)),
    ("failure_reason",re.compile(r"Failure Reason" + _SEP + r"(.+?)(?:\r?\n|$)", re.IGNORECASE)),
]

_TS_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p",
]


def _parse_ts(raw: str) -> Optional[datetime]:
    raw = raw.strip()
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(raw[:len(fmt) + 2], fmt)
        except ValueError:
            pass
    return None


def _extract_fields(text: str) -> dict:
    result: dict = {}
    for name, pat in _RE_FIELDS:
        m = pat.search(text)
        if m:
            result[name] = m.group(1).strip()
    return result


def _is_suspicious(event_id: str, fields: dict, process_name: str) -> tuple[bool, list[str]]:
    suspicious = False
    extra_techniques: list[str] = []

    proc = process_name.lower()
    proc_base = proc.split("\\")[-1].replace(".exe", "")
    if proc_base in SUSPICIOUS_PROCESSES:
        suspicious = True

    if "powershell" in proc:
        if any(flag in proc for flag in ["-enc", "-hidden", "-nop", "-bypass", "-exec bypass"]):
            suspicious = True
            extra_techniques.append("T1059.001")

    logon_type = fields.get("logon_type", "")
    if event_id == "4624" and logon_type == "10":
        src = fields.get("src_ip", "")
        if src and not _is_internal(src):
            suspicious = True
            extra_techniques.append("T1021.001")

    username = fields.get("username", "").lower()
    if event_id == "4625" and username in {"administrator", "admin", "root", "guest"}:
        suspicious = True

    return suspicious, extra_techniques


def _is_internal(ip: str) -> bool:
    return (
        ip.startswith("10.") or
        ip.startswith("192.168.") or
        ip.startswith("172.") or
        ip in ("-", "::1", "127.0.0.1")
    )


def parse_windows(text: str) -> list[LogEvent]:
    events: list[LogEvent] = []

    blocks = re.split(r"\n{2,}|(?=EventID[=:\s]+\d{4})", text)
    for block in blocks:
        block = block.strip()
        if not block:
            continue

        fields = _extract_fields(block)
        event_id = fields.get("event_id", "")
        if not event_id:
            continue

        meta = EVENT_MAP.get(event_id, ("Unknown Event", [], EventSeverity.LOW))
        description, mitre, severity = meta

        ts = _parse_ts(fields.get("timestamp", "")) if "timestamp" in fields else None

        process_name = fields.get("process_name", "")
        suspicious, extra_tech = _is_suspicious(event_id, fields, process_name)

        all_techniques = list(mitre) + extra_tech

        event = LogEvent(
            event_id=event_id,
            timestamp=ts,
            source="windows",
            severity=severity,
            description=description,
            username=fields.get("username", ""),
            domain=fields.get("domain", ""),
            src_ip=fields.get("src_ip", ""),
            process_name=process_name,
            process_id=fields.get("process_id", ""),
            parent_process=fields.get("parent_process", ""),
            mitre_techniques=all_techniques,
            is_suspicious=suspicious,
            raw=block,
            extra={
                "logon_type": fields.get("logon_type", ""),
                "workstation": fields.get("workstation", ""),
                "service_name": fields.get("service_name", ""),
                "task_name": fields.get("task_name", ""),
                "failure_reason": fields.get("failure_reason", ""),
            },
        )
        events.append(event)

    return events
