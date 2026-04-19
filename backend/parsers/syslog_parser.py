from __future__ import annotations
import re
from datetime import datetime
from .base_model import LogEvent, EventSeverity

# RFC 3164 format
_RFC3164 = re.compile(
    r"(?:<(\d+)>)?"
    r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(\S+)\s+"
    r"(\S+?)(?:\[(\d+)\])?:\s+"
    r"(.*)"
)

# RFC 5424 format
_RFC5424 = re.compile(
    r"<(\d+)>(\d+)\s+"
    r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\s+"
    r"(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+"
    r"(.*)"
)

_IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

_SEVERITY_KEYWORDS = {
    EventSeverity.CRITICAL: ["emergency", "alert", "critical", "panic"],
    EventSeverity.HIGH:     ["error", "err", "crit", "failed", "failure", "denied"],
    EventSeverity.MEDIUM:   ["warning", "warn", "notice", "invalid"],
    EventSeverity.LOW:      ["info", "debug", "accepted", "opened", "started"],
}

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

_TS5424_FMTS = [
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S",
]


def _parse_3164_ts(raw: str) -> datetime | None:
    raw = raw.strip()
    parts = raw.split()
    if len(parts) < 3:
        return None
    try:
        month = _MONTHS.get(parts[0][:3], 0)
        day = int(parts[1])
        time_parts = parts[2].split(":")
        h, m, s = int(time_parts[0]), int(time_parts[1]), int(time_parts[2])
        return datetime(datetime.now().year, month, day, h, m, s)
    except (ValueError, IndexError):
        return None


def _parse_5424_ts(raw: str) -> datetime | None:
    for fmt in _TS5424_FMTS:
        try:
            return datetime.strptime(raw[:len(fmt) + 4], fmt)
        except ValueError:
            pass
    return None


def _priority_to_severity(priority: int) -> EventSeverity:
    level = priority % 8
    if level <= 1:
        return EventSeverity.CRITICAL
    if level <= 3:
        return EventSeverity.HIGH
    if level <= 5:
        return EventSeverity.MEDIUM
    return EventSeverity.LOW


def _keyword_severity(msg: str) -> EventSeverity:
    lower = msg.lower()
    for sev, keywords in _SEVERITY_KEYWORDS.items():
        if any(kw in lower for kw in keywords):
            return sev
    return EventSeverity.LOW


def _extract_ips(msg: str) -> list[str]:
    return _IP_RE.findall(msg)


def parse_syslog(text: str) -> list[LogEvent]:
    events: list[LogEvent] = []

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue

        m5 = _RFC5424.match(line)
        if m5:
            priority = int(m5.group(1))
            ts = _parse_5424_ts(m5.group(3))
            hostname = m5.group(4)
            app = m5.group(5)
            proc_id = m5.group(6)
            msg = m5.group(8)
            severity = _priority_to_severity(priority)
        else:
            m3 = _RFC3164.match(line)
            if m3:
                priority = int(m3.group(1)) if m3.group(1) else -1
                ts = _parse_3164_ts(m3.group(2))
                hostname = m3.group(3)
                app = m3.group(4)
                proc_id = m3.group(5) or ""
                msg = m3.group(6)
                severity = _priority_to_severity(priority) if priority >= 0 else _keyword_severity(msg)
            else:
                continue

        ips = _extract_ips(msg)
        src_ip = ips[0] if ips else ""
        dest_ip = ips[1] if len(ips) > 1 else ""

        suspicious = severity in (EventSeverity.HIGH, EventSeverity.CRITICAL)

        event = LogEvent(
            timestamp=ts,
            source="syslog",
            severity=severity,
            description=msg[:200],
            process_name=app,
            process_id=proc_id,
            src_ip=src_ip,
            dest_ip=dest_ip,
            is_suspicious=suspicious,
            raw=line,
            extra={"hostname": hostname},
        )
        events.append(event)

    return events
