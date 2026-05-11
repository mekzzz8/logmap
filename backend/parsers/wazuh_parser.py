from __future__ import annotations
import json
from datetime import datetime
from .base_model import LogEvent, EventSeverity

# Wazuh rule.level → EventSeverity
def _level_to_severity(level: int) -> EventSeverity:
    if level >= 14:  return EventSeverity.CRITICAL
    if level >= 11:  return EventSeverity.HIGH
    if level >= 7:   return EventSeverity.MEDIUM
    return EventSeverity.LOW

# Wazuh rule ID ranges / exact IDs → MITRE techniques
_RULE_MITRE: list[tuple[range | set, list[str]]] = [
    # SSH brute force
    ({5710, 5711, 5712, 5713, 5503, 5504, 5760},  ["T1110"]),
    # Sudo escalation
    ({5401, 5402, 5403, 5404},                    ["T1548.003"]),
    # New user / account manipulation
    ({5902, 5903, 5905},                          ["T1136.001"]),
    # Windows auth failures
    ({18104, 18105, 18106},                       ["T1110"]),
    # Lateral movement / RDP
    ({60106, 60107, 60108},                       ["T1021.001"]),
    # Scheduled task / persistence
    ({18145, 18146},                              ["T1053.005"]),
    # PowerShell execution
    ({91502, 91503, 91504},                       ["T1059.001"]),
    # Pass-the-hash
    ({60122, 60123},                              ["T1550.002"]),
    # Privilege escalation
    ({80784, 80785},                              ["T1078.002"]),
]

_SUSPICIOUS_LEVELS = {EventSeverity.HIGH, EventSeverity.CRITICAL}
_SUSPICIOUS_TECHNIQUES = {
    "T1110", "T1548.003", "T1550.002", "T1078.002",
    "T1021.001", "T1059.001", "T1053.005",
}


def _mitre_for_rule(rule_id: int) -> list[str]:
    for matcher, techniques in _RULE_MITRE:
        if isinstance(matcher, set) and rule_id in matcher:
            return techniques
        if isinstance(matcher, range) and rule_id in matcher:
            return techniques
    return []


def _parse_timestamp(ts_str: str) -> datetime | None:
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
    ):
        try:
            dt = datetime.strptime(ts_str, fmt)
            return dt.replace(tzinfo=None)
        except ValueError:
            continue
    return None


def _parse_alert(obj: dict) -> LogEvent | None:
    rule = obj.get("rule", {})
    if not rule:
        return None

    rule_id_str = str(rule.get("id", "0"))
    try:
        rule_id = int(rule_id_str)
    except ValueError:
        rule_id = 0

    level = int(rule.get("level", 0))
    severity = _level_to_severity(level)
    description = rule.get("description", f"Wazuh rule {rule_id_str}")

    agent = obj.get("agent", {})
    data  = obj.get("data", {})

    src_ip   = data.get("srcip", "") or obj.get("data", {}).get("src_ip", "")
    username = data.get("dstuser", "") or data.get("srcuser", "") or ""

    timestamp = _parse_timestamp(obj.get("timestamp", ""))

    techniques = _mitre_for_rule(rule_id)
    is_suspicious = (
        severity in _SUSPICIOUS_LEVELS
        or bool(set(techniques) & _SUSPICIOUS_TECHNIQUES)
    )

    return LogEvent(
        event_id=rule_id_str,
        timestamp=timestamp,
        source=agent.get("name", "wazuh"),
        severity=severity,
        description=description,
        username=username,
        src_ip=src_ip,
        mitre_techniques=techniques,
        is_suspicious=is_suspicious,
        raw=obj.get("full_log", json.dumps(obj)),
        extra={
            "agent_id":   agent.get("id", ""),
            "rule_level": level,
            "rule_id":    rule_id_str,
        },
    )


def parse_wazuh(text: str) -> list[LogEvent]:
    """Parse Wazuh alerts.json — supports JSON array and JSON-lines formats."""
    text = text.strip()
    events: list[LogEvent] = []

    # Try JSON array first
    if text.startswith("["):
        try:
            items = json.loads(text)
            if isinstance(items, list):
                for item in items:
                    ev = _parse_alert(item)
                    if ev:
                        events.append(ev)
                return events
        except json.JSONDecodeError:
            pass

    # JSON lines (one object per line)
    for line in text.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
            ev = _parse_alert(obj)
            if ev:
                events.append(ev)
        except json.JSONDecodeError:
            continue

    return events
