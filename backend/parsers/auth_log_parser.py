from __future__ import annotations
import re
from datetime import datetime
from .base_model import LogEvent, EventSeverity

_LINE_RE = re.compile(
    r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"  # timestamp
    r"(\S+)\s+"                                       # hostname
    r"(\w[\w.-]*)(?:\[(\d+)\])?:\s+"                 # process[pid]
    r"(.*)"                                           # message
)

_SSH_ACCEPTED    = re.compile(r"Accepted (\w+) for (\S+) from ([\d.]+) port (\d+)")
_SSH_FAILED      = re.compile(r"Failed (\w+) for (?:invalid user )?(\S+) from ([\d.]+) port (\d+)")
_SSH_INVALID     = re.compile(r"Invalid user (\S+) from ([\d.]+)")
_SUDO_SUCCESS    = re.compile(r"(\S+) : TTY=(\S+) ; PWD=(\S+) ; USER=(\S+) ; COMMAND=(.+)")
_SUDO_FAIL       = re.compile(r"(\S+) : command not allowed|(\S+) : user NOT in sudoers")
_PAM_OPEN        = re.compile(r"pam_unix\(\S+:session\): session opened for user (\S+)")
_PAM_FAIL        = re.compile(r"pam_unix\(\S+:auth\): authentication failure")

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _parse_ts(raw: str) -> datetime | None:
    parts = raw.split()
    if len(parts) < 3:
        return None
    try:
        month = _MONTHS.get(parts[0][:3], 0)
        day = int(parts[1])
        h, m, s = (int(x) for x in parts[2].split(":"))
        return datetime(datetime.now().year, month, day, h, m, s)
    except (ValueError, IndexError):
        return None


def parse_auth(text: str) -> list[LogEvent]:
    events: list[LogEvent] = []

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue

        m = _LINE_RE.match(line)
        if not m:
            continue

        ts_raw, hostname, process, pid, msg = m.groups()
        ts = _parse_ts(ts_raw)
        pid = pid or ""

        event = LogEvent(
            timestamp=ts,
            source="auth",
            severity=EventSeverity.LOW,
            process_name=process,
            process_id=pid,
            raw=line,
            extra={"hostname": hostname},
        )

        m_acc = _SSH_ACCEPTED.search(msg)
        if m_acc:
            event.description = f"SSH Accepted ({m_acc.group(1)})"
            event.username = m_acc.group(2)
            event.src_ip = m_acc.group(3)
            event.severity = EventSeverity.LOW
            event.mitre_techniques = ["T1078"]
            events.append(event)
            continue

        m_fail = _SSH_FAILED.search(msg)
        if m_fail:
            event.description = f"SSH Failed ({m_fail.group(1)})"
            event.username = m_fail.group(2)
            event.src_ip = m_fail.group(3)
            event.severity = EventSeverity.MEDIUM
            event.mitre_techniques = ["T1110"]
            event.is_suspicious = True
            events.append(event)
            continue

        m_inv = _SSH_INVALID.search(msg)
        if m_inv:
            event.description = "SSH Invalid User"
            event.username = m_inv.group(1)
            event.src_ip = m_inv.group(2)
            event.severity = EventSeverity.MEDIUM
            event.mitre_techniques = ["T1110", "T1078"]
            event.is_suspicious = True
            events.append(event)
            continue

        m_sudo = _SUDO_SUCCESS.search(msg)
        if m_sudo:
            event.description = f"Sudo Escalation → {m_sudo.group(4)}: {m_sudo.group(5)[:80]}"
            event.username = m_sudo.group(1)
            event.severity = EventSeverity.HIGH
            event.mitre_techniques = ["T1548.003"]
            event.is_suspicious = True
            events.append(event)
            continue

        m_sudo_f = _SUDO_FAIL.search(msg)
        if m_sudo_f:
            user = m_sudo_f.group(1) or m_sudo_f.group(2) or ""
            event.description = "Sudo Failure"
            event.username = user
            event.severity = EventSeverity.HIGH
            event.mitre_techniques = ["T1548.003", "T1110"]
            event.is_suspicious = True
            events.append(event)
            continue

        m_pam = _PAM_OPEN.search(msg)
        if m_pam:
            event.description = f"PAM Session Opened for {m_pam.group(1)}"
            event.username = m_pam.group(1)
            event.severity = EventSeverity.LOW
            events.append(event)
            continue

        m_pam_f = _PAM_FAIL.search(msg)
        if m_pam_f:
            event.description = "PAM Auth Failure"
            event.severity = EventSeverity.MEDIUM
            event.mitre_techniques = ["T1110"]
            event.is_suspicious = True
            events.append(event)
            continue

    return events
