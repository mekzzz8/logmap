from __future__ import annotations
from .base_model import LogEvent
from .windows_parser import parse_windows
from .syslog_parser import parse_syslog
from .auth_log_parser import parse_auth

_SIGNATURES: dict[str, list[str]] = {
    "windows": [
        "EventID", "Account Name", "Account Domain", "Logon Type",
        "New Process Name", "Workstation Name", "Security ID",
        "Source Network Address",
    ],
    "syslog": [
        "kernel:", "syslogd", "<14>", "<30>", "<38>",
        "systemd[", "NetworkManager", "audit[",
        ">1 20",   # RFC 5424 version indicator ">1 2024-..."
    ],
    "auth": [
        "sshd[", "sudo:", "su[", "pam_unix", "Accepted password",
        "Failed password", "Invalid user", "session opened",
    ],
}


def _score(text: str) -> dict[str, int]:
    sample = text[:4096]
    scores: dict[str, int] = {fmt: 0 for fmt in _SIGNATURES}
    for fmt, sigs in _SIGNATURES.items():
        for sig in sigs:
            if sig in sample:
                scores[fmt] += 1
    return scores


def detect_format(text: str) -> str:
    scores = _score(text)
    best = max(scores, key=lambda k: scores[k])
    if scores[best] == 0:
        return "unknown"
    return best


def parse_logs(text: str) -> tuple[str, list[LogEvent]]:
    """Return (format_name, [LogEvent])."""
    fmt = detect_format(text)

    parsers = {
        "windows": parse_windows,
        "syslog":  parse_syslog,
        "auth":    parse_auth,
    }

    if fmt != "unknown":
        events = parsers[fmt](text)
        if events:
            return fmt, events

    # Fallback: try all parsers and pick the most productive
    best_fmt, best_events = "unknown", []
    for name, parser_fn in parsers.items():
        try:
            result = parser_fn(text)
            if len(result) > len(best_events):
                best_fmt, best_events = name, result
        except Exception:
            pass

    return best_fmt, best_events
