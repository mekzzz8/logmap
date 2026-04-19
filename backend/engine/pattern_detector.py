from __future__ import annotations
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from ..parsers.base_model import LogEvent

BRUTE_FORCE_THRESHOLD = 5        # N failed logins in window
BRUTE_FORCE_WINDOW    = timedelta(minutes=5)
SPRAY_THRESHOLD       = 3        # distinct users from same IP
LATERAL_MOVE_TYPE     = "10"     # RDP logon type


@dataclass
class DetectedPattern:
    pattern_type: str
    description: str
    entities: list[str] = field(default_factory=list)
    event_ids: list[str] = field(default_factory=list)
    severity: str = "HIGH"
    mitre_techniques: list[str] = field(default_factory=list)
    timestamp: datetime | None = None

    def to_dict(self) -> dict:
        return {
            "pattern_type": self.pattern_type,
            "description": self.description,
            "entities": self.entities,
            "severity": self.severity,
            "mitre_techniques": self.mitre_techniques,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }


def detect_patterns(events: list[LogEvent]) -> list[DetectedPattern]:
    patterns: list[DetectedPattern] = []

    patterns.extend(_detect_brute_force(events))
    patterns.extend(_detect_spray_attack(events))
    patterns.extend(_detect_pass_the_hash(events))
    patterns.extend(_detect_lateral_movement(events))
    patterns.extend(_detect_persistence(events))
    patterns.extend(_detect_priv_escalation(events))

    return patterns


def _detect_brute_force(events: list[LogEvent]) -> list[DetectedPattern]:
    patterns = []
    failed_by_ip: dict[str, list[LogEvent]] = defaultdict(list)

    for e in events:
        if e.event_id in ("4625", "") and e.src_ip and "T1110" in e.mitre_techniques:
            failed_by_ip[e.src_ip].append(e)
        elif e.source == "auth" and "SSH Failed" in e.description and e.src_ip:
            failed_by_ip[e.src_ip].append(e)

    for ip, evts in failed_by_ip.items():
        evts_with_ts = [e for e in evts if e.timestamp]
        if not evts_with_ts and len(evts) >= BRUTE_FORCE_THRESHOLD:
            patterns.append(DetectedPattern(
                pattern_type="BRUTE_FORCE",
                description=f"Brute force from {ip}: {len(evts)} failed attempts",
                entities=[ip],
                severity="CRITICAL",
                mitre_techniques=["T1110"],
            ))
            continue

        evts_with_ts.sort(key=lambda e: e.timestamp)
        i = 0
        while i < len(evts_with_ts):
            window = [evts_with_ts[i]]
            j = i + 1
            while j < len(evts_with_ts):
                if evts_with_ts[j].timestamp - evts_with_ts[i].timestamp <= BRUTE_FORCE_WINDOW:
                    window.append(evts_with_ts[j])
                    j += 1
                else:
                    break
            if len(window) >= BRUTE_FORCE_THRESHOLD:
                patterns.append(DetectedPattern(
                    pattern_type="BRUTE_FORCE",
                    description=f"Brute force from {ip}: {len(window)} failures in {BRUTE_FORCE_WINDOW}",
                    entities=[ip],
                    severity="CRITICAL",
                    mitre_techniques=["T1110"],
                    timestamp=window[0].timestamp,
                ))
                i = j
            else:
                i += 1

    return patterns


def _detect_spray_attack(events: list[LogEvent]) -> list[DetectedPattern]:
    patterns = []
    users_by_ip: dict[str, set[str]] = defaultdict(set)

    for e in events:
        if e.src_ip and e.username and "T1110" in e.mitre_techniques:
            users_by_ip[e.src_ip].add(e.username.lower())

    for ip, users in users_by_ip.items():
        if len(users) >= SPRAY_THRESHOLD:
            patterns.append(DetectedPattern(
                pattern_type="SPRAY_ATTACK",
                description=f"Password spray from {ip} targeting {len(users)} users",
                entities=[ip] + list(users),
                severity="CRITICAL",
                mitre_techniques=["T1110.003"],
            ))

    return patterns


def _detect_pass_the_hash(events: list[LogEvent]) -> list[DetectedPattern]:
    patterns = []
    # 4648 (explicit creds) from internal IP without preceding 4624
    explicit_ips: set[str] = set()
    successful_ips: set[str] = set()

    for e in events:
        if e.event_id == "4648" and e.src_ip:
            explicit_ips.add(e.src_ip)
        if e.event_id == "4624" and e.src_ip:
            successful_ips.add(e.src_ip)

    for ip in explicit_ips:
        if ip not in successful_ips and _is_internal(ip):
            patterns.append(DetectedPattern(
                pattern_type="PASS_THE_HASH",
                description=f"Possible Pass-the-Hash from internal {ip} (4648 without prior 4624)",
                entities=[ip],
                severity="CRITICAL",
                mitre_techniques=["T1550.002"],
            ))

    return patterns


def _detect_lateral_movement(events: list[LogEvent]) -> list[DetectedPattern]:
    patterns = []
    rdp_events = [
        e for e in events
        if e.event_id == "4624"
        and e.extra.get("logon_type") == LATERAL_MOVE_TYPE
        and e.src_ip
        and _is_internal(e.src_ip)
    ]

    hosts_by_user: dict[str, set[str]] = defaultdict(set)
    for e in rdp_events:
        host = e.extra.get("workstation") or e.dest_ip
        if host:
            hosts_by_user[e.username].add(host)

    for user, hosts in hosts_by_user.items():
        if len(hosts) >= 2:
            patterns.append(DetectedPattern(
                pattern_type="LATERAL_MOVE",
                description=f"Lateral movement by {user} via RDP to {len(hosts)} hosts",
                entities=[user] + list(hosts),
                severity="HIGH",
                mitre_techniques=["T1021.001"],
            ))

    return patterns


def _detect_persistence(events: list[LogEvent]) -> list[DetectedPattern]:
    patterns = []
    persistence_events = [e for e in events if e.event_id in ("4698", "7045")]
    suspicious_users = {e.username for e in events if e.is_suspicious and e.username}

    for e in persistence_events:
        if e.username in suspicious_users:
            etype = "Scheduled Task" if e.event_id == "4698" else "Service"
            patterns.append(DetectedPattern(
                pattern_type="PERSISTENCE",
                description=f"Persistence via {etype} by suspicious user {e.username}",
                entities=[e.username],
                severity="HIGH",
                mitre_techniques=e.mitre_techniques,
                timestamp=e.timestamp,
            ))

    return patterns


def _detect_priv_escalation(events: list[LogEvent]) -> list[DetectedPattern]:
    patterns = []
    priv_events = [e for e in events if e.event_id == "4672" and e.timestamp]
    suspicious_logins = [e for e in events if e.event_id == "4624" and e.is_suspicious and e.timestamp]

    for priv in priv_events:
        for login in suspicious_logins:
            if login.username == priv.username and login.timestamp:
                delta = abs((priv.timestamp - login.timestamp).total_seconds())
                if delta <= 120:
                    patterns.append(DetectedPattern(
                        pattern_type="PRIV_ESCALATION",
                        description=f"Privilege escalation by {priv.username} within 2min of suspicious login",
                        entities=[priv.username],
                        severity="CRITICAL",
                        mitre_techniques=["T1078.002"],
                        timestamp=priv.timestamp,
                    ))
                    break

    return patterns


def _is_internal(ip: str) -> bool:
    return (
        ip.startswith("10.") or
        ip.startswith("192.168.") or
        ip.startswith("172.") or
        ip in ("-", "::1", "127.0.0.1")
    )
