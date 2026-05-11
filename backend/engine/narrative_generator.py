from __future__ import annotations
from datetime import datetime


_PATTERN_LABELS = {
    "BRUTE_FORCE":    "Brute Force Attack",
    "SPRAY_ATTACK":   "Password Spray Attack",
    "PASS_THE_HASH":  "Pass-the-Hash Attack",
    "LATERAL_MOVE":   "Lateral Movement",
    "PERSISTENCE":    "Persistence Mechanism",
    "PRIV_ESCALATION": "Privilege Escalation",
}

_TACTIC_LABELS = {
    "CRITICAL": "a critical-severity",
    "HIGH":     "a high-severity",
    "MEDIUM":   "a medium-severity",
    "LOW":      "a low-severity",
}


def generate_narrative(events, patterns, report, graph) -> str:
    sections: list[str] = []

    # ── Overview ────────────────────────────────────────────────────────────
    total = len(events)
    suspicious = sum(1 for e in events if e.is_suspicious)
    timestamps = [e.timestamp for e in events if e.timestamp]
    time_range = ""
    if timestamps:
        t0, t1 = min(timestamps), max(timestamps)
        if t0.date() == t1.date():
            time_range = f" between {t0.strftime('%H:%M')} and {t1.strftime('%H:%M')} on {t0.strftime('%Y-%m-%d')}"
        else:
            time_range = f" from {t0.strftime('%Y-%m-%d %H:%M')} to {t1.strftime('%Y-%m-%d %H:%M')}"

    risk_level = report.risk_level
    overview = (
        f"Analysis of {total} log event{'s' if total != 1 else ''}{time_range} "
        f"revealed a {risk_level} risk environment (score: {report.global_score}/100). "
        f"{suspicious} event{'s were' if suspicious != 1 else ' was'} flagged as suspicious."
    )
    if patterns:
        pattern_names = ", ".join(
            _PATTERN_LABELS.get(p.pattern_type, p.pattern_type) for p in patterns
        )
        overview += f" The following attack behaviors were detected: {pattern_names}."
    sections.append(overview)

    # ── Per-pattern narrative ────────────────────────────────────────────────
    for p in patterns:
        label = _PATTERN_LABELS.get(p.pattern_type, p.pattern_type)
        sev_adj = _TACTIC_LABELS.get(p.severity, "a")
        entities = p.entities or []
        techniques = p.mitre_techniques or []

        ips    = [e for e in entities if _looks_like_ip(e)]
        users  = [e for e in entities if not _looks_like_ip(e) and not e.startswith("T1")]
        ts_str = p.timestamp.strftime("%Y-%m-%d %H:%M:%S") if p.timestamp else "unknown time"

        sentence = f"[{label}] {sev_adj} {label.lower()} was detected at {ts_str}. "

        if ips:
            sentence += f"Source IP{'s' if len(ips) > 1 else ''}: {', '.join(ips[:3])}. "
        if users:
            sentence += f"Targeted account{'s' if len(users) > 1 else ''}: {', '.join(users[:3])}. "

        sentence += p.description

        if techniques:
            sentence += f" MITRE ATT&CK: {', '.join(techniques)}."

        sections.append(sentence)

    # ── Top-entity summary ───────────────────────────────────────────────────
    top = report.top_entities[:5] if report.top_entities else []
    if top:
        entity_strs = []
        for ent in top:
            label_val = ent.get("label", "unknown")
            ntype = ent.get("type", "")
            score = ent.get("risk_score", 0)
            entity_strs.append(f"{label_val} ({ntype}, score {score:.2f})")
        sections.append(
            "Top suspicious entities: " + "; ".join(entity_strs) + "."
        )

    # ── Technique summary ────────────────────────────────────────────────────
    if report.technique_scores:
        top_techs = sorted(report.technique_scores, key=lambda t: t.final_score, reverse=True)[:4]
        tech_strs = [f"{t.technique} – {t.name} ({t.tactic})" for t in top_techs]
        sections.append(
            "Highest-scoring MITRE techniques: " + "; ".join(tech_strs) + "."
        )

    # ── Closing recommendation ───────────────────────────────────────────────
    closing_map = {
        "CRITICAL": (
            "IMMEDIATE ACTION REQUIRED: Isolate affected systems, revoke compromised credentials, "
            "and initiate incident response procedures."
        ),
        "HIGH": (
            "Prompt investigation is recommended. Review authentication logs, enforce MFA, "
            "and audit privileged account activity."
        ),
        "MEDIUM": (
            "Review the flagged events and tighten access controls where applicable."
        ),
        "LOW": (
            "No urgent action required. Monitor the environment for further anomalies."
        ),
    }
    sections.append(closing_map.get(risk_level, "Review the findings and take appropriate action."))

    return "\n\n".join(sections)


def _looks_like_ip(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
