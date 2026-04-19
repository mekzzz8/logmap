from __future__ import annotations
from dataclasses import dataclass, field
from .graph_model import GraphModel, NodeType
from .pattern_detector import DetectedPattern
from .technique_db import TECHNIQUE_DB, get as get_tech

# Fallback base score for techniques not in the DB (unknown/generic)
_UNKNOWN_BASE = 45.0

# Pattern-level scores derived from the highest-severity technique they imply
_PATTERN_SCORE: dict[str, float] = {
    "BRUTE_FORCE":     TECHNIQUE_DB["T1110"].base_score,        # 70.4
    "SPRAY_ATTACK":    TECHNIQUE_DB["T1110.003"].base_score,    # 70.4
    "PASS_THE_HASH":   TECHNIQUE_DB["T1550.002"].base_score,    # 83.2
    "LATERAL_MOVE":    TECHNIQUE_DB["T1021.001"].base_score,    # 62.4
    "PERSISTENCE":     TECHNIQUE_DB["T1053.005"].base_score,    # 71.2
    "PRIV_ESCALATION": TECHNIQUE_DB["T1078.002"].base_score,    # 83.6
}

_RISK_THRESHOLDS = [(76, "CRITICAL"), (51, "HIGH"), (26, "MEDIUM"), (0, "LOW")]


def _score_label(score: float) -> str:
    for threshold, label in _RISK_THRESHOLDS:
        if score >= threshold:
            return label
    return "LOW"


def _freq_multiplier(count: int) -> float:
    """Higher observation count → attacker is more active → higher risk."""
    if count >= 100: return 1.40
    if count >= 50:  return 1.25
    if count >= 20:  return 1.15
    if count >= 10:  return 1.05
    return 1.0


def _chain_multiplier(num_techniques: int) -> float:
    """Chained techniques indicate a multi-stage attack → amplified risk."""
    if num_techniques >= 5: return 1.30
    if num_techniques >= 3: return 1.15
    if num_techniques >= 2: return 1.05
    return 1.0


@dataclass
class TechniqueScore:
    technique: str
    name: str
    count: int
    tactic: str
    tactic_id: str
    tactic_score: int
    sigma_severity: str
    sigma_score: int
    base_score: float
    freq_multiplier: float
    final_score: float
    risk_level: str
    why: str
    formula: str
    sigma_rule_refs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "technique":       self.technique,
            "name":            self.name,
            "count":           self.count,
            "tactic":          self.tactic,
            "tactic_id":       self.tactic_id,
            "tactic_score":    self.tactic_score,
            "sigma_severity":  self.sigma_severity,
            "sigma_score":     self.sigma_score,
            "base_score":      round(self.base_score, 1),
            "freq_multiplier": round(self.freq_multiplier, 2),
            "final_score":     round(self.final_score, 1),
            "risk_level":      self.risk_level,
            "why":             self.why,
            "formula":         self.formula,
            "sigma_rule_refs": self.sigma_rule_refs,
        }


@dataclass
class RiskReport:
    global_score: int
    risk_level: str
    technique_scores: list[TechniqueScore] = field(default_factory=list)
    pattern_contributions: dict[str, float] = field(default_factory=dict)
    total_events: int = 0
    suspicious_events: int = 0
    top_entities: list[dict] = field(default_factory=list)
    scoring_note: str = ""

    def to_dict(self) -> dict:
        return {
            "global_score":          self.global_score,
            "risk_level":            self.risk_level,
            "technique_scores":      [t.to_dict() for t in self.technique_scores],
            "pattern_contributions": self.pattern_contributions,
            "total_events":          self.total_events,
            "suspicious_events":     self.suspicious_events,
            "top_entities":          self.top_entities,
            "scoring_note":          self.scoring_note,
        }


def calculate_risk(
    graph: GraphModel,
    patterns: list[DetectedPattern],
    events=None,
) -> RiskReport:
    # ── 1. Collect technique observation counts from graph nodes ──────────────
    tech_counts: dict[str, int] = {}
    for node in graph.nodes:
        if node.type == NodeType.TECHNIQUE:
            tech_counts[node.label] = max(node.event_count or 1, 1)

    # ── 2. Score each technique using the DB ──────────────────────────────────
    technique_scores: list[TechniqueScore] = []
    tech_component = 0.0

    for tech_id, count in tech_counts.items():
        meta = get_tech(tech_id)

        if meta:
            tactic_score  = meta.tactic_score
            sigma_sev     = meta.sigma_severity
            sigma_score   = meta.sigma_score
            base          = meta.base_score
            name          = meta.name
            tactic        = meta.tactic
            tactic_id     = meta.tactic_id
            why           = meta.why
            refs          = list(meta.sigma_rule_refs)
            formula       = (
                f"({tactic_score} × 0.4) + ({sigma_score} × 0.6) = {base:.1f}"
                f"  ×  freq_mult({count}) = "
            )
        else:
            tactic_score  = 50
            sigma_sev     = "medium"
            sigma_score   = 52
            base          = _UNKNOWN_BASE
            name          = tech_id
            tactic        = "Unknown"
            tactic_id     = "—"
            why           = (
                f"{tech_id} is not in the technique database. "
                "A default score of 45 is applied. Consider updating technique_db.py."
            )
            refs          = []
            formula       = f"(default base {base:.1f})  ×  freq_mult({count}) = "

        freq_mult = _freq_multiplier(count)
        final     = min(base * freq_mult, 100.0)
        formula  += f"{final:.1f}"

        ts = TechniqueScore(
            technique=tech_id,
            name=name,
            count=count,
            tactic=tactic,
            tactic_id=tactic_id,
            tactic_score=tactic_score,
            sigma_severity=sigma_sev,
            sigma_score=sigma_score,
            base_score=base,
            freq_multiplier=freq_mult,
            final_score=final,
            risk_level=_score_label(final),
            why=why,
            formula=formula,
            sigma_rule_refs=refs,
        )
        technique_scores.append(ts)
        tech_component = max(tech_component, final)

    chain_mult     = _chain_multiplier(len(tech_counts))
    tech_component = min(tech_component * chain_mult, 100.0)

    # ── 3. Pattern contributions (derived from DB scores, not magic numbers) ──
    pattern_contributions: dict[str, float] = {}
    pattern_component = 0.0
    for p in patterns:
        score = _PATTERN_SCORE.get(p.pattern_type, _UNKNOWN_BASE)
        pattern_contributions[p.pattern_type] = round(score, 1)
        pattern_component = max(pattern_component, score)

    # ── 4. Global score: 60% technique + 40% pattern ─────────────────────────
    if patterns:
        global_raw = tech_component * 0.6 + pattern_component * 0.4
    else:
        global_raw = tech_component

    global_score = max(1, min(100, round(global_raw)))
    risk_level   = _score_label(global_score)

    # ── 5. Supporting data ────────────────────────────────────────────────────
    suspicious_nodes = sorted(
        [n for n in graph.nodes if n.is_suspicious],
        key=lambda n: n.risk_score, reverse=True,
    )[:10]
    top_entities = [
        {"id": n.id, "label": n.label, "type": n.type.value, "risk_score": n.risk_score}
        for n in suspicious_nodes
    ]

    total_events     = sum(n.event_count for n in graph.nodes if n.event_count)
    suspicious_count = sum(1 for n in graph.nodes if n.is_suspicious)

    scoring_note = (
        "Score = max(technique_finals) × chain_mult(0.6) "
        "+ max(pattern_scores)(0.4).  "
        "Technique base = tactic_score×0.4 + sigma_score×0.6.  "
        "Sources: MITRE ATT&CK v14 tactic weights, SigmaHQ community severity levels."
    )

    return RiskReport(
        global_score=global_score,
        risk_level=risk_level,
        technique_scores=sorted(technique_scores, key=lambda t: t.final_score, reverse=True),
        pattern_contributions=pattern_contributions,
        total_events=total_events,
        suspicious_events=suspicious_count,
        top_entities=top_entities,
        scoring_note=scoring_note,
    )
