import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.engine.technique_db import TECHNIQUE_DB, get, all_as_dict, _base
from backend.parsers import parse_logs
from backend.engine import build_graph
from backend.engine.risk_scorer import calculate_risk
from backend.engine.pattern_detector import detect_patterns

# ── DB integrity ──────────────────────────────────────────────────────────────

def test_all_techniques_have_required_fields():
    for tid, meta in TECHNIQUE_DB.items():
        assert meta.id == tid
        assert meta.name
        assert meta.tactic
        assert meta.tactic_id
        assert 0 < meta.tactic_score <= 100
        assert meta.sigma_severity in ("critical", "high", "medium", "low", "informational")
        assert 0 < meta.sigma_score <= 100
        assert meta.base_score > 0
        assert meta.why
        assert meta.sigma_rule_refs


def test_base_score_formula():
    """base_score must equal tactic*0.4 + sigma*0.6 for every entry."""
    for tid, meta in TECHNIQUE_DB.items():
        expected = round(meta.tactic_score * 0.4 + meta.sigma_score * 0.6, 1)
        assert abs(meta.base_score - expected) < 0.05, (
            f"{tid}: expected {expected}, got {meta.base_score}"
        )


def test_critical_techniques_score_above_75():
    for tid, meta in TECHNIQUE_DB.items():
        if meta.sigma_severity == "critical":
            assert meta.base_score > 75, f"{tid} critical but base={meta.base_score}"


def test_medium_techniques_score_below_high():
    mediums = [m for m in TECHNIQUE_DB.values() if m.sigma_severity == "medium"]
    highs   = [m for m in TECHNIQUE_DB.values() if m.sigma_severity == "high"]
    assert max(m.base_score for m in mediums) < max(m.base_score for m in highs)


def test_pth_is_highest_sigma():
    pth = get("T1550.002")
    assert pth.sigma_severity == "critical"
    assert pth.base_score > 80


def test_domain_accounts_critical():
    meta = get("T1078.002")
    assert meta.sigma_severity == "critical"


def test_rdp_medium_sigma():
    meta = get("T1021.001")
    assert meta.sigma_severity == "medium"


def test_powershell_higher_than_parent():
    ps  = get("T1059.001")
    cmd = get("T1059")
    assert ps.base_score > cmd.base_score


def test_get_unknown_returns_none():
    assert get("T9999.999") is None


def test_all_as_dict_keys():
    d = all_as_dict()
    assert "T1110" in d
    assert "formula" in d["T1110"]
    assert "why"     in d["T1110"]
    assert "sigma_severity" in d["T1110"]


# ── Scorer integration ────────────────────────────────────────────────────────

BRUTE_LOG = "\n\n".join([
    f"""EventID=4625
Date/Time=2024-01-15T10:2{i}:00Z
Account Name=administrator
Account Domain=CORP
Source Network Address=10.0.0.99
Logon Type=3"""
    for i in range(8)
])


def test_scorer_enriches_technique_scores():
    _, events = parse_logs(BRUTE_LOG)
    graph    = build_graph(events)
    patterns = detect_patterns(events)
    report   = calculate_risk(graph, patterns)

    ts = next((t for t in report.technique_scores if t.technique == "T1110"), None)
    assert ts is not None
    assert ts.name == "Brute Force"
    assert ts.tactic == "Credential Access"
    assert ts.sigma_severity == "high"
    assert ts.sigma_score == 72
    assert ts.tactic_score == 68
    assert ts.why
    assert ts.formula
    assert ts.sigma_rule_refs


def test_scorer_formula_in_output():
    _, events = parse_logs(BRUTE_LOG)
    graph    = build_graph(events)
    patterns = detect_patterns(events)
    report   = calculate_risk(graph, patterns)
    d        = report.to_dict()

    ts = next(t for t in d["technique_scores"] if t["technique"] == "T1110")
    assert "formula" in ts
    assert "70.4" in ts["formula"]  # (68×0.4)+(72×0.6)=70.4
    assert "scoring_note" in d


def test_freq_multiplier_increases_score():
    """Scores must be higher with more events (frequency multiplier active)."""
    few_log  = BRUTE_LOG          # 8 events
    many_log = "\n\n".join([
        f"""EventID=4625\nDate/Time=2024-01-15T10:{i:02d}:00Z
Account Name=administrator\nAccount Domain=CORP
Source Network Address=10.0.0.99\nLogon Type=3"""
        for i in range(25)
    ])
    _, ev1 = parse_logs(few_log)
    _, ev2 = parse_logs(many_log)
    r1 = calculate_risk(build_graph(ev1), detect_patterns(ev1))
    r2 = calculate_risk(build_graph(ev2), detect_patterns(ev2))
    t1 = next(t for t in r1.technique_scores if t.technique == "T1110")
    t2 = next(t for t in r2.technique_scores if t.technique == "T1110")
    assert t2.final_score >= t1.final_score


if __name__ == "__main__":
    tests = [v for k, v in globals().items() if k.startswith("test_")]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
            passed += 1
        except Exception as e:
            print(f"  FAIL  {t.__name__}: {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    if failed:
        sys.exit(1)
