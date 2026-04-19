import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.parsers import parse_logs
from backend.engine import build_graph
from backend.engine.pattern_detector import detect_patterns, DetectedPattern
from backend.engine.risk_scorer import calculate_risk

BRUTE_FORCE_LOG = "\n\n".join([
    f"""EventID=4625
Date/Time=2024-01-15T10:2{i}:00Z
Account Name=administrator
Account Domain=CORP
Source Network Address=10.0.0.99
Logon Type=3"""
    for i in range(8)
])

SPRAY_LOG = "\n\n".join([
    f"""EventID=4625
Date/Time=2024-01-15T10:0{i}:00Z
Account Name=user{i}
Account Domain=CORP
Source Network Address=10.0.0.77
Logon Type=3"""
    for i in range(5)
])

LATERAL_LOG = """
EventID=4624
Date/Time=2024-01-15T10:00:00Z
Account Name=jsmith
Account Domain=CORP
Source Network Address=192.168.1.10
Logon Type=10
Workstation Name=WS-001

EventID=4624
Date/Time=2024-01-15T10:05:00Z
Account Name=jsmith
Account Domain=CORP
Source Network Address=192.168.1.10
Logon Type=10
Workstation Name=WS-002
"""

PRIV_ESC_LOG = """
EventID=4624
Date/Time=2024-01-15T10:00:00Z
Account Name=jsmith
Account Domain=CORP
Source Network Address=203.0.113.5
Logon Type=10

EventID=4672
Date/Time=2024-01-15T10:01:00Z
Account Name=jsmith
Account Domain=CORP
"""


def test_detect_brute_force():
    _, events = parse_logs(BRUTE_FORCE_LOG)
    patterns = detect_patterns(events)
    bf = [p for p in patterns if p.pattern_type == "BRUTE_FORCE"]
    assert len(bf) >= 1
    assert "10.0.0.99" in bf[0].entities
    assert "T1110" in bf[0].mitre_techniques


def test_detect_spray_attack():
    _, events = parse_logs(SPRAY_LOG)
    patterns = detect_patterns(events)
    spray = [p for p in patterns if p.pattern_type == "SPRAY_ATTACK"]
    assert len(spray) >= 1
    assert "10.0.0.77" in spray[0].entities


def test_detect_lateral_movement():
    _, events = parse_logs(LATERAL_LOG)
    patterns = detect_patterns(events)
    lateral = [p for p in patterns if p.pattern_type == "LATERAL_MOVE"]
    assert len(lateral) >= 1
    assert "jsmith" in lateral[0].entities


def test_detect_priv_escalation():
    _, events = parse_logs(PRIV_ESC_LOG)
    patterns = detect_patterns(events)
    priv = [p for p in patterns if p.pattern_type == "PRIV_ESCALATION"]
    assert len(priv) >= 1


def test_risk_score_brute_force():
    _, events = parse_logs(BRUTE_FORCE_LOG)
    graph = build_graph(events)
    patterns = detect_patterns(events)
    report = calculate_risk(graph, patterns, events)
    assert report.global_score >= 26
    assert report.risk_level in ("MEDIUM", "HIGH", "CRITICAL")


def test_risk_score_high_for_spray():
    _, events = parse_logs(SPRAY_LOG)
    graph = build_graph(events)
    patterns = detect_patterns(events)
    report = calculate_risk(graph, patterns, events)
    assert report.global_score >= 50


def test_risk_report_to_dict():
    _, events = parse_logs(BRUTE_FORCE_LOG)
    graph = build_graph(events)
    patterns = detect_patterns(events)
    report = calculate_risk(graph, patterns, events)
    d = report.to_dict()
    assert "global_score" in d
    assert "risk_level" in d
    assert "technique_scores" in d


def test_pattern_to_dict():
    p = DetectedPattern(
        pattern_type="BRUTE_FORCE",
        description="Test",
        entities=["10.0.0.1"],
        severity="CRITICAL",
        mitre_techniques=["T1110"],
    )
    d = p.to_dict()
    assert d["pattern_type"] == "BRUTE_FORCE"
    assert "T1110" in d["mitre_techniques"]


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
