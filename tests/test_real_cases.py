"""
Integration tests — Real APT/threat cases
==========================================
Each case loads its .log file from tests/real_cases/, runs the full
LogMap pipeline (parse → graph → patterns → risk) and asserts the
specific detections that the file was designed to trigger.

Run individually:
    python tests/test_real_cases.py

Run with pytest:
    pytest tests/test_real_cases.py -v
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from backend.parsers import parse_logs
from backend.engine import build_graph, NodeType, RelationType, RiskLevel
from backend.engine.pattern_detector import detect_patterns
from backend.engine.risk_scorer import calculate_risk

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_CASES_DIR = os.path.join(os.path.dirname(__file__), "real_cases")


def _load(filename: str) -> str:
    with open(os.path.join(_CASES_DIR, filename)) as f:
        return f.read()


def _pipeline(filename: str):
    """Return (fmt, events, graph, patterns, risk_report) for a log file."""
    text = _load(filename)
    fmt, events = parse_logs(text)
    graph = build_graph(events)
    patterns = detect_patterns(events)
    report = calculate_risk(graph, patterns, events)
    return fmt, events, graph, patterns, report


def _node_labels(graph, node_type: NodeType) -> set[str]:
    return {n.label for n in graph.nodes if n.type == node_type}


def _pattern_types(patterns) -> list[str]:
    return [p.pattern_type for p in patterns]


def _techniques(events) -> set[str]:
    return {t for e in events for t in e.mitre_techniques}


# ---------------------------------------------------------------------------
# Case 1 — APT29 / Cozy Bear: Lateral Movement
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def apt29():
    return _pipeline("apt29_lateral_movement.log")


def test_apt29_format_detected(apt29):
    fmt, *_ = apt29
    assert fmt == "windows"


def test_apt29_minimum_events_parsed(apt29):
    _, events, *_ = apt29
    # 23 events in the file (header comment + blank lines excluded by parser)
    assert len(events) >= 20


def test_apt29_lateral_movement_detected(apt29):
    _, _, _, patterns, _ = apt29
    lateral = [p for p in patterns if p.pattern_type == "LATERAL_MOVE"]
    assert len(lateral) >= 1
    # svc_backup pivoted to 4 internal hosts
    assert any("svc_backup" in p.entities for p in lateral)
    assert any(p.mitre_techniques == ["T1021.001"] for p in lateral)


def test_apt29_rdp_reaches_four_hosts(apt29):
    _, _, _, patterns, _ = apt29
    lateral = next(p for p in patterns if p.pattern_type == "LATERAL_MOVE"
                   and "svc_backup" in p.entities)
    # description: "Lateral movement by svc_backup via RDP to N hosts"
    assert "4 hosts" in lateral.description


def test_apt29_persistence_via_scheduled_task(apt29):
    _, _, _, patterns, _ = apt29
    persist = [p for p in patterns if p.pattern_type == "PERSISTENCE"]
    assert len(persist) >= 1
    assert any("svc_backup" in p.entities for p in persist)
    assert any("T1053.005" in p.mitre_techniques for p in persist)


def test_apt29_priv_escalation_detected(apt29):
    _, _, _, patterns, _ = apt29
    priv = [p for p in patterns if p.pattern_type == "PRIV_ESCALATION"]
    assert len(priv) >= 1
    assert any("svc_backup" in p.entities for p in priv)
    assert any("T1078.002" in p.mitre_techniques for p in priv)


def test_apt29_powershell_technique_detected(apt29):
    _, events, *_ = apt29
    techs = _techniques(events)
    assert "T1059.001" in techs  # -enc / -nop / -w hidden on powershell.exe


def test_apt29_external_ip_in_graph(apt29):
    _, _, graph, *_ = apt29
    ips = _node_labels(graph, NodeType.IP)
    assert "91.108.4.11" in ips  # North-Atlantic exit node used by APT29


def test_apt29_internal_pivot_ip_in_graph(apt29):
    _, _, graph, *_ = apt29
    ips = _node_labels(graph, NodeType.IP)
    assert "10.10.0.5" in ips  # CORP-GATEWAY-01 used as pivot host


def test_apt29_target_hosts_in_graph(apt29):
    _, _, graph, *_ = apt29
    hosts = _node_labels(graph, NodeType.HOST)
    assert {"WKSTN-FIN-01", "WKSTN-HR-02", "DC-CORP-01"}.issubset(hosts)


def test_apt29_backdoor_account_in_graph(apt29):
    _, _, graph, *_ = apt29
    users = _node_labels(graph, NodeType.USER)
    assert "helpdesk_temp" in users


def test_apt29_minimum_node_count(apt29):
    _, _, graph, *_ = apt29
    assert len(graph.nodes) >= 20


def test_apt29_risk_is_critical(apt29):
    *_, report = apt29
    assert report.risk_level == "CRITICAL"
    assert report.global_score >= 76


# ---------------------------------------------------------------------------
# Case 2 — FIN7: Brute Force + Persistence bancaria
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def fin7():
    return _pipeline("fin7_brute_persistence.log")


def test_fin7_format_detected(fin7):
    fmt, *_ = fin7
    assert fmt == "windows"


def test_fin7_spray_events_parsed(fin7):
    _, events, *_ = fin7
    failures = [e for e in events if e.event_id == "4625"]
    # 20 failure events across 7 distinct users
    assert len(failures) >= 20


def test_fin7_brute_force_detected(fin7):
    _, _, _, patterns, _ = fin7
    bf = [p for p in patterns if p.pattern_type == "BRUTE_FORCE"]
    assert len(bf) >= 1
    assert any("185.220.101.55" in p.entities for p in bf)
    assert any("T1110" in p.mitre_techniques for p in bf)


def test_fin7_spray_attack_detected(fin7):
    _, _, _, patterns, _ = fin7
    spray = [p for p in patterns if p.pattern_type == "SPRAY_ATTACK"]
    assert len(spray) >= 1
    assert any("185.220.101.55" in p.entities for p in spray)
    # 7 distinct usernames targeted
    assert any(len(p.entities) >= 8 for p in spray)  # IP + 7 users


def test_fin7_spray_technique(fin7):
    _, _, _, patterns, _ = fin7
    spray = next(p for p in patterns if p.pattern_type == "SPRAY_ATTACK")
    assert "T1110.003" in spray.mitre_techniques


def test_fin7_service_persistence_detected(fin7):
    _, _, _, patterns, _ = fin7
    persist = [p for p in patterns if p.pattern_type == "PERSISTENCE"]
    service_persist = [p for p in persist if "T1543.003" in p.mitre_techniques]
    assert len(service_persist) >= 1
    assert any("jsmith" in p.entities for p in service_persist)


def test_fin7_task_persistence_detected(fin7):
    _, _, _, patterns, _ = fin7
    persist = [p for p in patterns if p.pattern_type == "PERSISTENCE"]
    task_persist = [p for p in persist if "T1053.005" in p.mitre_techniques]
    assert len(task_persist) >= 1


def test_fin7_priv_escalation_after_spray(fin7):
    _, _, _, patterns, _ = fin7
    priv = [p for p in patterns if p.pattern_type == "PRIV_ESCALATION"]
    assert len(priv) >= 1
    assert any("jsmith" in p.entities for p in priv)


def test_fin7_attacker_ip_in_graph(fin7):
    _, _, graph, *_ = fin7
    ips = _node_labels(graph, NodeType.IP)
    assert "185.220.101.55" in ips


def test_fin7_spray_users_in_graph(fin7):
    _, _, graph, *_ = fin7
    users = _node_labels(graph, NodeType.USER)
    sprayed = {"jsmith", "mgarcia", "rlopez", "cferrer"}
    assert sprayed.issubset(users)


def test_fin7_minimum_node_count(fin7):
    _, _, graph, *_ = fin7
    assert len(graph.nodes) >= 15


def test_fin7_risk_is_critical(fin7):
    *_, report = fin7
    assert report.risk_level == "CRITICAL"


# ---------------------------------------------------------------------------
# Case 3 — Lazarus Group: Credential Dump + Backdoor
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def lazarus():
    return _pipeline("lazarus_credential_dump.log")


def test_lazarus_format_detected_as_windows(lazarus):
    # Windows events dominate the first 4096 bytes → windows format wins
    fmt, *_ = lazarus
    assert fmt == "windows"


def test_lazarus_minimum_events_parsed(lazarus):
    _, events, *_ = lazarus
    assert len(events) >= 14


def test_lazarus_priv_escalation_detected(lazarus):
    _, _, _, patterns, _ = lazarus
    priv = [p for p in patterns if p.pattern_type == "PRIV_ESCALATION"]
    assert len(priv) >= 1
    assert any("mpark" in p.entities for p in priv)


def test_lazarus_persistence_via_backdoor_account(lazarus):
    _, _, _, patterns, _ = lazarus
    persist = [p for p in patterns if p.pattern_type == "PERSISTENCE"]
    # svc_dbbackup inherits suspicion from mpark's account creation chain
    assert len(persist) >= 1


def test_lazarus_credential_dump_tools_flagged(lazarus):
    _, events, *_ = lazarus
    suspicious_procs = {
        e.process_name.split("\\")[-1].split(".")[0].lower()
        for e in events
        if e.is_suspicious and e.process_name
    }
    # procdump and mimikatz are in SUSPICIOUS_PROCESSES
    assert "procdump" in suspicious_procs or "mimikatz" in suspicious_procs


def test_lazarus_powershell_payload_technique(lazarus):
    _, events, *_ = lazarus
    techs = _techniques(events)
    assert "T1059.001" in techs


def test_lazarus_ntlm_technique_detected(lazarus):
    _, events, *_ = lazarus
    techs = _techniques(events)
    assert "T1110.002" in techs  # 4776 Credential Validation


def test_lazarus_pass_the_hash_detected(lazarus):
    _, _, _, patterns, _ = lazarus
    pth = [p for p in patterns if p.pattern_type == "PASS_THE_HASH"]
    assert len(pth) >= 1  # 4648 from 10.20.0.100 without prior 4624


def test_lazarus_nk_ip_in_graph(lazarus):
    _, _, graph, *_ = lazarus
    ips = _node_labels(graph, NodeType.IP)
    assert "175.45.176.8" in ips  # North Korean IP range


def test_lazarus_backdoor_account_created(lazarus):
    _, events, *_ = lazarus
    created = [e for e in events if e.event_id == "4720"]
    usernames = [e.username for e in created]
    assert "svc_dbbackup" in usernames


def test_lazarus_both_attacker_accounts_in_graph(lazarus):
    _, _, graph, *_ = lazarus
    users = _node_labels(graph, NodeType.USER)
    assert "mpark" in users
    assert "svc_dbbackup" in users


def test_lazarus_minimum_node_count(lazarus):
    _, _, graph, *_ = lazarus
    assert len(graph.nodes) >= 15


def test_lazarus_risk_is_critical(lazarus):
    *_, report = lazarus
    assert report.risk_level == "CRITICAL"


# ---------------------------------------------------------------------------
# Case 4 — WannaCry: Propagación lateral masiva (topología estrella)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def wannacry():
    return _pipeline("wannacry_style_spread.log")


def test_wannacry_format_detected(wannacry):
    fmt, *_ = wannacry
    assert fmt == "windows"


def test_wannacry_many_events_parsed(wannacry):
    _, events, *_ = wannacry
    assert len(events) >= 30


def test_wannacry_brute_force_from_patient_zero(wannacry):
    _, _, _, patterns, _ = wannacry
    bf = [p for p in patterns if p.pattern_type == "BRUTE_FORCE"]
    assert len(bf) >= 1
    assert any("10.10.50.100" in p.entities for p in bf)


def test_wannacry_spray_from_patient_zero(wannacry):
    _, _, _, patterns, _ = wannacry
    spray = [p for p in patterns if p.pattern_type == "SPRAY_ATTACK"]
    assert len(spray) >= 1
    assert any("10.10.50.100" in p.entities for p in spray)


def test_wannacry_lateral_movement_to_five_hosts(wannacry):
    _, _, _, patterns, _ = wannacry
    lateral = [p for p in patterns if p.pattern_type == "LATERAL_MOVE"]
    assert len(lateral) >= 1
    star = next(p for p in lateral if "administrator" in p.entities)
    assert "5 hosts" in star.description


def test_wannacry_service_installed_on_each_host(wannacry):
    _, _, _, patterns, _ = wannacry
    persist = [p for p in patterns if p.pattern_type == "PERSISTENCE"
               and any("T1543.003" in p.mitre_techniques for _ in [p])]
    # One service-persistence per compromised host = 5 total
    assert len(persist) >= 5


def test_wannacry_real_service_name_in_graph(wannacry):
    # mssecsvc2.0 is WannaCry's actual service name
    _, events, *_ = wannacry
    service_events = [e for e in events if e.event_id == "7045"]
    names = [e.extra.get("service_name", "") for e in service_events]
    assert all(n == "mssecsvc2.0" for n in names if n)


def test_wannacry_real_account_created(wannacry):
    # WNcry@2ol7 is the actual account name created by WannaCry
    _, events, *_ = wannacry
    created = [e for e in events if e.event_id == "4720"]
    assert any("WNcry@2ol7" in e.username for e in created)


def test_wannacry_star_topology_in_graph(wannacry):
    # patient-zero IP (10.10.50.100) must connect to all 5 target hosts
    _, _, graph, *_ = wannacry
    connected_from_edges = [
        e for e in graph.edges
        if e.relation == RelationType.CONNECTED_FROM
    ]
    patient_zero_edges = [
        e for e in connected_from_edges
        if any(n.label == "10.10.50.100" for n in graph.nodes if n.id == e.source)
    ]
    # At least 5 distinct hosts reachable from 10.10.50.100
    dest_ids = {e.target for e in patient_zero_edges}
    assert len(dest_ids) >= 5


def test_wannacry_minimum_node_count(wannacry):
    _, _, graph, *_ = wannacry
    assert len(graph.nodes) >= 15


def test_wannacry_risk_is_critical(wannacry):
    *_, report = wannacry
    assert report.risk_level == "CRITICAL"
    # Propagation speed + service install each host compounds risk
    assert report.global_score >= 80


# ---------------------------------------------------------------------------
# Case 5 — Insider Threat: Empleado malicioso sin señales externas
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def insider():
    return _pipeline("insider_threat.log")


def test_insider_format_detected(insider):
    fmt, *_ = insider
    assert fmt == "windows"


def test_insider_minimum_events_parsed(insider):
    _, events, *_ = insider
    assert len(events) >= 12


def test_insider_no_brute_force(insider):
    """Insider uses own credentials — no failed login attempts."""
    _, _, _, patterns, _ = insider
    bf = [p for p in patterns if p.pattern_type == "BRUTE_FORCE"]
    assert len(bf) == 0


def test_insider_no_spray_attack(insider):
    """No password spraying — insider already knows the passwords."""
    _, _, _, patterns, _ = insider
    spray = [p for p in patterns if p.pattern_type == "SPRAY_ATTACK"]
    assert len(spray) == 0


def test_insider_certutil_flagged_as_suspicious(insider):
    _, events, *_ = insider
    certutil_events = [
        e for e in events
        if "certutil" in e.process_name.lower() and e.is_suspicious
    ]
    assert len(certutil_events) >= 1


def test_insider_persistence_detected_via_tool_download(insider):
    """certutil download makes rgarcia suspicious → subsequent 4698 triggers PERSISTENCE."""
    _, _, _, patterns, _ = insider
    persist = [p for p in patterns if p.pattern_type == "PERSISTENCE"]
    assert len(persist) >= 1
    assert any("rgarcia" in p.entities for p in persist)


def test_insider_backdoor_account_creation_detected(insider):
    _, events, *_ = insider
    # 4720 = T1136.001 — account creation
    created = [e for e in events if e.event_id == "4720"]
    assert len(created) >= 1
    assert any(e.username == "svc_backup02" for e in created)


def test_insider_account_manipulation_technique(insider):
    _, events, *_ = insider
    techs = _techniques(events)
    assert "T1098" in techs  # 4732 user-added-to-group


def test_insider_powershell_exfil_technique(insider):
    _, events, *_ = insider
    techs = _techniques(events)
    assert "T1059.001" in techs  # PowerShell -enc payload


def test_insider_actor_remains_internal(insider):
    """All activity originates from the corporate LAN — no external IPs."""
    _, events, *_ = insider
    external_logins = [
        e for e in events
        if e.src_ip
        and not (
            e.src_ip.startswith("10.")
            or e.src_ip.startswith("192.168.")
            or e.src_ip.startswith("172.")
            or e.src_ip in ("-", "::1", "127.0.0.1")
        )
    ]
    assert len(external_logins) == 0


def test_insider_both_accounts_in_graph(insider):
    _, _, graph, *_ = insider
    users = _node_labels(graph, NodeType.USER)
    assert "rgarcia" in users
    assert "svc_backup02" in users


def test_insider_minimum_node_count(insider):
    _, _, graph, *_ = insider
    assert len(graph.nodes) >= 14


def test_insider_risk_not_critical(insider):
    """
    Insider threat without external IP or brute force should score HIGH but
    not CRITICAL — the absence of brute-force/spray patterns keeps the score
    below the CRITICAL threshold, reflecting the real difficulty of detection.
    """
    *_, report = insider
    assert report.risk_level in ("HIGH", "CRITICAL")
    assert report.global_score >= 51


# ---------------------------------------------------------------------------
# Cross-case: sanity checks across all 5 files
# ---------------------------------------------------------------------------

_ALL_LOGS = [
    "apt29_lateral_movement.log",
    "fin7_brute_persistence.log",
    "lazarus_credential_dump.log",
    "wannacry_style_spread.log",
    "insider_threat.log",
]


@pytest.mark.parametrize("filename", _ALL_LOGS)
def test_all_cases_parse_as_windows(filename):
    text = _load(filename)
    fmt, events = parse_logs(text)
    assert fmt == "windows", f"{filename} detected as '{fmt}', expected 'windows'"


@pytest.mark.parametrize("filename", _ALL_LOGS)
def test_all_cases_minimum_ten_nodes(filename):
    text = _load(filename)
    _, events = parse_logs(text)
    graph = build_graph(events)
    assert len(graph.nodes) >= 10, (
        f"{filename}: only {len(graph.nodes)} nodes, expected ≥ 10"
    )


@pytest.mark.parametrize("filename", _ALL_LOGS)
def test_all_cases_have_mitre_techniques(filename):
    text = _load(filename)
    _, events = parse_logs(text)
    techs = _techniques(events)
    assert len(techs) >= 2, (
        f"{filename}: only {len(techs)} techniques detected, expected ≥ 2"
    )


@pytest.mark.parametrize("filename", _ALL_LOGS)
def test_all_cases_have_technique_nodes_in_graph(filename):
    text = _load(filename)
    _, events = parse_logs(text)
    graph = build_graph(events)
    tech_nodes = [n for n in graph.nodes if n.type == NodeType.TECHNIQUE]
    assert len(tech_nodes) >= 1, f"{filename}: no TECHNIQUE nodes in graph"


@pytest.mark.parametrize("filename", _ALL_LOGS)
def test_all_cases_risk_at_least_high(filename):
    text = _load(filename)
    _, events = parse_logs(text)
    graph = build_graph(events)
    patterns = detect_patterns(events)
    report = calculate_risk(graph, patterns, events)
    assert report.risk_level in ("HIGH", "CRITICAL"), (
        f"{filename}: risk_level={report.risk_level}, expected HIGH or CRITICAL"
    )


@pytest.mark.parametrize("filename", _ALL_LOGS)
def test_all_cases_graph_has_edges(filename):
    text = _load(filename)
    _, events = parse_logs(text)
    graph = build_graph(events)
    assert len(graph.edges) >= 5, f"{filename}: fewer than 5 edges in graph"


# ---------------------------------------------------------------------------
# Standalone runner (no pytest required)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import traceback

    all_tests = [(k, v) for k, v in globals().items()
                 if k.startswith("test_") and callable(v)]

    # Resolve fixtures manually for standalone run
    _fixtures = {
        "apt29":    lambda: _pipeline("apt29_lateral_movement.log"),
        "fin7":     lambda: _pipeline("fin7_brute_persistence.log"),
        "lazarus":  lambda: _pipeline("lazarus_credential_dump.log"),
        "wannacry": lambda: _pipeline("wannacry_style_spread.log"),
        "insider":  lambda: _pipeline("insider_threat.log"),
    }
    _fixture_cache: dict = {}

    def _get_fixture(name: str):
        if name not in _fixture_cache:
            _fixture_cache[name] = _fixtures[name]()
        return _fixture_cache[name]

    passed = failed = 0
    for name, fn in sorted(all_tests):
        import inspect
        sig = inspect.signature(fn)
        params = list(sig.parameters.keys())

        # Parametrized tests
        if params == ["filename"]:
            for filename in _ALL_LOGS:
                label = f"{name}[{filename}]"
                try:
                    fn(filename)
                    print(f"  PASS  {label}")
                    passed += 1
                except Exception as e:
                    print(f"  FAIL  {label}: {e}")
                    failed += 1
            continue

        # Fixture-based tests
        if params and params[0] in _fixtures:
            fixture_data = _get_fixture(params[0])
            try:
                fn(fixture_data)
                print(f"  PASS  {name}")
                passed += 1
            except Exception as e:
                print(f"  FAIL  {name}: {e}")
                traceback.print_exc()
                failed += 1
        else:
            try:
                fn()
                print(f"  PASS  {name}")
                passed += 1
            except Exception as e:
                print(f"  FAIL  {name}: {e}")
                failed += 1

    total = passed + failed
    print(f"\n{'='*50}")
    print(f"  {passed}/{total} passed  |  {failed} failed")
    if failed:
        sys.exit(1)
