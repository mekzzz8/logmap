import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.parsers import parse_logs
from backend.engine import build_graph, NodeType, RelationType, RiskLevel

WINDOWS_SAMPLE = """
EventID=4625
Date/Time=2024-01-15T10:23:41Z
Account Name=administrator
Account Domain=CORP
Source Network Address=192.168.1.45
Logon Type=3

EventID=4625
Date/Time=2024-01-15T10:23:42Z
Account Name=administrator
Account Domain=CORP
Source Network Address=192.168.1.45
Logon Type=3

EventID=4624
Date/Time=2024-01-15T10:25:00Z
Account Name=jsmith
Account Domain=CORP
Source Network Address=192.168.1.45
Logon Type=10
Workstation Name=WS-001

EventID=4688
Date/Time=2024-01-15T10:25:30Z
Account Name=jsmith
New Process Name=C:\\Windows\\System32\\powershell.exe -enc ZQBjAGgAbwA=
New Process ID=0x1234
Creator Process Name=C:\\Windows\\explorer.exe
"""

AUTH_SAMPLE = """
Jan 15 10:23:41 server1 sshd[1234]: Failed password for root from 10.0.0.1 port 22 ssh2
Jan 15 10:23:42 server1 sshd[1234]: Failed password for root from 10.0.0.1 port 22 ssh2
Jan 15 10:24:00 server1 sshd[1235]: Accepted password for jsmith from 10.0.0.2 port 22 ssh2
Jan 15 10:25:00 server1 sudo:   jsmith : TTY=pts/0 ; PWD=/home/jsmith ; USER=root ; COMMAND=/bin/bash
"""


def test_graph_has_nodes():
    _, events = parse_logs(WINDOWS_SAMPLE)
    graph = build_graph(events)
    assert len(graph.nodes) > 0


def test_graph_has_edges():
    _, events = parse_logs(WINDOWS_SAMPLE)
    graph = build_graph(events)
    assert len(graph.edges) > 0


def test_ip_node_exists():
    _, events = parse_logs(WINDOWS_SAMPLE)
    graph = build_graph(events)
    ip_nodes = [n for n in graph.nodes if n.type == NodeType.IP]
    assert any(n.label == "192.168.1.45" for n in ip_nodes)


def test_user_node_exists():
    _, events = parse_logs(WINDOWS_SAMPLE)
    graph = build_graph(events)
    user_nodes = [n for n in graph.nodes if n.type == NodeType.USER]
    labels = [n.label for n in user_nodes]
    assert "administrator" in labels or "jsmith" in labels


def test_technique_node_exists():
    _, events = parse_logs(WINDOWS_SAMPLE)
    graph = build_graph(events)
    tech_nodes = [n for n in graph.nodes if n.type == NodeType.TECHNIQUE]
    labels = [n.label for n in tech_nodes]
    assert "T1110" in labels


def test_edges_authenticated_as():
    _, events = parse_logs(WINDOWS_SAMPLE)
    graph = build_graph(events)
    rels = [e.relation for e in graph.edges]
    assert RelationType.AUTHENTICATED_AS in rels


def test_edges_maps_to():
    _, events = parse_logs(WINDOWS_SAMPLE)
    graph = build_graph(events)
    rels = [e.relation for e in graph.edges]
    assert RelationType.MAPS_TO in rels


def test_event_count_accumulates():
    _, events = parse_logs(WINDOWS_SAMPLE)
    graph = build_graph(events)
    ip_nodes = [n for n in graph.nodes if n.type == NodeType.IP and n.label == "192.168.1.45"]
    assert ip_nodes[0].event_count >= 3


def test_suspicious_flag_sticky():
    _, events = parse_logs(WINDOWS_SAMPLE)
    graph = build_graph(events)
    ip_nodes = [n for n in graph.nodes if n.type == NodeType.IP and n.label == "192.168.1.45"]
    assert ip_nodes[0].is_suspicious


def test_risk_not_decreasing():
    _, events = parse_logs(WINDOWS_SAMPLE)
    graph = build_graph(events)
    # IP 192.168.1.45 sent failed logons → should be at least MEDIUM
    ip = [n for n in graph.nodes if n.label == "192.168.1.45"][0]
    assert ip.risk_level in (RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL)


def test_edge_weight_accumulates():
    _, events = parse_logs(WINDOWS_SAMPLE)
    graph = build_graph(events)
    auth_edges = [e for e in graph.edges if e.relation == RelationType.AUTHENTICATED_AS]
    assert any(e.weight >= 2 for e in auth_edges)


def test_auth_graph():
    _, events = parse_logs(AUTH_SAMPLE)
    graph = build_graph(events)
    assert len(graph.nodes) > 0
    ip_nodes = [n for n in graph.nodes if n.type == NodeType.IP]
    assert any(n.label == "10.0.0.1" for n in ip_nodes)


def test_to_dict():
    _, events = parse_logs(WINDOWS_SAMPLE)
    graph = build_graph(events)
    d = graph.to_dict()
    assert "nodes" in d and "edges" in d
    assert isinstance(d["nodes"], list)
    assert isinstance(d["edges"], list)


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
