import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.parsers import parse_logs, detect_format
from backend.parsers.base_model import EventSeverity

WINDOWS_SAMPLE = """
EventID=4625
Date/Time=2024-01-15T10:23:41Z
Account Name=administrator
Account Domain=CORP
Source Network Address=192.168.1.45
Logon Type=3
Failure Reason=Unknown user name or bad password

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
Jan 15 10:26:00 server1 sshd[1236]: Invalid user hacker from 203.0.113.5
"""

SYSLOG_SAMPLE = """
Jan 15 10:00:00 server1 kernel: EXT4-fs error (device sda1): ext4_find_entry:1455
<38>Jan 15 10:01:00 server1 sshd[999]: Failed password for root from 10.0.0.1 port 22 ssh2
<134>1 2024-01-15T10:02:00Z myhost app 123 ID47 - This is a test message with IP 192.168.1.1
"""


def test_detect_windows():
    assert detect_format(WINDOWS_SAMPLE) == "windows"


def test_detect_auth():
    assert detect_format(AUTH_SAMPLE) == "auth"


def test_detect_syslog():
    assert detect_format(SYSLOG_SAMPLE) == "syslog"


def test_windows_parse_events():
    fmt, events = parse_logs(WINDOWS_SAMPLE)
    assert fmt == "windows"
    assert len(events) >= 3
    ids = [e.event_id for e in events]
    assert "4625" in ids
    assert "4624" in ids
    assert "4688" in ids


def test_windows_brute_force_suspicious():
    fmt, events = parse_logs(WINDOWS_SAMPLE)
    failed = [e for e in events if e.event_id == "4625"]
    assert failed[0].is_suspicious
    assert "T1110" in failed[0].mitre_techniques


def test_windows_powershell_suspicious():
    fmt, events = parse_logs(WINDOWS_SAMPLE)
    ps = [e for e in events if e.event_id == "4688"]
    assert ps[0].is_suspicious
    assert "T1059.001" in ps[0].mitre_techniques


def test_auth_parse():
    fmt, events = parse_logs(AUTH_SAMPLE)
    assert fmt == "auth"
    assert len(events) >= 5


def test_auth_failed_ssh():
    _, events = parse_logs(AUTH_SAMPLE)
    failed = [e for e in events if "Failed" in e.description]
    assert len(failed) >= 2
    assert failed[0].src_ip == "10.0.0.1"
    assert "T1110" in failed[0].mitre_techniques
    assert failed[0].is_suspicious


def test_auth_sudo():
    _, events = parse_logs(AUTH_SAMPLE)
    sudo_events = [e for e in events if "Sudo" in e.description]
    assert len(sudo_events) >= 1
    assert "T1548.003" in sudo_events[0].mitre_techniques


def test_syslog_parse():
    fmt, events = parse_logs(SYSLOG_SAMPLE)
    assert fmt == "syslog"
    assert len(events) >= 1


def test_fallback_unknown():
    fmt, events = parse_logs("This is not a log file at all.")
    # Should return something (fallback) without crashing
    assert isinstance(events, list)


# ─── Wazuh tests ──────────────────────────────────────────────────────────────

WAZUH_JSON_LINES = """\
{"timestamp":"2024-01-12T08:34:01.123Z","rule":{"id":"5710","level":10,"description":"SSH brute force attack"},"agent":{"id":"001","name":"server-prod"},"data":{"srcip":"192.168.1.45","dstuser":"root"},"full_log":"Jan 12 sshd[1234]: Failed password for root from 192.168.1.45"}
{"timestamp":"2024-01-12T08:34:05.000Z","rule":{"id":"5401","level":8,"description":"sudo: authentication failure"},"agent":{"id":"001","name":"server-prod"},"data":{"srcip":"10.0.0.5","dstuser":"jsmith"},"full_log":"Jan 12 sudo: jsmith failed"}
{"timestamp":"2024-01-12T08:35:00.000Z","rule":{"id":"9999","level":3,"description":"Informational event"},"agent":{"id":"002","name":"server-dev"},"data":{},"full_log":"Jan 12 app: startup"}
"""

WAZUH_JSON_ARRAY = """[
  {"timestamp":"2024-01-12T08:34:01.123Z","rule":{"id":"5710","level":14,"description":"SSH brute force critical"},"agent":{"id":"001","name":"web-01"},"data":{"srcip":"203.0.113.1","dstuser":"admin"},"full_log":"brute force"},
  {"timestamp":"2024-01-12T08:34:02.000Z","rule":{"id":"60122","level":12,"description":"Pass-the-hash detected"},"agent":{"id":"002","name":"web-02"},"data":{"srcip":"10.0.1.5"},"full_log":"pth event"}
]"""


def test_wazuh_detect_jsonlines():
    fmt = detect_format(WAZUH_JSON_LINES)
    assert fmt == "wazuh"


def test_wazuh_detect_jsonarray():
    fmt = detect_format(WAZUH_JSON_ARRAY)
    assert fmt == "wazuh"


def test_wazuh_parse_jsonlines():
    fmt, events = parse_logs(WAZUH_JSON_LINES)
    assert fmt == "wazuh"
    assert len(events) == 3


def test_wazuh_parse_jsonarray():
    fmt, events = parse_logs(WAZUH_JSON_ARRAY)
    assert fmt == "wazuh"
    assert len(events) == 2


def test_wazuh_severity_mapping():
    _, events = parse_logs(WAZUH_JSON_LINES)
    # rule level 10 → MEDIUM
    brute = next(e for e in events if e.event_id == "5710")
    assert brute.severity.value == "MEDIUM"
    # rule level 3 → LOW
    info = next(e for e in events if e.event_id == "9999")
    assert info.severity.value == "LOW"


def test_wazuh_critical_severity():
    _, events = parse_logs(WAZUH_JSON_ARRAY)
    critical = next(e for e in events if e.event_id == "5710")
    assert critical.severity.value == "CRITICAL"


def test_wazuh_brute_force_mitre():
    _, events = parse_logs(WAZUH_JSON_LINES)
    brute = next(e for e in events if e.event_id == "5710")
    assert "T1110" in brute.mitre_techniques
    assert brute.is_suspicious


def test_wazuh_sudo_mitre():
    _, events = parse_logs(WAZUH_JSON_LINES)
    sudo_ev = next(e for e in events if e.event_id == "5401")
    assert "T1548.003" in sudo_ev.mitre_techniques


def test_wazuh_pass_the_hash_mitre():
    _, events = parse_logs(WAZUH_JSON_ARRAY)
    pth = next(e for e in events if e.event_id == "60122")
    assert "T1550.002" in pth.mitre_techniques
    assert pth.is_suspicious


def test_wazuh_src_ip_extracted():
    _, events = parse_logs(WAZUH_JSON_LINES)
    brute = next(e for e in events if e.event_id == "5710")
    assert brute.src_ip == "192.168.1.45"


def test_wazuh_agent_name_as_source():
    _, events = parse_logs(WAZUH_JSON_LINES)
    assert events[0].source == "server-prod"


def test_wazuh_low_level_not_suspicious():
    _, events = parse_logs(WAZUH_JSON_LINES)
    info = next(e for e in events if e.event_id == "9999")
    assert not info.is_suspicious


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
