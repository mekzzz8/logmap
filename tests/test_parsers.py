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
