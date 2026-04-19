#!/usr/bin/env python3
"""LogMap — Blue Team Log Analyzer CLI."""
from __future__ import annotations

import sys
import os

# Allow running from repo root without install
sys.path.insert(0, os.path.dirname(__file__))

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.rule import Rule
from rich import box

from backend.parsers import parse_logs
from backend.parsers.base_model import EventSeverity
from backend.engine import build_graph
from backend.engine.pattern_detector import detect_patterns
from backend.engine.risk_scorer import calculate_risk
from backend.engine.graph_model import NodeType, RiskLevel

console = Console()

_RISK_COLOR = {
    "LOW": "green",
    "MEDIUM": "yellow",
    "HIGH": "red",
    "CRITICAL": "bold red",
}

_SEV_COLOR = {
    "LOW": "green",
    "MEDIUM": "yellow",
    "HIGH": "red",
    "CRITICAL": "bold red",
}

_MITRE_NAMES = {
    "T1110":     "Brute Force",
    "T1110.002": "Password Cracking",
    "T1110.003": "Password Spraying",
    "T1078":     "Valid Accounts",
    "T1078.002": "Domain Accounts",
    "T1550.002": "Pass-the-Hash",
    "T1059":     "Command & Scripting",
    "T1059.001": "PowerShell",
    "T1053.005": "Scheduled Task",
    "T1543.003": "New Service",
    "T1136.001": "Create Account",
    "T1098":     "Account Manipulation",
    "T1548.003": "Sudo Escalation",
    "T1021.001": "RDP Lateral Move",
}

_RECOMMENDATIONS: dict[str, list[str]] = {
    "T1110":     ["Enable account lockout policy", "Block offending IPs at firewall"],
    "T1110.003": ["Require MFA on all accounts", "Alert on >3 failures/user in 1h"],
    "T1078":     ["Reset compromised account credentials", "Review privileged account activity"],
    "T1550.002": ["Enable Protected Users security group", "Audit NTLM usage"],
    "T1059.001": ["Restrict PowerShell execution policy", "Enable Script Block Logging"],
    "T1053.005": ["Audit scheduled tasks", "Alert on new task creation"],
    "T1543.003": ["Audit new services", "Restrict service installation permissions"],
    "T1548.003": ["Audit sudoers file", "Enable sudo logging"],
    "T1021.001": ["Restrict RDP access", "Enable NLA for RDP"],
    "BRUTE_FORCE":    ["Block IPs exceeding failed-login threshold"],
    "SPRAY_ATTACK":   ["Enable smart lockout", "Deploy Credential Guard"],
    "PASS_THE_HASH":  ["Disable NTLM", "Enable Protected Users group"],
    "LATERAL_MOVE":   ["Segment network, restrict RDP", "Deploy endpoint detection"],
    "PERSISTENCE":    ["Audit task/service creation", "Enable application whitelisting"],
    "PRIV_ESCALATION":["Review privileged account activity", "Implement just-in-time access"],
}


def _bar(value: int, max_val: int, width: int = 12) -> str:
    if max_val == 0:
        return " " * width
    filled = int(width * value / max_val)
    return "█" * filled + "░" * (width - filled)


def _risk_style(level: str) -> str:
    return _RISK_COLOR.get(level, "white")


def _print_header(fmt: str, total: int, suspicious: int, score: int, risk: str) -> None:
    color = _risk_style(risk)
    console.print()
    console.print(Panel(
        f"[bold cyan]LOGMAP — ANALYSIS REPORT[/bold cyan]",
        box=box.DOUBLE,
        expand=False,
    ))
    console.print(f"  Format    : [bold]{fmt.upper()}[/bold]")
    console.print(f"  Events    : [bold]{total:,}[/bold]")
    console.print(f"  Suspicious: [bold yellow]{suspicious:,}[/bold yellow]")
    console.print(f"  Risk Score: [{color}]{score}/100 {risk}[/{color}]")
    console.print()


def _print_attack_graph(graph, events) -> None:
    console.print(Rule("[bold]ATTACK GRAPH[/bold]"))

    from collections import defaultdict
    from backend.engine.graph_model import RelationType

    # Build adjacency for text rendering
    edge_map: dict[str, list] = defaultdict(list)
    node_map = {n.id: n for n in graph.nodes}

    for edge in graph.edges:
        edge_map[edge.source].append(edge)

    # Start from IP nodes
    ip_nodes = [n for n in graph.nodes if n.type == NodeType.IP]
    ip_nodes.sort(key=lambda n: n.risk_score, reverse=True)

    printed = set()

    def _node_label(node) -> str:
        color = _risk_style(node.risk_level.value if hasattr(node.risk_level, 'value') else node.risk_level)
        return f"[{color}]{node.label}[/{color}] ([dim]{node.type.value}[/dim])"

    def _print_node(node, prefix: str = "", depth: int = 0) -> None:
        if node.id in printed or depth > 4:
            return
        printed.add(node.id)

        label = _node_label(node)
        console.print(f"{prefix}{label}")

        children = edge_map.get(node.id, [])
        for i, edge in enumerate(children[:6]):
            target = node_map.get(edge.target)
            if not target or target.id in printed:
                continue
            is_last = i == len(children) - 1
            connector = "└──" if is_last else "├──"
            rel_color = "red" if edge.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL) else "dim"
            rel_str = f"[{rel_color}][{edge.relation.value} x{edge.weight}][/{rel_color}]"
            console.print(f"{prefix}  {connector}{rel_str}──► ", end="")
            _print_node(target, prefix + ("       " if is_last else "  │    "), depth + 1)

    for ip in ip_nodes[:5]:
        _print_node(ip)
        console.print()


def _print_mitre(technique_scores) -> None:
    console.print(Rule("[bold]MITRE TECHNIQUES[/bold]"))
    if not technique_scores:
        console.print("  [dim]No techniques detected[/dim]")
        return

    max_count = max((t.count for t in technique_scores), default=1)
    table = Table(box=None, show_header=True, header_style="bold")
    table.add_column("ID", style="cyan", width=12)
    table.add_column("Name", width=24)
    table.add_column("Count", justify="right", width=8)
    table.add_column("Frequency", width=14)
    table.add_column("Risk", width=10)

    for ts in technique_scores[:15]:
        name = _MITRE_NAMES.get(ts.technique, "Unknown")
        bar = _bar(ts.count, max_count)
        color = _risk_style(ts.risk_level)
        table.add_row(
            ts.technique,
            name,
            str(ts.count),
            bar,
            f"[{color}]{ts.risk_level}[/{color}]",
        )
    console.print(table)
    console.print()


def _print_top_ips(graph, events) -> None:
    console.print(Rule("[bold]TOP SUSPICIOUS IPs[/bold]"))
    ip_nodes = [n for n in graph.nodes if n.type == NodeType.IP and n.is_suspicious]
    ip_nodes.sort(key=lambda n: n.risk_score, reverse=True)

    if not ip_nodes:
        console.print("  [dim]No suspicious IPs detected[/dim]")
    else:
        table = Table(box=None, show_header=True, header_style="bold")
        table.add_column("IP Address", width=18)
        table.add_column("Events", justify="right", width=8)
        table.add_column("Techniques", width=30)
        table.add_column("Risk", width=10)

        for n in ip_nodes[:10]:
            color = _risk_style(n.risk_level.value if hasattr(n.risk_level, 'value') else str(n.risk_level))
            table.add_row(
                n.label,
                str(n.event_count),
                ", ".join(n.mitre_techniques[:4]),
                f"[{color}]{n.risk_level.value if hasattr(n.risk_level, 'value') else n.risk_level}[/{color}]",
            )
        console.print(table)
    console.print()


def _print_top_users(graph) -> None:
    console.print(Rule("[bold]TOP SUSPICIOUS USERS[/bold]"))
    user_nodes = [n for n in graph.nodes if n.type == NodeType.USER and n.is_suspicious]
    user_nodes.sort(key=lambda n: n.risk_score, reverse=True)

    if not user_nodes:
        console.print("  [dim]No suspicious users detected[/dim]")
    else:
        table = Table(box=None, show_header=True, header_style="bold")
        table.add_column("Username", width=20)
        table.add_column("Events", justify="right", width=8)
        table.add_column("Techniques", width=30)
        table.add_column("Risk", width=10)

        for n in user_nodes[:10]:
            color = _risk_style(n.risk_level.value if hasattr(n.risk_level, 'value') else str(n.risk_level))
            table.add_row(
                n.label,
                str(n.event_count),
                ", ".join(n.mitre_techniques[:4]),
                f"[{color}]{n.risk_level.value if hasattr(n.risk_level, 'value') else n.risk_level}[/{color}]",
            )
        console.print(table)
    console.print()


def _print_timeline(events, limit: int = 15) -> None:
    console.print(Rule("[bold]ATTACK CHAIN (Timeline)[/bold]"))
    suspicious = [e for e in events if e.is_suspicious and e.timestamp]
    suspicious.sort(key=lambda e: e.timestamp)

    if not suspicious:
        console.print("  [dim]No timestamped suspicious events[/dim]")
        return

    for e in suspicious[:limit]:
        ts = e.timestamp.strftime("%Y-%m-%d %H:%M:%S") if e.timestamp else "N/A"
        color = _SEV_COLOR.get(e.severity.value if hasattr(e.severity, 'value') else e.severity, "white")
        techs = " ".join(f"[cyan]{t}[/cyan]" for t in e.mitre_techniques[:3])
        ip = f"[dim]{e.src_ip}[/dim] → " if e.src_ip else ""
        user = f"[yellow]{e.username}[/yellow] " if e.username else ""
        console.print(
            f"  [dim]{ts}[/dim]  [{color}]{e.event_id or e.source}[/{color}]  "
            f"{ip}{user}{e.description[:60]}  {techs}"
        )
    console.print()


def _print_patterns(patterns) -> None:
    if not patterns:
        return
    console.print(Rule("[bold]DETECTED ATTACK PATTERNS[/bold]"))
    for p in patterns:
        color = _risk_style(p.severity)
        techs = ", ".join(p.mitre_techniques)
        console.print(
            f"  [{color}][{p.pattern_type}][/{color}]  {p.description}  "
            f"[cyan]{techs}[/cyan]"
        )
    console.print()


def _print_recommendations(report, patterns) -> None:
    console.print(Rule("[bold]RECOMMENDATIONS[/bold]"))
    recs: list[str] = []

    seen: set[str] = set()
    for ts in report.technique_scores[:5]:
        for r in _RECOMMENDATIONS.get(ts.technique, []):
            if r not in seen:
                recs.append(r)
                seen.add(r)

    for p in patterns:
        for r in _RECOMMENDATIONS.get(p.pattern_type, []):
            if r not in seen:
                recs.append(r)
                seen.add(r)

    if not recs:
        recs = ["Continue monitoring for anomalous activity"]

    for i, rec in enumerate(recs[:8], 1):
        console.print(f"  [[bold cyan]{i}[/bold cyan]] {rec}")
    console.print()


def _apply_filters(events, severity_filter, mitre_filter):
    filtered = events
    if severity_filter:
        target = severity_filter.upper()
        filtered = [e for e in filtered if (e.severity.value if hasattr(e.severity, 'value') else e.severity) == target]
    if mitre_filter:
        filtered = [e for e in filtered if mitre_filter in e.mitre_techniques]
    return filtered


@click.group()
def cli():
    """LogMap — Blue Team Log Analyzer"""


@cli.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--severity", "-s", default=None, help="Filter by severity (LOW|MEDIUM|HIGH|CRITICAL)")
@click.option("--mitre", "-m", default=None, help="Filter by MITRE technique ID (e.g. T1110)")
@click.option("--output", "-o", default=None, help="Save text report to file")
def analyze(file: str, severity: str | None, mitre: str | None, output: str | None) -> None:
    """Analyze a log file and display the attack graph."""
    try:
        with open(file, "r", errors="replace") as f:
            raw = f.read()
    except OSError as e:
        console.print(f"[red]Error reading file: {e}[/red]")
        sys.exit(1)

    with console.status("[cyan]Parsing logs…[/cyan]"):
        fmt, events = parse_logs(raw)

    if not events:
        console.print("[yellow]No events parsed from the log file.[/yellow]")
        sys.exit(0)

    events = _apply_filters(events, severity, mitre)
    if not events:
        console.print(f"[yellow]No events match the applied filters.[/yellow]")
        sys.exit(0)

    with console.status("[cyan]Building graph…[/cyan]"):
        graph = build_graph(events)

    with console.status("[cyan]Detecting patterns…[/cyan]"):
        patterns = detect_patterns(events)

    with console.status("[cyan]Scoring risk…[/cyan]"):
        report = calculate_risk(graph, patterns, events)

    if output:
        from rich.console import Console as RCon
        file_console = RCon(file=open(output, "w"), highlight=False, markup=False)
        # Simple text dump
        file_console.print(f"Format: {fmt}")
        file_console.print(f"Events: {len(events)}")
        file_console.print(f"Risk: {report.global_score}/100 {report.risk_level}")
        for ts in report.technique_scores:
            file_console.print(f"  {ts.technique} {_MITRE_NAMES.get(ts.technique, '')} count={ts.count}")
        file_console.print("Patterns:")
        for p in patterns:
            file_console.print(f"  {p.pattern_type}: {p.description}")
        console.print(f"[green]Report saved to {output}[/green]")

    _print_header(fmt, len(events), sum(1 for e in events if e.is_suspicious),
                  report.global_score, report.risk_level)
    _print_attack_graph(graph, events)
    _print_mitre(report.technique_scores)
    _print_top_ips(graph, events)
    _print_top_users(graph)
    _print_timeline(events)
    _print_patterns(patterns)
    _print_recommendations(report, patterns)


if __name__ == "__main__":
    cli()
