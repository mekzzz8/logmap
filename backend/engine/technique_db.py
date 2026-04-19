"""
MITRE ATT&CK technique metadata with Sigma Rules severity levels.

Scoring methodology (0–100):
  base_score = tactic_score × 0.4 + sigma_score × 0.6

Tactic scores reflect the kill-chain phase severity:
  Impact           = 92   Lateral Movement  = 78
  Persistence      = 74   Privilege Escal.  = 74
  Defense Evasion  = 68   Credential Access = 68
  Execution        = 62   Initial Access    = 60

Sigma severity scores:
  critical = 90  |  high = 72  |  medium = 52  |  low = 30
"""
from __future__ import annotations
from dataclasses import dataclass


@dataclass(frozen=True)
class TechniqueMeta:
    id: str
    name: str
    tactic: str           # Primary MITRE tactic name
    tactic_id: str        # TA00XX
    tactic_score: int     # 0-100 based on kill-chain phase
    sigma_severity: str   # critical / high / medium / low
    sigma_score: int      # 90 / 72 / 52 / 30
    base_score: float     # tactic*0.4 + sigma*0.6  (pre-computed)
    why: str              # Human-readable scoring rationale
    sigma_rule_refs: list[str]   # Representative Sigma rule filenames

    def to_dict(self) -> dict:
        return {
            "id":               self.id,
            "name":             self.name,
            "tactic":           self.tactic,
            "tactic_id":        self.tactic_id,
            "tactic_score":     self.tactic_score,
            "sigma_severity":   self.sigma_severity,
            "sigma_score":      self.sigma_score,
            "base_score":       round(self.base_score, 1),
            "formula":          f"({self.tactic_score} × 0.4) + ({self.sigma_score} × 0.6) = {self.base_score:.1f}",
            "why":              self.why,
            "sigma_rule_refs":  self.sigma_rule_refs,
        }


def _base(tactic: int, sigma: int) -> float:
    return round(tactic * 0.4 + sigma * 0.6, 1)


TECHNIQUE_DB: dict[str, TechniqueMeta] = {

    "T1110": TechniqueMeta(
        id="T1110", name="Brute Force",
        tactic="Credential Access", tactic_id="TA0006",
        tactic_score=68, sigma_severity="high", sigma_score=72,
        base_score=_base(68, 72),
        why=(
            "Repeated authentication attempts generate detectable noise and "
            "directly lead to account compromise. Sigma community rates this HIGH "
            "because it is unambiguously malicious when volume exceeds normal use. "
            "Credential Access (TA0006) gates all later attack phases, making "
            "success here a critical pivot point."
        ),
        sigma_rule_refs=[
            "win_security_susp_failed_logon_reasons.yml",
            "win_security_susp_failed_remote_logon.yml",
        ],
    ),

    "T1110.002": TechniqueMeta(
        id="T1110.002", name="Password Cracking",
        tactic="Credential Access", tactic_id="TA0006",
        tactic_score=68, sigma_severity="medium", sigma_score=52,
        base_score=_base(68, 52),
        why=(
            "Offline cracking of captured hashes occurs silently off-network, "
            "so Sigma rates it MEDIUM — it requires prior access to hash material "
            "but generates no live authentication noise. Score reflects the "
            "moderate detection surface despite high impact when successful."
        ),
        sigma_rule_refs=["win_security_credential_dumping.yml"],
    ),

    "T1110.003": TechniqueMeta(
        id="T1110.003", name="Password Spraying",
        tactic="Credential Access", tactic_id="TA0006",
        tactic_score=68, sigma_severity="high", sigma_score=72,
        base_score=_base(68, 72),
        why=(
            "Low-and-slow credential testing across many accounts deliberately "
            "stays below per-account lockout thresholds. Sigma rates HIGH "
            "because it is harder to detect than standard brute force yet "
            "compromises accounts at scale. A single success grants stealth "
            "access with valid credentials."
        ),
        sigma_rule_refs=[
            "win_security_susp_failed_logon_reasons.yml",
            "win_security_multiple_failed_logon_with_success.yml",
        ],
    ),

    "T1078": TechniqueMeta(
        id="T1078", name="Valid Accounts",
        tactic="Defense Evasion / Persistence", tactic_id="TA0005/TA0003",
        tactic_score=71, sigma_severity="high", sigma_score=72,
        base_score=_base(71, 72),
        why=(
            "Using legitimate credentials makes attacker activity blend with "
            "normal traffic. Sigma rates HIGH because it spans four MITRE tactics "
            "(Initial Access, Persistence, Privilege Escalation, Defense Evasion) "
            "simultaneously. The tactic score is averaged across those phases. "
            "High detection difficulty significantly elevates the risk."
        ),
        sigma_rule_refs=[
            "win_security_susp_logon_event_anomaly.yml",
            "win_security_pass_the_ticket.yml",
        ],
    ),

    "T1078.002": TechniqueMeta(
        id="T1078.002", name="Domain Accounts",
        tactic="Privilege Escalation", tactic_id="TA0004",
        tactic_score=74, sigma_severity="critical", sigma_score=90,
        base_score=_base(74, 90),
        why=(
            "Domain account compromise grants access across the entire Active "
            "Directory forest. Sigma rates this CRITICAL — the blast radius is "
            "organisation-wide, not just a single host. Combined with Privilege "
            "Escalation tactic weight (74), this is the highest-severity "
            "credential technique in Windows environments."
        ),
        sigma_rule_refs=[
            "win_security_susp_special_privilege_assigned.yml",
            "win_security_susp_kerberoasting.yml",
        ],
    ),

    "T1550.002": TechniqueMeta(
        id="T1550.002", name="Pass the Hash",
        tactic="Lateral Movement / Defense Evasion", tactic_id="TA0008/TA0005",
        tactic_score=73, sigma_severity="critical", sigma_score=90,
        base_score=_base(73, 90),
        why=(
            "Authentication with captured NTLM hashes bypasses password "
            "requirements entirely. Sigma rates CRITICAL — it is the definitive "
            "indicator of credential theft (e.g., Mimikatz) and active lateral "
            "movement. Tactic score averaged across Lateral Movement (78) and "
            "Defense Evasion (68). This technique alone justifies immediate "
            "incident response."
        ),
        sigma_rule_refs=[
            "win_security_pass_the_hash.yml",
            "win_security_susp_ntlm_auth.yml",
        ],
    ),

    "T1059": TechniqueMeta(
        id="T1059", name="Command and Scripting Interpreter",
        tactic="Execution", tactic_id="TA0002",
        tactic_score=62, sigma_severity="medium", sigma_score=52,
        base_score=_base(62, 52),
        why=(
            "Execution via built-in command interpreters (cmd, bash) is "
            "inherently dual-use. Sigma rates MEDIUM because context determines "
            "malice — suspicious only with unusual parent process, time of day, "
            "or argument patterns. Execution (TA0002) tactic weight is moderate "
            "since it typically follows initial access rather than representing "
            "it directly."
        ),
        sigma_rule_refs=["win_proc_creation_susp_cmd.yml"],
    ),

    "T1059.001": TechniqueMeta(
        id="T1059.001", name="PowerShell",
        tactic="Execution", tactic_id="TA0002",
        tactic_score=62, sigma_severity="high", sigma_score=72,
        base_score=_base(62, 72),
        why=(
            "PowerShell is one of the most prevalent LOLBIN attack vectors. "
            "Sigma rates HIGH because obfuscation flags (-enc, -nop, -bypass, "
            "-w hidden) are strong indicators of malicious intent. Attackers use "
            "it for download-cradles, in-memory execution, and AMSI bypass. "
            "Elevated above parent T1059 due to higher Sigma community consensus."
        ),
        sigma_rule_refs=[
            "win_proc_creation_susp_powershell_enc_cmd.yml",
            "win_proc_creation_susp_powershell_hidden.yml",
            "win_proc_creation_powershell_download.yml",
        ],
    ),

    "T1053.005": TechniqueMeta(
        id="T1053.005", name="Scheduled Task",
        tactic="Persistence / Privilege Escalation", tactic_id="TA0003/TA0004",
        tactic_score=70, sigma_severity="high", sigma_score=72,
        base_score=_base(70, 72),
        why=(
            "Scheduled tasks provide persistent execution and can run as SYSTEM. "
            "Sigma rates HIGH — a primary persistence mechanism heavily abused by "
            "ransomware and APT groups. Tactic score averaged across Execution "
            "(62), Persistence (74), and Privilege Escalation (74). New tasks "
            "created outside maintenance windows are a reliable malware indicator."
        ),
        sigma_rule_refs=[
            "win_security_schtask_creation.yml",
            "win_proc_creation_schtasks_susp.yml",
        ],
    ),

    "T1543.003": TechniqueMeta(
        id="T1543.003", name="Windows Service",
        tactic="Persistence / Privilege Escalation", tactic_id="TA0003/TA0004",
        tactic_score=74, sigma_severity="high", sigma_score=72,
        base_score=_base(74, 72),
        why=(
            "New Windows services default to SYSTEM privileges, making this a "
            "high-value persistence and privilege escalation path. Sigma rates "
            "HIGH — service installation outside patch windows or with unusual "
            "binary paths is a reliable malware indicator. Tactic score reflects "
            "the Persistence + PrivEsc overlap (both 74)."
        ),
        sigma_rule_refs=[
            "win_security_new_service_installation.yml",
            "win_proc_creation_sc_create_service.yml",
        ],
    ),

    "T1136.001": TechniqueMeta(
        id="T1136.001", name="Create Local Account",
        tactic="Persistence", tactic_id="TA0003",
        tactic_score=74, sigma_severity="medium", sigma_score=52,
        base_score=_base(74, 52),
        why=(
            "Creating a new local account establishes a persistent backdoor. "
            "Sigma rates MEDIUM because account creation is frequently legitimate "
            "(IT provisioning). Score rises in breach context — a new account "
            "created after suspicious authentication is a strong persistence "
            "indicator. Persistence tactic (74) drives the base score higher "
            "than the Sigma level alone would suggest."
        ),
        sigma_rule_refs=["win_security_user_creation.yml"],
    ),

    "T1098": TechniqueMeta(
        id="T1098", name="Account Manipulation",
        tactic="Persistence / Privilege Escalation", tactic_id="TA0003/TA0004",
        tactic_score=74, sigma_severity="high", sigma_score=72,
        base_score=_base(74, 72),
        why=(
            "Modifying account properties (group membership, permissions) is "
            "often the final step before full privilege escalation — e.g., adding "
            "a compromised user to the Administrators group. Sigma rates HIGH. "
            "Spans Persistence and Privilege Escalation tactics (both 74), "
            "yielding one of the higher tactic scores in this category."
        ),
        sigma_rule_refs=[
            "win_security_user_added_to_local_admin.yml",
            "win_security_susp_group_modification.yml",
        ],
    ),

    "T1548.003": TechniqueMeta(
        id="T1548.003", name="Sudo and Sudo Caching",
        tactic="Privilege Escalation / Defense Evasion", tactic_id="TA0004/TA0005",
        tactic_score=71, sigma_severity="high", sigma_score=72,
        base_score=_base(71, 72),
        why=(
            "Sudo abuse is the primary root-escalation path on Linux/Unix. "
            "Sigma rates HIGH — sudo failures followed by success indicate "
            "targeted privilege escalation. Tactic score averaged across "
            "Privilege Escalation (74) and Defense Evasion (68). Sudo "
            "configuration mistakes (NOPASSWD, wildcards) make this a "
            "common post-exploitation target."
        ),
        sigma_rule_refs=[
            "lnx_susp_sudo_execution.yml",
            "lnx_susp_sudoers_modification.yml",
        ],
    ),

    "T1021.001": TechniqueMeta(
        id="T1021.001", name="Remote Desktop Protocol",
        tactic="Lateral Movement", tactic_id="TA0008",
        tactic_score=78, sigma_severity="medium", sigma_score=52,
        base_score=_base(78, 52),
        why=(
            "RDP enables interactive lateral movement between hosts. Sigma "
            "rates MEDIUM by default due to heavy legitimate use in enterprise "
            "environments. However, the Lateral Movement tactic carries the "
            "highest tactic score here (78), pulling the base score above 60. "
            "RDP from unusual sources or after credential theft escalates "
            "contextual risk significantly."
        ),
        sigma_rule_refs=[
            "win_security_rdp_login.yml",
            "win_security_susp_rdp_from_unexpected_src.yml",
        ],
    ),
}


def get(technique_id: str) -> TechniqueMeta | None:
    return TECHNIQUE_DB.get(technique_id)


def all_as_dict() -> dict[str, dict]:
    return {tid: meta.to_dict() for tid, meta in TECHNIQUE_DB.items()}
