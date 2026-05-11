# Caso 3 — Lazarus Group: Credential Dump + Cuenta Backdoor

## Grupo APT

**Lazarus Group** (también conocido como HIDDEN COBRA, Guardians of Peace, APT38) es un grupo de amenaza persistente atribuido al RGB norcoreano (Reconnaissance General Bureau). Combina espionaje con robo financiero (criptomonedas, SWIFT). Notable por los ataques al Banco de Bangladesh (2016, $81M robados) y Sony Pictures (2014).

- **MITRE ID:** G0032
- **País:** Corea del Norte (RGB)
- **Motivación:** Espionaje estatal + financiamiento del régimen mediante ciberrobo

---

## Técnicas MITRE ATT&CK aplicadas

| ID | Nombre | Descripción en este log |
|----|--------|------------------------|
| T1078 | Valid Accounts | Login SSH con credenciales de `mpark` comprometidas |
| T1548.003 | Abuse Elevation Control: Sudo | Escalada inmediata a root via sudo |
| T1059.001 | PowerShell | Payload en memoria con `-enc` y `-w hidden` |
| T1003 | OS Credential Dumping | `procdump.exe` sobre lsass + `mimikatz.exe` |
| T1003.003 | NTDS | `ntdsutil.exe` para dump del Active Directory |
| T1136.001 | Create Local Account | Cuenta backdoor `svc_dbbackup` en Windows y Linux |
| T1078.002 | Valid Accounts: Domain | Uso de la cuenta backdoor con privs de dominio |
| T1053.005 | Scheduled Task | Tarea `DbBackupRoutine` para persistencia/exfiltración |

---

## Escenario simulado

### Contexto

Lazarus compromete primero el servidor Linux (`CORPDEV-LNX-01`) mediante credenciales de `mpark` robadas en una campaña de spearphishing previa. Desde allí pivota al entorno Windows para el volcado de credenciales y la implantación del backdoor.

### Línea de tiempo (03:14 – 03:45 UTC)

```
03:14  SSH Accepted publickey  mpark desde 175.45.176.8 (Corea del Norte)
03:14  sudo bash              mpark escala a root inmediatamente
       → T1548.003: Abuse Elevation Control (auth.log)
03:14  4624  mpark logon network en CORPDEV-WIN-02 (Windows)
03:15  4688  powershell.exe -enc [...] carga shellcode en memoria
03:17  4624  mpark logon RDP (Type=10) desde 175.45.176.8
              → SUSPICIOUS: RDP externo — mpark entra en suspicious_users
03:18  4672  mpark → privilegios especiales
              → PRIV_ESCALATION detectado (Δt = 32s)
03:22  4688  procdump.exe -ma lsass.exe → dump de LSASS (T1003)
03:24  4688  mimikatz.exe sekurlsa::logonpasswords → extracción de hashes
03:25  4776  Validación NTLM (credenciales recién obtenidas)
03:26  4648  Explicit credentials para movimiento lateral
03:27  4688  ntdsutil.exe → dump completo del Active Directory (T1003.003)
03:29  4720  Cuenta svc_dbbackup creada (backdoor Windows)
03:30  4732  svc_dbbackup → grupo Administrators
03:32  4624  svc_dbbackup logon con nuevas credenciales (backdoor activo)
03:32  4672  svc_dbbackup → admin privs confirmados
03:35  4688  powershell.exe -enc [...] desde svc_dbbackup (exfiltración)
03:38  4698  Tarea DbBackupRoutine (exfil persistente disfrazada de backup)
03:44  4634  mpark cierra sesión — ataque completado

--- auth.log Linux (mismas 03:14) ---
03:14  SSH login mpark (publickey) desde 175.45.176.8
03:14  pam_unix session opened for mpark
03:14  sudo: mpark → root — /bin/bash
03:22  sudo: root → cat /etc/shadow (extracción de hashes Linux)
03:29  sudo: root → useradd svc_dbbackup (cuenta backdoor Linux)
03:30  sudo: root → usermod -aG sudo svc_dbbackup
03:44  SSH session closed for mpark
```

---

## Formato mixto — comportamiento del detector

El archivo combina **Windows Event Log** (eventos 4624-4732, bloque principal) y **auth.log Linux** (sección final). El detector de LogMap:

1. **Evalúa los primeros 4.096 caracteres** — los eventos Windows dominan → formato **windows** detectado
2. Los eventos Windows se parsean completamente (14 eventos → 14+ nodos)
3. Las líneas auth.log al final del archivo **no son parseadas** por el parser de Windows, pero están presentes para correlación manual o futura extensión del parser

**En un entorno SIEM real**, estas dos fuentes llegarían como streams separados y se correlacionarían por timestamp + IP origen (175.45.176.8).

---

## Patrones que debe detectar LogMap

| Patrón | Descripción esperada |
|--------|---------------------|
| `PRIV_ESCALATION` | mpark: 4624 RDP externo → 4672 en 32s |
| `PASS_THE_HASH` | 4648 (explicit creds) desde 10.20.0.15 sin 4624 previo de esa IP |
| `PERSISTENCE` | svc_dbbackup (suspicious por herencia de mpark) → 4698 |
| T1059.001 | PowerShell con `-enc`, `-nop`, `-w hidden` |
| T1003 | procdump.exe + mimikatz.exe en SUSPICIOUS_PROCESSES |
| T1003.003 | ntdsutil.exe en SUSPICIOUS_PROCESSES |

---

## Nodos esperados en el grafo

- Usuarios: `mpark`, `svc_dbbackup`
- IPs externas: `175.45.176.8`
- IPs internas: `10.20.0.15`
- Workstations: `CORPDEV-WIN-02`, `CORPDEV-LNX-01`
- Procesos: `powershell.exe`, `procdump.exe`, `mimikatz.exe`, `ntdsutil.exe`

**Total esperado: 16+ nodos**

---

## Referencia

- [MITRE ATT&CK G0032 — Lazarus Group](https://attack.mitre.org/groups/G0032/)
- [US-CERT Alert AA21-048A — HIDDEN COBRA](https://www.cisa.gov/news-events/alerts/2021/02/17/aa21-048a)
- [Mandiant APT38 Report](https://www.mandiant.com/sites/default/files/2022-02/rpt-apt38-2018-web_v5-1.pdf)
