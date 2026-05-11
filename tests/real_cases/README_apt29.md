# Caso 1 — APT29 / Cozy Bear: Lateral Movement estilo SolarWinds

## Grupo APT

**APT29** (también conocido como Cozy Bear, The Dukes, NOBELIUM) es un grupo de amenaza avanzada atribuido al SVR ruso (Servicio de Inteligencia Exterior). Es responsable de la campaña SolarWinds (2020), el hackeo del DNC (2016) y múltiples operaciones contra gobiernos occidentales.

- **MITRE ID:** G0016
- **País:** Rusia (SVR)
- **Motivación:** Espionaje geopolítico, robo de inteligencia

---

## Técnicas MITRE ATT&CK aplicadas

| ID | Nombre | Descripción en este log |
|----|--------|------------------------|
| T1078 | Valid Accounts | Uso de credenciales de la cuenta de servicio `svc_backup` |
| T1021.001 | Remote Desktop Protocol | Logon Type 10 desde IP externa (09:15) y desde IP interna a 4 hosts |
| T1059.001 | PowerShell | Ejecución con `-enc`, `-nop`, `-w hidden` — payload en memoria |
| T1053.005 | Scheduled Task/Job | Tarea `\Microsoft\Windows\Update\SvcHostUpdate` para persistencia |
| T1136.001 | Create Local Account | Cuenta `helpdesk_temp` creada para acceso backdoor |
| T1098 | Account Manipulation | `helpdesk_temp` añadida al grupo Administrators (4732) |
| T1003 | OS Credential Dumping | `mimikatz.exe` ejecutado en DC-CORP-01 (EventID 4688) |
| T1070.001 | Clear Windows Event Logs | `wevtutil.exe cl Security` al final del ataque |

---

## Escenario simulado

### Línea de tiempo (09:15 – 10:00 UTC)

```
09:15  4624  svc_backup logon Type=10 desde 91.108.4.11 (externo)
              → Primera señal: RDP desde IP no corporativa
09:16  4672  svc_backup → privilegios especiales
              → PRIV_ESCALATION detectado (Δt = 34s)
09:18  4688  powershell.exe -nop -w hidden -enc [...]
              → Payload en memoria, T1059.001 detectado
09:20  4688  powershell.exe -enc [...] -bypass
              → Segunda ejecución de PS ofuscado
09:21  4648  svc_backup explicit credentials desde 10.10.0.5
              → Paso de credenciales para movimiento lateral
09:22  4624  svc_backup Type=10 → WKSTN-FIN-01  (lateral #1)
09:25  4624  svc_backup Type=10 → WKSTN-HR-02   (lateral #2)
09:29  4624  svc_backup Type=10 → WKSTN-DEV-03  (lateral #3)
09:32  4624  svc_backup Type=10 → DC-CORP-01    (lateral #4, Domain Controller)
09:33  4672  svc_backup en DC → administrador de dominio
09:35  4698  Tarea programada SvcHostUpdate → PERSISTENCE detectado
09:40  4688  mimikatz.exe → volcado de credenciales
09:44  4688  powershell.exe -enc [...] → exfiltración/C2
09:47  4720  Cuenta helpdesk_temp creada (backdoor)
09:48  4732  helpdesk_temp → grupo Administrators
09:55  4624  helpdesk_temp logon en DC (backdoor activo)
09:58  4688  wevtutil.exe cl Security → borrado de evidencias
10:00  1102  Security log cleared
```

---

## Patrones que debe detectar LogMap

| Patrón | Descripción esperada |
|--------|---------------------|
| `PRIV_ESCALATION` | svc_backup: 4624 externo type=10 a las 09:15 → 4672 a las 09:16 (34s) |
| `LATERAL_MOVE` | svc_backup via RDP a 4 hosts internos desde 10.10.0.5 |
| `PERSISTENCE` | svc_backup (en suspicious_users) → 4698 tarea SvcHostUpdate |
| T1059.001 | Detectado en los 4688 de PowerShell con `-enc`, `-nop`, `-bypass` |
| T1003 | mimikatz.exe marcado como suspicious en 4688 (proceso en SUSPICIOUS_PROCESSES) |

---

## Nodos esperados en el grafo (mínimo)

- Usuarios: `svc_backup`, `helpdesk_temp`
- IPs: `91.108.4.11`, `10.10.0.5`
- Workstations: `WKSTN-FIN-01`, `WKSTN-HR-02`, `WKSTN-DEV-03`, `DC-CORP-01`
- Procesos: `powershell.exe`, `mimikatz.exe`, `wevtutil.exe`
- Eventos: 4624, 4672, 4688, 4698, 4720, 4732

**Total esperado: 18+ nodos**

---

## Cómo ejecutar

```bash
python logmap.py --input tests/real_cases/apt29_lateral_movement.log --output apt29_graph.json
```

---

## Referencia

- [MITRE ATT&CK G0016](https://attack.mitre.org/groups/G0016/)
- [CISA Alert AA20-352A — SolarWinds](https://www.cisa.gov/news-events/alerts/2020/12/17/aa20-352a)
- [Mandiant: UNC2452 (NOBELIUM)](https://www.mandiant.com/resources/unc2452-merged-into-apt29)
