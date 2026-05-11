# Caso 2 — FIN7 (Carbanak): Brute Force + Persistencia bancaria

## Grupo APT

**FIN7** (también conocido como Carbanak Group, Navigator Group) es un grupo criminal financiero altamente sofisticado activo desde 2013. Ha robado más de $1.000 millones de instituciones financieras globales. Utiliza técnicas APT clásicas con motivación puramente económica.

- **MITRE ID:** G0046
- **País:** Desconocido (probablemente Europa del Este)
- **Motivación:** Ganancia financiera — robo bancario directo

---

## Técnicas MITRE ATT&CK aplicadas

| ID | Nombre | Descripción en este log |
|----|--------|------------------------|
| T1110 | Brute Force | 20 intentos fallidos desde 185.220.101.55 |
| T1110.003 | Password Spraying | Mismo IP, 7 usuarios distintos atacados en ronda |
| T1078 | Valid Accounts | Acceso exitoso con `jsmith` tras spray |
| T1021.001 | RDP | Logon Type=10 desde IP atacante externo |
| T1543.003 | Windows Service | Servicio `WinUpdateSvc` instalado (EventID 7045) |
| T1053.005 | Scheduled Task | Tarea `WinHealthCheck` para persistencia (EventID 4698) |
| T1098 | Account Manipulation | `jsmith` añadido a grupo Administrators (EventID 4732) |

---

## Escenario simulado

### Patrón de spray (14:00 – 14:02 UTC)

FIN7 realiza **password spraying** — en lugar de atacar muchas contraseñas contra un usuario (que bloqueará la cuenta), prueba **una contraseña por usuario** ciclando por la lista de usuarios. Evita los bloqueos de cuenta porque ningún usuario supera el umbral de fallos.

**Usuarios atacados:** administrator, jsmith, mgarcia, rlopez, cferrer, aortega, lruiz (7 usuarios distintos)
**Contraseñas probadas:** Ciclos con passwords comunes de temporada (`Spring2025!`, `Welcome2025`, etc.)
**Nota:** El log muestra 20 intentos representativos. El ataque real registró ~200+ intentos en 30 minutos.

### Línea de tiempo

```
14:00-14:02  4625 × 20  Password spray desde 185.220.101.55
                          → BRUTE_FORCE detectado (>5 en <5 min)
                          → SPRAY_ATTACK detectado (7 usuarios distintos)
14:23        4624         jsmith login exitoso, Type=10, IP externa
                          → jsmith marcado como suspicious
14:23        4672         jsmith → privilegios especiales
                          → PRIV_ESCALATION detectado (Δt = 34s)
14:25        7045         Servicio WinUpdateSvc instalado por jsmith
                          → PERSISTENCE detectado
14:25        4688         schtasks.exe crea tarea con PS payload
                          → T1059.001 en línea de comando
14:26        4698         Tarea WinHealthCheck registrada
                          → PERSISTENCE detectado (segunda instancia)
14:28        4732         jsmith → grupo Administrators
                          → T1098 detectado
```

---

## Patrones que debe detectar LogMap

| Patrón | Descripción esperada |
|--------|---------------------|
| `BRUTE_FORCE` | 5+ fallos de 185.220.101.55 en ventana de 5 min |
| `SPRAY_ATTACK` | 7 usuarios distintos atacados desde misma IP |
| `PRIV_ESCALATION` | jsmith: 4624 externo type=10 → 4672 en 34s |
| `PERSISTENCE` | jsmith (suspicious) → 7045 + 4698 |

---

## Por qué es difícil de detectar el spray

El password spraying es la técnica preferida de FIN7 porque:
1. Ningún usuario supera el umbral de bloqueo (típicamente 5-10 intentos)
2. Los fallos se distribuyen por usuario → bajos false positives por cuenta
3. Los logs de 4625 son normales en empresas con muchos usuarios
4. Solo una herramienta que **correlaciona IPs de origen** puede detectarlo

---

## Nodos esperados en el grafo

- Usuarios: `jsmith`, `administrator`, `mgarcia`, `rlopez`, `cferrer`, `aortega`, `lruiz`
- IPs: `185.220.101.55`
- Workstations: `WKSTN-BANK-01`
- Procesos: `schtasks.exe`
- Eventos: 4624, 4625, 4672, 4688, 4698, 4732, 7045

**Total esperado: 15+ nodos**

---

## Referencia

- [MITRE ATT&CK G0046 — FIN7](https://attack.mitre.org/groups/G0046/)
- [US-CERT Alert AA20-049A — FIN7](https://www.cisa.gov/news-events/alerts/2020/02/18/aa20-049a)
- [Mandiant: FIN7 Evolution](https://www.mandiant.com/resources/blog/fin7-spear-phishing-campaign-targets-personnel)
