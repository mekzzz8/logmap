# Caso 4 — WannaCry: Propagación lateral masiva (topología estrella)

## Malware / Campaña

**WannaCry** (S0366) es el ransomware que en mayo de 2017 infectó 200.000+ sistemas en 150 países en 4 horas, causando daños estimados en $4.000-8.000 millones. Utilizaba EternalBlue (MS17-010) para propagarse, pero en redes sin ese exploit disponible se propaga mediante fuerza bruta RDP y SMB. Atribuido a Lazarus Group / Corea del Norte.

- **MITRE ID Software:** S0366
- **País:** Corea del Norte (atribución con alta confianza, US/UK Gov)
- **Motivación:** Financiamiento + destrucción (impacto sabotaje > recaudación real)

---

## Técnicas MITRE ATT&CK aplicadas

| ID | Nombre | Descripción en este log |
|----|--------|------------------------|
| T1110 | Brute Force | 18 intentos fallidos desde 10.10.50.100 contra múltiples hosts |
| T1110.003 | Password Spraying | 4 usuarios distintos (administrator, Guest, backup_svc, admin) |
| T1021.001 | RDP | Logon Type=10 desde PATIENT-ZERO a 5 hosts comprometidos |
| T1078 | Valid Accounts | `administrator` local usado en todos los hosts (sin patch) |
| T1543.003 | New Windows Service | `mssecsvc2.0` — nombre real del servicio de WannaCry |
| T1136 | Create Account | `WNcry@2ol7` — nombre de cuenta real creada por WannaCry |

---

## Escenario simulado

### Topología de propagación (grafo estrella)

```
                    WKSTN-ACCT-01 ──→ mssecsvc2.0
                   /
                  /──→ WKSTN-ACCT-02 ──→ mssecsvc2.0
                 /
WKSTN-ACCT-ZERO ──→ WKSTN-OPS-01  ──→ mssecsvc2.0
(10.10.50.100)   \
                  \──→ WKSTN-DEV-01  ──→ mssecsvc2.0
                   \
                    SRV-FILE-01    ──→ mssecsvc2.0
```

En el grafo de LogMap este patrón debe ser visible como **un único nodo origen** (10.10.50.100 / administrator) con aristas hacia 5 nodos destino distintos, cada uno con un nodo adicional de servicio instalado.

### Línea de tiempo (11:00 – 11:11 UTC)

```
11:00:01-18  4625 × 18  Spray desde 10.10.50.100 contra 5 workstations
                         Usuarios: administrator, Guest, backup_svc, admin
                         → BRUTE_FORCE detectado (>5 intentos en 5 min)
                         → SPRAY_ATTACK detectado (4 usuarios distintos)
11:02:14     4624        administrator → WKSTN-ACCT-01 (Type=10)
11:02:28     4672        administrator → privs especiales en ACCT-01
11:02:55     7045        mssecsvc2.0 instalado en ACCT-01
                         → PERSISTENCE detectado
11:03:30     4720        Cuenta WNcry@2ol7 creada (nombre real WannaCry)
11:04:22     4624        administrator → WKSTN-ACCT-02 (Type=10)
11:04:35     4672        administrator → privs en ACCT-02
11:05:01     7045        mssecsvc2.0 instalado en ACCT-02
11:06:10     4624        administrator → WKSTN-OPS-01 (Type=10)
             ...
11:10:52     7045        mssecsvc2.0 instalado en SRV-FILE-01
```

---

## Patrones que debe detectar LogMap

| Patrón | Descripción esperada |
|--------|---------------------|
| `BRUTE_FORCE` | 5+ fallos de 10.10.50.100 en ventana de 5 min |
| `SPRAY_ATTACK` | 4 usuarios distintos desde 10.10.50.100 |
| `LATERAL_MOVE` | administrator via RDP a 5 hosts distintos desde 10.10.50.100 |
| `PERSISTENCE` | administrator (suspicious por 4625) → 7045 × 5 instancias |

---

## Detalles de autenticidad

El log usa artefactos documentados del malware real:
- **Nombre del servicio:** `mssecsvc2.0` — nombre exacto usado por WannaCry (referencia: análisis Kaspersky, 2017)
- **Nombre de cuenta:** `WNcry@2ol7` — creada por WannaCry para el proceso de cifrado
- **Patrón de tiempo:** propagación completada en ~11 minutos para 5 hosts — coherente con velocidad documentada

---

## Por qué el grafo de estrella es útil

La topología de estrella en el grafo de LogMap es una **firma visual del ransomware de propagación automática**:
- En ataques humanos (APT), el movimiento lateral es selectivo y disperso en el tiempo
- En ransomware, el patrón es **inmediato, exhaustivo y desde un único origen**
- La densidad de aristas desde un único nodo en un período breve es anomalía detectable visualmente

---

## Nodos esperados en el grafo

- Usuarios: `administrator`, `WNcry@2ol7`, `Guest`, `backup_svc`, `admin`
- IPs: `10.10.50.100`
- Workstations: `WKSTN-ACCT-01`, `WKSTN-ACCT-02`, `WKSTN-OPS-01`, `WKSTN-DEV-01`, `SRV-FILE-01`
- Eventos: 4624, 4625, 4672, 4720, 7045

**Total esperado: 15+ nodos con topología de estrella clara**

---

## Referencia

- [MITRE ATT&CK S0366 — WannaCry](https://attack.mitre.org/software/S0366/)
- [Kaspersky: WannaCry Technical Analysis](https://securelist.com/wannacry-ransomware-used-in-widespread-attacks/78351/)
- [NSA/CISA Advisory — MS17-010](https://www.cisa.gov/news-events/alerts/2017/05/12/indicators-associated-wannacry-ransomware)
