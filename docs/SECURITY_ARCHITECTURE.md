# Sentinel Security Architecture (v3.8)

Sentinel es un **Supply Chain Enforcement Layer** — no un scanner de vulnerabilidades. La distinción es deliberada y estratégica: Sentinel no informa *qué está mal*, decide *si algo entra*.

---

## Principio Arquitectural Central

```
Input: "sentinel install <adapter> <package>"
Output: BLOCK | SUSPICIOUS | SAFE + Audit Trail

No se analiza código de vulnerabilidades.
No se expone inteligencia a actores no verificados.
No se ejecuta ningún paquete hasta que el veredicto es SAFE.
```

---

## Diagrama de Alto Nivel

```
┌─────────────────────────────────────────────────────────────────────┐
│                        SENTINEL (v3.8)                               │
│                  Supply Chain Enforcement Layer                       │
├─────────────────┬───────────────────────────────────────────────────┤
│  ENTRY POINTS   │  CLI (sentinel install / guard / trust)            │
│                 │  Sentinel Guard (shell alias interception)          │
│                 │  CI/CD (GitHub Actions, exit codes)                 │
├─────────────────┼───────────────────────────────────────────────────┤
│  DISPATCH       │  SupplyChainShield — Ecosystem Dispatcher           │
│                 │  Resolves adapter by ecosystem (npm/pip/docker)     │
├────────┬────────┴────────┬──────────────────┬────────────────────────┤
│  ADAPTERS               │                  │                          │
│  NpmAdapter             │  PipAdapter       │  DockerAdapter           │
│  - package.json         │  - pyproject.toml │  - Publisher tier        │
│  - lifecycle hooks      │  - entry_points   │  - Digest pinning        │
│  - scope camouflage     │  - PEP-503 confus │  - Image mimicry         │
├────────┴────────┬────────┴──────────────────┴────────────────────────┤
│  CORE ENGINE    │  Levenshtein (typosquatting)                        │
│                 │  calcRiskScore (probabilistic aggregation)           │
│                 │  TrustCache (persistent, 7-day TTL)                  │
├─────────────────┼───────────────────────────────────────────────────┤
│  POLICY ENGINE  │  enforcement_mode: strict | advisory                │
│                 │  exposure_level: authorized | partner | restricted   │
│                 │  redaction_mode: none | balanced | aggressive        │
├─────────────────┼───────────────────────────────────────────────────┤
│  AUDIT LAYER    │  HMAC-SHA256 Trace IDs (every verdict)              │
│                 │  audit.jsonl (append-only forensic log)             │
│                 │  Risk Intelligence Asymmetry (tactical silence)      │
└─────────────────┴───────────────────────────────────────────────────┘
```

---

## El Pipeline de Instalación (Flujo Completo)

### Paso 1 — Intercepción

El desarrollador ejecuta `npm install <pkg>`.

- **Con `sentinel guard enable`**: el alias de shell intercepta el comando antes de que npm lo procese.
- **Con `sentinel install npm <pkg>`**: invocación explícita.

En ambos casos, el paquete no se descarga hasta que Sentinel emite veredicto.

### Paso 2 — Trust Cache

Verificación O(1) contra el caché persistente en `~/.sentinel/trust-cache.json`.

- **HIT + no expirado (TTL 7d)**: veredicto inmediato, sin análisis.
- **HIT expirado o MISS**: continúa al pipeline completo.

El hash del veredicto (`cache:abc1234f`) se muestra en el output para trazabilidad forense.

### Paso 3 — Análisis por Adapter

El Dispatcher delega al adapter correcto según el ecosistema:

| Adapter | Análisis principal |
|---|---|
| `npm` | Levenshtein contra 25+ paquetes protegidos, scope camouflage (`@evil/react`), extension camouflage (`axios-pro`), lifecycle scripts (`postinstall`) |
| `pip` | Levenshtein contra 40+ paquetes PyPI protegidos, normalización PEP-503 (guiones = subrayados), `entry_points` en `pyproject.toml` |
| `docker` | Parsing de image ref (`registry/org/image:tag@sha256:digest`), clasificación de publisher en 6 tiers, `:latest` enforcement, image mimicry |

### Paso 4 — Scoring Probabilístico

```
riskScore = min(1.0,
    (typosquatting ? 0.95 : 0) +
    Σ(lifecycle findings × severity_weight) +
    Σ(adapter_specific_signals × riskLevel)
)
```

Umbrales de veredicto:
- `>= 0.85` → **BLOCK**
- `>= 0.40` → **SUSPICIOUS**
- `< 0.40`  → **SAFE**

### Paso 5 — Policy Engine (Enforcement)

El Policy Engine determina **cómo se impone el veredicto**, no qué es:

| Modo | Activación | Comportamiento en BLOCK |
|---|---|---|
| **Strict** | CI/CD auto-detectado (`CI=true`, `GITHUB_ACTIONS`, no-TTY) | `exit 1`. Instalación detenida. |
| **Advisory** | `--advisory` flag, TTY interactivo | Advierte con detalle completo, pero procede. |

### Paso 6 — Intelligence Asymmetry

El output se filtra según identidad verificada:

| Nivel | Recibe |
|---|---|
| **Authorized** (owner verificado vía `gh auth`) | Nombres de señales, categorías, descripciones técnicas |
| **Restricted** (sin verificación) | Solo el veredicto: `BLOCK`. Sin detalles técnicos. |

Esto evita que Sentinel sea usado como herramienta de reconocimiento ofensivo.

---

## Extensión: Añadir un Nuevo Adapter

```js
// src/ui/backend/scanner/adapters/cargo_adapter.js
module.exports = {
    id: 'cargo',
    aliases: ['cargo'],
    installCmd: (pkg, args = []) => ['cargo', ['add', pkg, ...args]],
    protected: ['serde', 'tokio', 'rand', ...],
    parseManifest(manifest) { /* parse Cargo.toml */ },
    auditScripts(scripts)  { /* check build.rs patterns */ },
    checkScopeAbuse(pkg)   { /* crates.io-specific checks */ }
};

// Luego en supply_chain_shield.js — una línea:
const ADAPTERS = {
    // ...
    cargo: require('./adapters/cargo_adapter'),
};
```

El core (Trust Cache, Scoring, Policy Engine, CLI) no requiere ningún cambio.

---

## El Pipeline de Escaneo de Repositorio (Fases 1-3)

Este pipeline es independiente del Firewall de Instalación. Opera sobre código ya existente en el repositorio:

### Layer 1 — Static Engine
Análisis AST sin ejecución. Regex + walking estructural. Detecta primitivas peligrosas, `.npmrc` overrides, y mapas de dependencias transitivas.

### Layer 2 — Adaptive Scoring Engine
Combina múltiples señales de baja confianza mediante el `OracleBrain` (probabilistic scoring con damping). El riesgo compuesto activa un incidente solo cuando supera el umbral de ruido (`rulepack_version: 2026.04`).

### Layer 3 — Cloud Sandbox
Detonación controlada mediante `sentinel verify-pkg <adapter> <pkg> --sandbox`. Genera un workflow de GitHub Actions para observación comportamental aislada.

---

## Capas de Seguridad Defensiva

### Anti-Probing
- Jitter probabilístico en latencia de respuesta.
- Degradación de output para peticiones anómalas.
- Modo `LOCKDOWN` en detección de probing sistemático.

### Forensic Auditability
- Cada veredicto emite un `TraceID` firmado con HMAC-SHA256 (`SENTINEL_TRACE_SALT`).
- Log append-only: `~/.sentinel/audit.jsonl`.
- Formato compatible con SIEM (Splunk, Elastic).

### Fail-Closed Design
- Error en el adapter → veredicto `SUSPICIOUS` por defecto. Nunca `SAFE`.
- Error en Policy Engine → modo `strict` por defecto. Nunca `advisory`.
- Error en Trust Cache → análisis completo. Nunca skip silencioso.

---

## Archivos Clave

| Archivo | Responsabilidad |
|---|---|
| `supply_chain_shield.js` | Dispatcher, Trust Cache, Scoring |
| `adapters/npm_adapter.js` | Análisis npm/yarn/pnpm |
| `adapters/pip_adapter.js` | Análisis pip/poetry/uv |
| `adapters/docker_adapter.js` | Análisis docker pull |
| `policy_engine.js` | Enforcement mode, exposure level, redaction |
| `risk_orchestrator.js` | Arbitraje de escaneo de repositorio |
| `scoring_engine.js` | Deduplicación semántica, OracleBrain |
| `cli/guard.js` | Provisión de alias de shell |
| `~/.sentinel/trust-cache.json` | Trust Cache persistente |
| `~/.sentinel/sentinel-policy.json` | Política local (opcional, sobreescribe defaults) |
