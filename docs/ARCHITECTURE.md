# Sentinel — Documentación de Arquitectura para Desarrolladores

> **Versión:** 3.0 (Sandbox Dinámico)
> **Última actualización:** Abril 2026
> **Estado:** Producción

---

## Índice

1. [Visión General](#1-visión-general)
2. [Estructura de Archivos](#2-estructura-de-archivos)
3. [Capas de Seguridad (Defense in Depth)](#3-capas-de-seguridad)
4. [Pipeline de Escaneo](#4-pipeline-de-escaneo)
5. [Sandbox Dinámico (GitHub Actions)](#5-sandbox-dinámico)
6. [Threat Intelligence](#6-threat-intelligence)
7. [API Reference](#7-api-reference)
8. [Guía de Contribución](#8-guía-de-contribución)

---

## 1. Visión General

Sentinel es una herramienta de seguridad de cadena de suministro (**Supply Chain Security**) que protege repositorios GitHub de ataques avanzados como:

- **Registry Poisoning** — Redirección de npm a registros maliciosos
- **Phantom Dependencies** — Paquetes inyectados en lockfiles sin declarar
- **Dropper de 2 etapas** — `fetch` malicioso → `eval` (patrón AST detectado)
- **Exfiltración de credenciales** — `process.env.TOKEN` → llamada de red
- **Evasión CI** — Código que se comporta diferente en entornos CI
- **Compromisos post-merge** — Análisis sandbox detecta comportamiento real en instalación

### Principios de diseño

| Principio | Implementación |
|---|---|
| **Zero-Trust** | Solo lectura de archivos. Sin ejecutar código del usuario |
| **Zero-Network** | Todo el análisis estático es offline. Sin llamadas externas |
| **Zero-Shell** | Todo `execFileSync` usa array de args. `shell: false` siempre |
| **Defense-in-Depth** | 7 capas de análisis independientes |
| **Fail-Safe** | Cualquier módulo puede fallar sin bloquear el pipeline |

---

## 2. Estructura de Archivos

```
src/ui/backend/
│
├── server/
│   └── index.js              ← API Express (endpoints REST hardened)
│
├── scanner/
│   ├── index.js              ← Pipeline principal (7 capas)
│   ├── ast_inspector.js      ← Análisis AST Source→Sink
│   ├── lifecycle_filter.js   ← Scripts de lifecycle + análisis transitivo
│   ├── lockfile_filter.js    ← Integridad de lockfiles
│   ├── config_integrity.js   ← Monitor de .npmrc/.yarnrc
│   ├── threat_intel.js       ← Base de datos de IOCs conocidos (C2 domains)
│   ├── detector_unicode.js   ← Detección de caracteres Unicode invisibles
│   ├── detector_entropy.js   ← Detección de strings de alta entropía
│   └── rules/
│       ├── malware.yaml      ← Reglas YAML: firmas de malware conocido
│       ├── secrets.yaml      ← Reglas YAML: detección de secretos hardcodeados
│       ├── supply-chain.yaml ← Reglas YAML: ataques de supply chain genéricos
│       └── github-actions.yaml  ← [NUEVO v3.0] Escaneo de workflows CI
│   └── workflow/
│       └── sentinel-sandbox.yml ← [NUEVO v3.0] Template del sandbox
│
├── lib/
│   ├── ci_sandbox.js         ← [NUEVO v3.0] Orquestador del sandbox (Modo Pasivo)
│   ├── gh_bridge.js          ← Interfaz con GitHub CLI
│   ├── git_bridge.js         ← Interfaz con Git local
│   ├── db.js                 ← Base de datos SQLite local
│   ├── sanitizer.js          ← Validación de inputs (anti-injection)
│   └── git_hooks.js          ← Gestión de hooks de Git
│
└── services/
    ├── polling.js            ← Servicio de polling de PRs en background
    └── hardener.js           ← Interruptores de seguridad del sistema
```

---

## 3. Capas de Seguridad

Sentinel implementa **7 capas de análisis** que corren en secuencia para cada archivo:

```
Archivo de entrada
      │
      ▼
┌─────────────────────────────┐  Capa 1: Reglas YAML dinámicas
│  YAML Rules Engine          │  → malware.yaml, secrets.yaml, supply-chain.yaml,
│  (regex con timeout 50ms)   │     github-actions.yaml (v3.0)
└─────────────────────────────┘
      │
      ▼
┌─────────────────────────────┐  Capa 2: Detectores Heurísticos
│  Unicode + Entropy          │  → Caracteres invisibles, strings de alta entropía
│  Detectors                  │
└─────────────────────────────┘
      │
      ▼
┌─────────────────────────────┐  Capa 3: Lifecycle Scripts
│  Lifecycle Filter           │  → postinstall, preinstall, prepare
│  (de-ofuscación Base64/Hex) │  → De-ofuscación: Base64, Hex, string inversion
└─────────────────────────────┘
      │
      ▼
┌─────────────────────────────┐  Capa 4: Lockfile Integrity
│  Lockfile Guardian          │  → Registry poisoning, phantom deps, hashes faltantes
│  + Transitive Analysis      │  → Árbol completo de sub-dependencias (Axios 2026)
└─────────────────────────────┘
      │
      ▼
┌─────────────────────────────┐  Capa 5: Config Integrity
│  .npmrc / .yarnrc Monitor   │  → Registry overrides, proxy injection, tokens expuestos
└─────────────────────────────┘
      │
      ▼
┌─────────────────────────────┐  Capa 6: AST + Threat Intel
│  AST Inspector              │  → fetch→eval, process.env→net, CI evasion
│  + C2 Blacklist             │  → IOCs conocidos: sfrclak.com, copayapi.host, etc.
└─────────────────────────────┘
      │
      ▼
┌─────────────────────────────┐  Capa 7: CI Workflow Scanner
│  GitHub Actions Rules       │  → registry override en CI, auto-publish,
└─────────────────────────────┘     download-and-exec, token exposure
      │
      ▼
   Alertas consolidadas
      │
      ▼ (async, on-demand)
┌─────────────────────────────┐  Capa 8: Sandbox Dinámico (v3.0)
│  GitHub Actions Sandbox     │  → Comportamiento real de instalación
│  (Modo Pasivo)              │  → Lockfile diff, WASM, egress, ejecutables
└─────────────────────────────┘
```

---

## 4. Pipeline de Escaneo

### `scanner/index.js` — `scanFile(filename, content, authorMeta)`

Función central del pipeline. Recibe el contenido de un archivo y devuelve un objeto `results` con todas las alertas encontradas.

**Parámetros:**
- `filename` — Nombre del archivo (se usa para determinar qué capas aplican)
- `content` — Contenido completo del archivo como string
- `authorMeta` — Objeto opcional con `{ login, createdAt, accountAgeDays }` del autor del PR

**Protecciones implementadas:**
- Límite de líneas a escanear: `MAX_SCAN_LINES = 10000`
- Límite de longitud de regex: `MAX_REGEX_LENGTH = 500`
- Timeout de regex por línea: 50ms (via `vm.createContext`)
- AST parsing no-fatal (try/catch en todo)

---

## 5. Sandbox Dinámico

### Arquitectura (Modo Pasivo)

El sandbox usa **GitHub Actions como entorno de ejecución aislado y efímero**. Sentinel no ejecuta código sospechoso en la máquina del usuario.

```
Usuario                    Sentinel CLI              GitHub Actions
  │                            │                           │
  │── Agrega workflow ──────→  │                           │
  │   (una vez)                │                           │
  │                            │─── trigger run ──────────→│
  │                            │    (workflow_dispatch)    │
  │                            │                           │── npm ci --ignore-scripts
  │                            │                           │── Harden-Runner egress audit
  │                            │                           │── Captura telemetría
  │                            │                           │── Sube artefactos
  │                            │←── poll status ───────────│
  │                            │←── download artifacts ────│
  │                            │── analyzeTelemetry()      │
  │←── reporte de amenazas ────│                           │
```

### `lib/ci_sandbox.js` — Funciones principales

| Función | Descripción |
|---|---|
| `generateWorkflowTemplate()` | Genera el YAML para instalación manual |
| `checkWorkflowInstalled(repo)` | Verifica si el workflow existe en el repo |
| `triggerSandboxRun(repo, branch)` | Dispara `workflow_dispatch` vía `gh` CLI |
| `getSandboxRunStatus(repo, runId)` | Polling del estado del run |
| `waitForSandboxRun(repo, runId)` | Espera activa hasta completion (timeout: 15min) |
| `downloadSandboxArtifacts(repo, runId)` | Descarga el ZIP del artefacto `sentinel-telemetry` |
| `analyzeTelemetry(tempDir, repo)` | Analiza los archivos de telemetría y genera amenazas |
| `cleanupTempDir(tempDir)` | Elimina archivos temporales |

### Telemetría capturada por el workflow

| Archivo | Contenido | Señal buscada |
|---|---|---|
| `lockfile-diff.txt` | Diff antes/después de `npm ci` | Phantom deps, manifest-swap |
| `wasm-files.txt` | Lista de `.wasm` en node_modules | Código binario ofuscado |
| `netstat-diff.txt` | Conexiones TCP nuevas durante install | Contacto con servidor C2 |
| `executables.txt` | Binarios ejecutables en node_modules | Dropper binario |
| `npm-env.txt` | Variables de entorno npm activas | Registry override en runtime |

---

## 6. Threat Intelligence

### `scanner/threat_intel.js`

Base de datos local de IOCs (Indicadores de Compromiso). **Offline-first** — sin llamadas de red.

**IOCs actuales (v3.0):**

| Dominio | Campaña | Severidad |
|---|---|---|
| `sfrclak.com` | Axios Supply Chain Attack (2026) | CRITICAL |
| `copayapi.host` | Event-stream / flatmap-stream (2018) | CRITICAL |
| `citationsherbe.at` | ua-parser-js hijack (2021) | CRITICAL |
| `kahabkhj.host` | ua-parser-js hijack (2021) | CRITICAL |
| `workers.dev` | Generic C2 via Cloudflare Workers | HIGH (con contexto) |
| `raw.githubusercontent.com` | GitHub Raw Content Abuse | MEDIUM (con contexto) |

**Para añadir nuevos IOCs:** Editar el array `KNOWN_C2_DOMAINS` en `threat_intel.js`.

---

## 7. API Reference

### Supply Chain Endpoints

| Método | Ruta | Descripción |
|---|---|---|
| `POST` | `/api/supply/scan-lockfile` | Escanea un lockfile por registry poisoning |
| `POST` | `/api/supply/scan-config` | Escanea .npmrc/.yarnrc por overrides maliciosos |
| `POST` | `/api/supply/scan-transitive` | Escanea árbol completo de dependencias |
| `GET` | `/api/supply/logs` | Logs de alertas de supply chain |

### Sandbox Endpoints

| Método | Ruta | Descripción |
|---|---|---|
| `GET` | `/api/supply/sandbox/template` | Obtener el YAML del workflow |
| `GET` | `/api/supply/sandbox/check/:owner/:repo` | Verificar si el sandbox está instalado |
| `POST` | `/api/supply/sandbox/trigger` | Disparar un análisis sandbox |
| `GET` | `/api/supply/sandbox/status/:owner/:repo/:runId` | Polling del estado |
| `POST` | `/api/supply/sandbox/analyze` | Descargar y analizar telemetría |

---

## 8. Guía de Contribución

### Añadir nuevas reglas de detección

1. Edita el archivo YAML apropiado en `scanner/rules/`
2. Las reglas se cargan automáticamente al iniciar el servidor
3. Formato:
   ```yaml
   - id: "rule-unique-id"
     name: "Nombre descriptivo"
     category: "supply-chain|malware|secrets|ci-supply-chain"
     severity: 1-10
     pattern: "regex_pattern"
     description: "Explicación del vector de ataque"
   ```

### Añadir nuevos IOCs (dominios C2)

1. Editar `KNOWN_C2_DOMAINS` en `scanner/threat_intel.js`
2. Incluir: `domain`, `campaign`, `description`, `severity`, `year`
3. Añadir el IOC como comentario en `SECURITY_AUDIT.md`

### Seguridad en contribuciones

- ❌ NUNCA usar `shell: true` en `execFileSync`
- ❌ NUNCA interpolar inputs del usuario en strings de comandos
- ❌ NUNCA hacer llamadas de red en módulos de análisis estático
- ✅ SIEMPRE validar inputs con `sanitizer.js` antes de usarlos
- ✅ SIEMPRE envolver análisis en try/catch (no-fatal)
- ✅ SIEMPRE limitar el tamaño de inputs (protección DoS)
