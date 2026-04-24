# Sentinel — Documentación de Arquitectura (v3.8.0)

> **Versión:** 3.8.0 (The Universal Trust Release)
> **Última actualización:** Abril 2026
> **Estado:** Enterprise Hardened + Supply Chain Firewall

---

## Índice

1. [Visión General](#1-visión-general)
2. [Estructura de Archivos](#2-estructura-de-archivos)
3. [Dependency Trust Engine (v3.8)](#3-dependency-trust-engine)
4. [Ecosystem Adapters](#4-ecosystem-adapters)
5. [Capas de Seguridad (Defense in Depth)](#5-capas-de-seguridad)
6. [Motor de Decisión (Risk Orchestrator)](#6-motor-de-decisión)
7. [Capa de Inteligencia del Oráculo](#7-capa-de-inteligencia-del-oráculo)
8. [Auditoría Forense](#8-auditoría-forense)

---

## 1. Visión General

Sentinel es una infraestructura de decisión gubernamental para la seguridad de la cadena de suministro (**Supply Chain Security**). Su arquitectura evoluciona del escaneo estático pasivo a una **Api de Decisión Privada** y un **Firewall de Instalación Proactivo**.

### Principios de diseño (v3.8)

| Principio | Implementación |
|---|---|
| **Universal Trust** | Verificación agnóstica de ecosistemas (npm, pip, docker) |
| **Information Asymmetry** | Diferenciación estricta entre reporte Autorizado vs. Redactado |
| **Probabilistic Risk** | Agregación no lineal de señales: $1 - \prod(1 - r_i)$ |
| **Fail-Closed Governance** | Si el análisis falla, el veredicto es BLOCK por defecto |

---

## 2. Estructura de Archivos

```
src/ui/backend/
│
├── scanner/
│   ├── index.js              ← Orquestador Asíncrono (Repo Scanning)
│   ├── supply_chain_shield.js ← Dispatcher del Firewall de Instalación
│   ├── policy_engine.js      ← Lógica de Enforcement (Strict vs Advisory)
│   ├── adapters/             ← Plugins por ecosistema
│   │   ├── npm_adapter.js
│   │   ├── pip_adapter.js
│   │   └── docker_adapter.js
│   ├── file_classifier.js    ← Clasificación Granular de tipos de archivo
│   ├── risk_orchestrator.js  ← Motor de riesgo v2.0 (Bands P0-P4)
│   └── rules/                ← Definiciones YAML
│
├── lib/
│   ├── cmd_resolver.js       ← Abstracción de ejecución cross-platform (Win/Unix)
│   ├── gh_bridge.js          ← Motor de resolución de propiedad multi-señal
│   └── ci_sandbox.js         ← Orquestador de Dynamic Sandbox
│
└── cli/
    ├── index.js              ← Punto de entrada (Comandos v3.8)
    └── guard.js              ← Provisión de alias de shell para intercepción
```

---

## 3. Dependency Trust Engine (v3.8)

El motor de confianza gestiona el ciclo de vida de una instalación:

1. **Intercepción**: Sentinel Guard (vía alias) redirige comandos como `npm install` al CLI de Sentinel.
2. **Trust Cache**: Verificación O(1) en `trust-cache.json` con TTL de 7 días.
3. **Multi-Factor Analysis**: Evaluación de Typosquatting (Levenshtein), Lifecycle Scripts y Reputación.
4. **Verdict**: Emisión de veredicto (SAFE, SUSPICIOUS, BLOCK).

---

## 4. Ecosystem Adapters

Cada adaptador encapsula la "física" de su ecosistema:
- **NpmAdapter**: Analiza `package.json` y scripts de ciclo de vida.
- **PipAdapter**: Audita `pyproject.toml` y vectores de confusión de nombres en PyPI.
- **DockerAdapter**: Evalúa tiers de confianza del publisher e integridad de la imagen (digests).

---

## 5. Capas de Seguridad (v3.8)

Sentinel implementa un pipeline integrado de **Firewall + Scanner**:

```
[Target Ingress (Install/Commit)]
      │
      ▼
┌─────────────────────────────┐  NIVEL 0: Firewall Layer (v3.8)
│  Dependency Trust Engine    │  → Ecosystem Adapters
│  & Sentinel Guard           │  → Trust Cache (O1)
└─────────────────────────────┘
      │
      ▼
┌─────────────────────────────┐  NIVEL 1: Oracle Layer
│  Ownership & Governance     │  → Multi-signal Identity
└─────────────────────────────┘
      │
      ▼
┌─────────────────────────────┐  NIVEL 2: Static Engine
│  Inspection Pipeline        │  → Rules, AST, Entropy, Unicode
└─────────────────────────────┘
      │
      ▼
┌─────────────────────────────┐  NIVEL 3: Risk Orchestration
│  Probabilistic Aggregator    │  → Non-linear scoring
└─────────────────────────────┘
      │
      ▼
┌─────────────────────────────┐  NIVEL 4: Forensic Audit
│  Terminal Metadata & Log     │  → Append-only audit.jsonl
│  (Intent Classification)     │  → Oracle attack detection
└─────────────────────────────┘
```

---

## 6. Auditoría Forense

Cada veredicto emite un `TraceID` firmado con HMAC-SHA256, permitiendo la trazabilidad completa desde la terminal del desarrollador hasta el log de cumplimiento institucional. El log `sentinel-audit.jsonl` clasifica la intencionalidad (Standard, CI, Oracle Attempt) para prevenir ataques de reversión del modelo.
