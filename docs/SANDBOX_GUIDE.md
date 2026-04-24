# Sentinel v3.7: Dynamic Sandbox Guide

## Overview

El Dynamic Sandbox de Sentinel proporciona análisis conductual de dependencias mediante la ejecución en entornos efímeros aislados (GitHub Actions). Esta capa es crítica para detectar amenazas invisibles al análisis estático, como droppers binarios, exfiltración de red en runtime y módulos WebAssembly ofuscados.

---

## ⚖️ Static Analysis vs. Dynamic Sandbox

| Feature | Static Analysis (AST/Heuristics) | Dynamic Sandbox |
|---|---|---|
| **Efectividad** | Cada commit y Pull Request. | PRs de alto riesgo o nuevas dependencias. |
| **Latencia** | < 2 segundos. | 3-10 minutos (Overhead de CI). |
| **Visibilidad** | Estructura, secretos, patrones conocidos. | Conexiones de red, integridad de lockfile. |
| **Costo** | Mínimo (CPU Local). | Créditos de GitHub Actions. |
| **Gobernanza** | Primera línea de defensa obligatoria. | Validación dirigida para activos sospechosos. |

---

## 🔄 Flujo de Orquestación (v3.7)

1. **Generación de Workflow**: `sntl sandbox generate` para obtener el template YAML.
2. **Setup**: Instalar `.github/workflows/sentinel-sandbox.yml` en la rama principal.
3. **Trigger**: Ejecutar `sntl sandbox trigger <repo> <branch> --wait` ante cambios en dependencias.
4. **Ingesta de Señales**: Los resultados del sandbox se inyectan en el **Risk Orchestrator v2**, influyendo en la Banda de Riesgo (**P0-P4**) del reporte final.

---

## 🛡️ Operación en "Passive Mode"

Sentinel implementa un modelo de seguridad pasivo: no requiere permisos de escritura en el repositorio remoto. Se apoya en un flujo pre-instalado disparado via `workflow_dispatch` API. Esto garantiza que el IP de seguridad y la configuración de CI/CD permanezcan inmutables para el agente local.

---

## 🔬 Caso de Estudio: Ataque "Axios 2026"

### Evaluación de Resultados (`sntl sandbox analyze`)

En la v3.7, el análisis del sandbox no genera alertas aisladas, sino que escala la postura de seguridad del activo:

```text
📥 Downloading artifacts for run #99283741...
🔍 Injecting signals into Risk Orchestrator...

🚨 SANDBOX CRITICAL SIGNALS DETECTED:

[P0] UNEXPECTED_NETWORK_CONNECTIONS
Evidence: tcp 45.33.22.11:443 [ESTABLISHED] -> Domain: sfrclak.com

[P1] RUNTIME_REGISTRY_OVERRIDE
Evidence: npm_config_registry = https://malicious-registry.host/

[P1] WASM_PERSISTENCE
Evidence: node_modules/axios/lib/core/auth.wasm (Entropy: 7.8)

--------------------------------------------------
AGGREGATED RISK: 0.99 [CRITICAL]
TACTICAL BAND: P0 - IMMEDIATE BLOCK
REDUCCIÓN DE RIESGO ESTIMADA (ROI): 94% tras remediación.
--------------------------------------------------
```

---

## 🔍 Troubleshooting

### Error: "Workflow not found" (404)
Asegúrese de que el archivo YAML existe en la rama por defecto del repositorio remoto. Use `sntl sandbox generate` para verificar el nombre exacto requerido.

### Error: "Secondary Rate Limit" (403)
GitHub limita el disparo frecuente de workflows. Espere 60 segundos antes de re-intentar o use `gh auth refresh -s workflow`.

### Telemetría Vacía
Si el paso `npm install` falla catastróficamente antes de la captura de telemetría, Sentinel reportará un error de ejecución. Revise los logs de la Action para descartar problemas de red o dependencias rotas.
