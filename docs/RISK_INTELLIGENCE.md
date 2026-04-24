# Sentinel Risk Intelligence Infrastructure (v2.0)

Sentinel ha evolucionado hacia una **Infraestructura de Decisión Probabilística**. Este documento detalla la lógica matemática y la arquitectura de orquestación de la versión 3.7.1, que permite a Sentinel arbitrar entre múltiples fuentes de inteligencia con un enfoque defensivo.

## 1. Filosofía: "Autonomous Decision, Human Oversight"

La arquitectura de Riesgo de Sentinel v3.7 se basa en la **Asimetría de Inteligencia**. El motor no solo detecta, sino que decide la "Fuerza de Bloqueo" basada en la convergencia de señales internas (SARB) y externas.

- **Signals (Inputs)**: Heurísticas, firmas YAML, indicadores de compromiso (IOCs), auditoría de dependencias.
- **Orchestrator (Engine)**: Aplica pesos contextuales y agregación no lineal.
- **Verdict (Output)**: Clasificación en Bandas Tácticas (P0-P4) y ROI de mitigación.

---

## 2. El Modelo Matemático de v3.7

### 2.1. Agregación Probabilística de Riesgo ($R$)

Para evitar la fatiga por acumulación lineal de alertas (donde 10 alertas bajas parecerían una crítica), Sentinel utiliza un modelo de **Probabilidad de Compromiso**:

$$R = 1 - \prod_{i=1}^{n} (1 - (r_i \times w_i))$$

- $r_i$: Riesgo base de la señal $i$ (normalizado $0-1$).
- $w_i$: Peso contextual (ej. $w=1.3$ para archivos en la raíz, $w=0.7$ para carpetas de tests).

### 2.2. Cuantización y Jitter (Oracle Protection)

En modo Oráculo, el riesgo calculado se discretiza para evitar ataques de inversión de modelo:

- **Buckets**: $\{0, 0.25, 0.50, 0.75, 1.0\}$.
- **Stable Jitter**: Ruido estocástico basado en el fingerprint del repo, garantizando que el reporte sea reproducible pero no exploitable.

---

## 3. Bandas Tácticas de Riesgo (P0-P4)

Sentinel clasifica el riesgo agregado en 5 bandas de acción inmediata:

| Band | Severity | Priority | Decision Engine Action |
| :--- | :--- | :--- | :--- |
| **CRITICAL** | 0.95 - 1.00 | **P0** | **BLOCK**: Amenaza activa o altísima probabilidad de compromiso. |
| **HIGH** | 0.60 - 0.95 | **P1** | **BLOCK**: Señal fuerte de intención maliciosa o supply chain attack. |
| **MODERATE** | 0.35 - 0.60 | **P2** | **REVIEW**: Requiere auditoría manual antes de permitir el merge. |
| **LOW** | 0.15 - 0.35 | **P3** | **MONITOR**: Bajo riesgo, registrado para análisis de deriva. |
| **NEGLIGIBLE**| 0.00 - 0.15 | **P4** | **PASS**: Sin impacto significativo en la postura de seguridad. |

---

## 4. Perfiles de Decisión (Thresholds)

| Perfil | $Threshold$ | Enfoque Operativo |
| :--- | :--- | :--- |
| **strict** | 0.55 | Zero-trust. Bloquea ante la mínima acumulación de señales inciertas. |
| **balanced** | 0.70 | Producción estándar. Optimizado para velocidad y seguridad. |
| **relaxed** | 0.90 | Consultivo. Solo bloquea amenazas determinísticas extremas. |

---

## 5. Explicabilidad y ROI de Mitigación

Cada veredicto de Sentinel incluye un análisis de **ROI de Seguridad**:
- **Reduction**: Proporción en la que bajaría el riesgo agregado si se elimina un hallazgo específico.
- **Tactical Advice**: Guía de remediación para descender de banda (ej: de P1 a P2).
- **Oracle Redaction**: En modo no autorizado, solo se muestra la banda de riesgo y el veredicto general.
