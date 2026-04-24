# Sentinel: Oracle Intelligence Layer & Information Asymmetry Engine

## Abstract

La version 3.7.1 de Sentinel introduce la Capa de Inteligencia del Oráculo (Oracle Mode), una infraestructura de decision diseñada para gestionar la asimetria de informacion en el analisis de codigo fuente. Este sistema permite la ejecucion de inspecciones de seguridad sobre activos de software mientras restringe la extraccion de inteligencia tactica granular a actores no autorizados. Mediante el uso de cuantizacion estocastica, fingerprinting hibrido y resolucion de propiedad multi-señal, Sentinel se establece como una superficie de inteligencia controlada.

## 1. Arquitectura de Asimetria de Informacion

La premisa fundamental de esta capa es el control del output sobre el input. El sistema distingue dos estados operativos basados en la resolucion de identidad del activo:

- **Authorized Intelligence Mode**: Acceso completo a metadatos de riesgo, telemetria de lineas de codigo y sugerencias de remediacion exacta.
- **Oracle Redacted Mode**: Acceso limitado a veredictos deterministas y puntuaciones de riesgo cuantizadas. Los detalles de implementacion de la vulnerabilidad permanecen ofuscados para prevenir la reconstruccion del mapa de fallos.

## 2. Motor de Cuantizacion con Jitter Estable (Anti-Oracle Protection)

Para mitigar ataques de canal lateral orientados a la inversion del modelo mediante cambios incrementales en el codigo, se ha implementado un algoritmo de cuantización no lineal:

### 2.1 Ecuacion de Discretizacion
El score de riesgo crudo ($R_c$) se mapea a un conjunto discreto de buckets $B = \{0.0, 0.25, 0.50, 0.75, 1.0\}$. El score reportado ($R_r$) en modo Oráculo se define como:

$$R_r = \text{nearest}(R_c, B) + \epsilon$$

Donde $\epsilon$ representa un **Jitter Estable** derivado de:

$$\epsilon = \text{Hash}(F \cdot U \cdot T) \pmod{\delta}$$

- $F$: Fingerprint hibrido del repositorio.
- $U$: Identidad del usuario (GitHub ID).
- $T$: Ventana temporal de sesion (1 hora).
- $\delta$: Magnitud maxima del jitter ($\pm 0.03$).

Este enfoque garantiza que el ruido sea reproducible y auditable dentro de una misma sesion, pero matematicamente no invertible para un observador externo.

## 3. Fingerprinting Hibrido de Activos (Identity Anchoring)

La identidad del repositorio no depende de metadatos volatiles. Sentinel genera una huella digital hibrida compuesta por tres vectores de integridad:

1. **Structural Vector**: Grafo de nombres y tamaños de archivos en el root del proyecto.
2. **Dependency Vector**: Serializacion del arbol de dependencias declarado en descriptores de paquete (e.g., package.json).
3. **Partial Content Vector**: SHA-256 de los primeros 1024 bytes de archivos criticos de configuracion e indexacion.

La colision de estos vectores permite identificar el activo incluso tras operaciones de renombrado o inyeccion de archivos basura (anti-evasion).

## 4. Resolucion de Propiedad Multi-Señal

El sistema de gobernanza requiere la convergencia de al menos **dos señales positivas** para autorizar el acceso a la inteligencia completa:

- **Git Provenance**: Coincidencia entre el remote origin y la identidad autenticada en GitHub CLI.
- **Permission Scope**: Validacion de roles de escritura (ADMIN, MAINTAIN, WRITE) via API de GitHub.
- **Trusted Local Context**: Verificacion de proximidad en el Sistema de Archivos (Homedir) y registro previo en la base de datos local del agente.

## 5. Auditoria Forense e Intencionalidad

Cada iteracion de escaneo se registra en un log de auditoria persistente (`sentinel-audit.jsonl`). El sistema clasifica el intento de escaneo en tres categorias:

- **Standard**: Operacion autorizada bajo flujo normal de desarrollo.
- **Authorized CI**: Operacion en entornos de integracion continua verificada.
- **Interactive Oracle Attempt**: Multiples escaneos sobre el mismo fingerprint en modo Oráculo, indicando una posible exploracion adversaria de la superficie de riesgo.

## 6. Resultados de Validacion de Estrés

En escenarios de agregación probabilística ("Death by a Thousand Cuts"), el motor ha demostrado una precision del 100% en la activacion de bloques preventivos:

- **Aggregated Risk**: 98% (derivado de 10 señales de severidad moderada).
- **Risk Band**: CRITICAL [P0].
- **Mitigation ROI**: Calculado en base a la reduccion contrafactual de probabilidad de compromiso.
