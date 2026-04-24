# Sentinel Governance & Policy Framework (v3.8.0)

Este documento establece las normas de gobernanza, privacidad y uso ético de Sentinel v3.8.0 — Supply Chain Enforcement Layer.

> [!IMPORTANT]
> **Resumen Ejecutivo (v3.8)**:
> Sentinel opera bajo un modelo de **Zero-Telemetry** y **Privacy-Preserving Intelligence**. La introducción del **Supply Chain Firewall** (Trust Engine + Ecosystem Adapters + Guard Mode) amplía el perímetro de protección de Sentinel desde el análisis de repositorios hasta la **intercepción proactiva de instalaciones de dependencias**. El Dual Enforcement Mode (strict/advisory) garantiza que la protección sea firme en CI/CD y útil en entornos de desarrollo local. La Trust Cache proporciona velocidad nativa sin comprometer la seguridad.

---

## 1. Data Sovereignty & Privacy Policy

Sentinel se fundamenta en el principio de **Soberanía de Datos Local**.

### Compromiso de Cero Telemetría
- **Privacidad Total**: Sentinel NO recolecta, transmite ni almacena datos de uso, telemetría o patrones de código en servidores externos.
- **Análisis Offline**: El 100% del análisis (AST, Heurística, Entropía, Trust Engine) se ejecuta en la máquina del usuario.
- **Trust Cache Local**: Los veredictos persistidos en `~/.sentinel/trust-cache.json` nunca se sincronizan con servidores externos.
- **Auditoría Local**: Los registros de auditoría (`audit.jsonl`) permanecen exclusivamente en el entorno local.

---

## 2. Supply Chain Firewall Policy (v3.8 — NUEVO)

Con la versión 3.8, Sentinel implementa un **Firewall de Instalación de Dependencias** que opera en el punto cero del riesgo: antes de que cualquier paquete ejecute código en el sistema del desarrollador.

### 2.1 Principio de Enforcement Dual

- **Strict Mode**: Activado automáticamente en entornos CI/CD. Los veredictos `BLOCK` producen `exit 1` y detienen el pipeline. Este modo no puede ser sobrescrito por flags de usuario en pipelines con `CI=true`.
- **Advisory Mode**: Disponible en entornos interactivos locales. Los veredictos `BLOCK` generan advertencias detalladas pero no impiden la instalación. El evento queda registrado en el audit trail.

**La decisión de qué modo aplicar es determinista, no configurable a discreción en CI.**

### 2.2 Guard Mode — Consentimiento Explícito

El comando `sentinel guard enable` modifica el perfil de shell del usuario para interceptar gestores de paquetes (`npm`, `pip`, `docker`, etc.). Este cambio:
- Requiere ejecución explícita del comando por parte del usuario.
- Es completamente reversible con `sentinel guard disable`.
- Solo afecta al perfil del usuario que ejecuta el comando (no requiere privilegios de sistema).
- Es transparente: las modificaciones al perfil son legibles en texto plano.

### 2.3 Trust Cache — Política de Expiración

- Los veredictos se almacenan con un TTL de **7 días**.
- Los paquetes marcados manualmente como `TRUSTED` o `BLOCKED` no expiran.
- La caché puede ser auditada con `sentinel trust list` y limpiada con `sentinel trust clear`.

---

## 3. Oracle & Information Asymmetry Policy

Con la versión 3.7.1 (vigente en v3.8), Sentinel implementa una política de asimetría de información:

- **Authorized Access**: Solo usuarios con señales de propiedad verificadas acceden a reportes completos con nombres de señales y descripciones técnicas.
- **Restricted Access**: Actores no autorizados reciben únicamente el veredicto (`BLOCK/SAFE/SUSPICIOUS`) sin inteligencia técnica subyacente.

**Esto previene que Sentinel sea usado como herramienta de reconocimiento ofensivo por atacantes.**

---

## 4. Responsible Use & Ethics

Sentinel es una herramienta de seguridad defensiva. Su uso debe alinearse con:
- **Auditoría Autorizada**: Prohibido el uso de Sentinel para reconocimiento ofensivo de repositorios de terceros sin autorización explícita.
- **Guard Mode Ético**: El Guard Mode solo debe activarse en máquinas propias o con consentimiento del propietario del sistema.
- **Integridad del Motor**: Modificar el motor para evadir las protecciones del Oráculo o el Trust Engine constituye una violación de los términos de uso.

---

## 5. Licensing & Commercial Terms (v3.8 actualizado)

Sentinel utiliza la **Business Source License 1.1 (BSL 1.1)** con conversión a MIT en 2029.

### Uso No-Comercial (Sin Costo)
1. **Uso Personal**: Desarrolladores independientes en proyectos personales.
2. **Uso Interno Organizacional**: Empresas que usan Sentinel para proteger su propio entorno de desarrollo.
3. **Investigación/Educación**: Uso académico y contribuciones comunitarias.

### Triggers de Licencia Comercial (v3.8 — actualizado)
Se requiere licencia comercial para:
1. Ofrecer Sentinel como **SaaS** o servicio gestionado.
2. Integrar el **Trust Engine o los Adapters** en productos comerciales de terceros.
3. Ofrecer el **Guard Mode como servicio** en entornos multi-tenant.
4. Redistribución del Supply Chain Firewall como componente de plataformas de seguridad.
5. Consultoría basada en redistribución o hosting de Sentinel.

Para consultas comerciales: **sentinel-licensing@proton.me**

---

## 6. Audit Integrity & Forensic Accountability

Sentinel implementa una Capa de Confianza Criptográfica:

- **TraceID**: Cada veredicto (instalación o scan) emite un ID firmado con HMAC-SHA256.
- **Trust Cache Hashes**: Cada entrada en caché incluye un hash de 8 caracteres para trazabilidad forense.
- **Audit Log**: `~/.sentinel/audit.jsonl` — append-only, compatible con SIEM.
- **Enterprise Reports**: Firmados con License Key única. Solo estos son válidos para auditorías de cumplimiento institucional.

---

## 7. Compliance & Enforcement

La eliminación o alteración de marcas de agua, metadatos de licencia o firmas de integridad en outputs de Sentinel constituye violación de BSL 1.1.

Para verificación de legitimidad: **sentinel-compliance@proton.me**

---

## 1. Data Sovereignty & Privacy Policy

Sentinel se fundamenta en el principio de **Soberanía de Datos Local**.

### Compromiso de Cero Telemetría
- **Privacidad Total**: Sentinel NO recolecta, transmite ni almacena datos de uso, telemetría o patrones de código en servidores externos. 
- **Análisis Offline**: El 100% del análisis estático (AST, Heurística, Entropía) se ejecuta en la máquina del usuario.
- **Auditoría Local**: Los registros de auditoría (`audit.jsonl`) y la inteligencia de amenazas permanecen exclusivamente en el entorno local del agente.

---

## 2. Oracle & Information Asymmetry Policy

Con la versión 3.7.1, Sentinel implementa una política de asimetría de información para proteger el IP de seguridad:

- **Authorized Access**: Solo usuarios con señales de propiedad verificadas (Git Remote + GitHub Auth + DB Match) acceden a reportes completos.
- **Redaction Policy**: Actores no autorizados reciben veredictos cuantizados con jitter estable para prevenir la reconstrucción de vulnerabilidades mediante ataques de oráculo.

---

## 3. Responsible Use & Ethics

Sentinel es una herramienta de auditoría defensiva. Su uso debe alinearse con la ética de ciberseguridad:
- **Auditoría Autorizada**: Se prohibe el uso de Sentinel para el reconocimiento ofensivo de repositorios de terceros sin autorización explícita.
- **Integridad del Motor**: La modificación del motor para evadir las protecciones del Oráculo o para usos maliciosos constituye una violación de los términos de uso.

---

## 4. Licensing & Commercial Terms

Sentinel utiliza la **Business Source License 1.1 (BSL 1.1)** con un horizonte de conversión a MIT en 2029.

### Definición de Uso No-Comercial (Sin Costo)
1. **Uso Personal**: Desarrolladores independientes en proyectos personales.
2. **Uso Interno Organizacional**: Empresas que utilizan Sentinel para auditar su propio código fuente, donde los resultados no se venden ni se exponen a terceros.
3. **Investigación/Educación**: Uso académico y contribuciones a la comunidad.

### Triggers de Licencia Comercial (Requiere Pago)
Se requiere una licencia comercial firmada para:
1. Ofrecer Sentinel como **Software-as-a-Service (SaaS)**.
2. Integrar Sentinel en productos o servicios comerciales de terceros.
3. Prestar servicios de consultoría basados en la redistribución o hosting de Sentinel.
4. Forks monetizados o derivados que compitan con la oferta oficial.

Para consultas comerciales: **sentinel-licensing@proton.me**

---

## 5. Audit Integrity & Authentic Verification

Sentinel implementa una Capa de Confianza Criptográfica para garantizar la integridad de sus reportes frente a manipulaciones de terceros.

### 5.1. Niveles de Verificación de Reporte
1. **Unverified / Community**: Reportes generados por la edición gratuita. Incluyen una firma HMAC basada en una clave pública. Válidos para uso interno y personal.
2. **Enterprise-Certified**: Reportes firmados con una License Key única del licenciatario oficial. Solo estos reportes se consideran válidos para evaluaciones de seguridad institucional y auditorías de cumplimiento comercial.

### 5.2. Verificación de Proveedores de Servicio
Cualquier entidad que proporcione auditorías basadas en Sentinel debe figurar en el **[Registro Oficial de Socios](PARTNERS.md)**. Se recomienda a las empresas finales verificar la firma del reporte y el estatus del proveedor antes de aceptar los resultados.

---

## 6. Compliance & Enforcement Policy

### Reconocimiento de Manipulación
La eliminación o alteración de las marcas de agua, metadatos de licencia o firmas de integridad integradas en los outputs de Sentinel constituye una violación de los términos de la Business Source License 1.1. 

### Acción Legal
El uso comercial no autorizado de Sentinel (SaaS, redistribución o consultoría sin licencia) resultará en la revocación automática de los derechos de uso y podrá estar sujeto a acciones legales bajo las leyes de propiedad intelectual internacionales.

Para consultas de verificación de legitimidad: **sentinel-compliance@proton.me**
