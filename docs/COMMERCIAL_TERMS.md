# Sentinel Commercial Terms

Version 1.0 — Effective April 22, 2026

This document describes the commercial licensing model for Sentinel Security
Engine. It is a supplementary guide to the formal license in
[LICENSE.md](../LICENSE.md). In case of conflict, LICENSE.md prevails.

---

## Commercial Trigger Matrix

The following table defines exactly when a commercial license is required.

| Scenario | License Required | Rationale |
|---|---|---|
| Developer uses Sentinel to scan their own projects | No | Personal use |
| Company uses Sentinel internally to audit its own codebase | No | Organizational internal use |
| Security team runs Sentinel in their CI/CD pipeline | No | Internal tooling |
| Consultant uses Sentinel as an **auxiliary tool** (not core value) | No | Professional internal use |
| Agency offers "Sentinel-powered audits" (Material Dependency) | **Yes** | Managed service |
| Company forks Sentinel and sells it as a product | **Yes** | Commercial redistribution |
| Startup integrates Sentinel engine into their SaaS platform | **Yes** | Embedded integration |
| Any redistribution of **modified versions** for profit | **Yes** | Commercial derivative work |

---

## What Counts as a "Derivative Work" & Material Dependency

Para proteger el valor de Sentinel, definimos el concepto de **Dependencia Material**:

1. **Dependencia Material**: Un servicio o producto tiene dependencia material si el valor entregado al cliente final reside predominantemente en la lógica de decisión, orquestación de riesgo o reportes generados por Sentinel.
2. **Uso de Consultoría Permitido**: Se permite el uso de Sentinel por consultores independientes siempre que la herramienta sea secundaria al análisis humano predominante y no se venda como un "Sentinel-Service" automatizado.
3. **Forks con Ánimo de Lucro**: Cualquier redistribución de una versión modificada de Sentinel que se utilice para generar ingresos (directos o indirectos) requiere una licencia comercial explícita.

---

## Audit Integrity & Partner Status

Sentinel implementa una Capa de Confianza para diferenciar auditorías oficiales de usos no verificados:

1. **Certified Audits**: Solo los reportes firmados con una **Enterprise Key** válida y emitidos por una entidad en el **[Partner Registry](PARTNERS.md)** se consideran certificados.
2. **Compliance Risk**: El uso de Sentinel en entornos corporativos sin licencia o la eliminación de marcas de integridad constituye un riesgo de cumplimiento legal y anula la validez del reporte ante terceros.

---

## Pricing Model

Commercial licenses are negotiated on a case-by-case basis. Pricing factors
include:

- Scale of deployment (number of repositories, pipelines, or users).
- Nature of integration (embedded vs. standalone).
- Revenue model of the licensee's product.
- Duration of the agreement.

---

## How to Obtain a Commercial License

Contact the Licensor through any of the following channels:

- **GitHub**: [github.com/javier20dev25](https://github.com/javier20dev25)
- **Email**: sentinel-licensing@proton.me

All commercial inquiries will receive a response within 5 business days.

---

## Enforcement

The Licensor reserves the right to:

1. Request proof of compliance from organizations using Sentinel.
2. Revoke access to future updates for entities found in violation.
3. Pursue legal remedies for unauthorized commercial use, as defined in
   LICENSE.md.

Compliance is determined by the definitions in LICENSE.md, not by this
document.

---

## Conversion to MIT

On **April 22, 2029**, the Licensed Work automatically converts to the
**MIT License**, at which point all commercial restrictions are permanently
removed.
