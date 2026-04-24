# Sentinel Playbooks — Guía del Lenguaje (v0.1)

Los **Sentinel Playbooks** son archivos `.sentinel` que permiten orquestar los motores de seguridad de Sentinel de forma declarativa: sin escribir código, sin encadenar 12 comandos manualmente.

Piensa en ellos como **macros de seguridad con cerebro**.

---

## Inicio Rápido

### Nivel 1 — Tu primer playbook

Crea un archivo `security.sentinel`:

```sentinel
workflow "protect-manifest" {
  target repo "./"
  profile strict

  when change in ["package.json"] {
    run pr_policy_engine
    block
  }
}
```

Valídalo:

```bash
sentinel playbook validate security.sentinel
```

Ejecútalo:

```bash
sentinel playbook run security.sentinel --context '{"event":{"changedFiles":["package.json"]}}'
```

---

## Estructura del Lenguaje

### Archivo

Extensión: **`.sentinel`**

Cada archivo contiene uno o más `workflow`.

### Workflow

Unidad principal de automatización.

```sentinel
workflow "nombre" {
  target ...
  profile ...

  when <condición> {
    ...
  }
}
```

### Target

Define el objeto que se analiza.

```sentinel
target repo "./"
target pr "owner/repo#42"
target package
target file "src/security/auth.js"
```

### Profile

Perfil de decisión que afecta umbrales y comportamiento por defecto.

```sentinel
profile strict     // CI/CD — bloquea ante duda
profile balanced   // Balance entre seguridad y UX
profile oracle     // Restringe inteligencia para no autorizados
```

---

## Condiciones (`when` / `if`)

### `when change in [...]` (azúcar sintáctico)

Dispara el bloque cuando se modifican archivos específicos:

```sentinel
when change in ["package.json", "src/security/*"] {
  ...
}
```

### `when install package`

Dispara cuando se detecta una instalación de paquete:

```sentinel
when install package {
  run supply_chain_shield
  ...
}
```

### Condiciones generales

```sentinel
if risk.band == "CRITICAL" { block }
if repo.authorized == false { redact evidence }
if signals.count >= 3 and risk.band in ["HIGH", "CRITICAL"] { block }
```

### Operadores de comparación

| Operador | Ejemplo |
|---|---|
| `==` | `risk.band == "HIGH"` |
| `!=` | `policy.mode != "advisory"` |
| `>=`, `<=`, `>`, `<` | `signals.count >= 3` |
| `in` | `risk.band in ["HIGH", "CRITICAL"]` |
| `contains` | `event.branch contains "release"` |
| `matches` | `package.name matches "ax[io]s"` |
| `starts_with` | `repo.path starts_with "src/"` |
| `ends_with` | `event.source ends_with ".json"` |

### Operadores lógicos

```sentinel
if risk.band == "CRITICAL" and repo.authorized == false { block }
if not repo.authorized { redact evidence }
if risk.band == "HIGH" or signals.count >= 5 { sandbox verify }
```

Precedencia: `not` > comparaciones > `and` > `or`

---

## Motores (`run`)

Los motores son los cerebros de Sentinel. Los invocas con `run`:

```sentinel
run risk_orchestrator
run supply_chain_shield
run pr_policy_engine
run policy_engine
run scanner
```

Con argumentos opcionales:

```sentinel
run risk_orchestrator mode="oracle"
```

### Motores disponibles en v0.1

| Motor | Qué hace |
|---|---|
| `risk_orchestrator` | Agrega señales y emite un veredicto de riesgo |
| `supply_chain_shield` | Evalúa paquetes, detecta typosquatting |
| `pr_policy_engine` | Evalúa archivos modificados contra reglas de política |
| `policy_engine` | Resuelve niveles de exposición y modo de enforcement |
| `scanner` | Motor de análisis estático de archivos |

---

## Acciones

Las acciones son los verbos que Sentinel ejecuta. Son la salida del playbook.

### Acciones terminales (cambian el veredicto)

| Acción | Efecto |
|---|---|
| `allow` | Autoriza la operación |
| `block` | Bloquea la operación |
| `sandbox` | Escala a verificación aislada |
| `review` | Requiere aprobación humana |

### Acciones de efecto secundario (se registran pero no cambian el veredicto)

| Acción | Sintaxis | Efecto |
|---|---|---|
| `notify` | `notify admin channel "slack:#secops"` | Alerta a destinatarios |
| `redact` | `redact evidence, file_paths, lines` | Suprime inteligencia sensible |
| `audit` | `audit trace` | Registra evidencia forense |

---

## Variables de Contexto

Estas variables están disponibles para condiciones durante la ejecución:

### Repositorio
```
repo.path, repo.owner, repo.authorized, repo.fingerprint
```

### Usuario
```
user.name, user.permission
```

### Evento
```
event.type, event.branch, event.pr_number, event.source, event.changedFiles
```

### Riesgo (pobladas por `run risk_orchestrator`)
```
risk.score, risk.band, risk.confidence, risk.contributors
```

### Política (pobladas por `run pr_policy_engine`)
```
policy.rule, policy.mode, policy.verdict, policy.requires_review
```

### Paquete
```
package.name, package.publisher, package.age_days, package.downloads
package.typosquatting, package.postinstall_risk
```

### Señales
```
signal.source, signal.category, signal.weight, signals.count
```

---

## Ejemplos Completos

### 1. Proteger `package.json`

```sentinel
workflow "protect-package-json" {
  target repo "./"
  profile strict

  when change in ["package.json", "package-lock.json"] {
    run pr_policy_engine

    if risk.band == "CRITICAL" {
      block
      notify admin
      audit trace
    } else {
      allow
    }
  }
}
```

### 2. Firewall de Instalación

```sentinel
workflow "install-firewall" {
  target package
  profile balanced

  when install package {
    run supply_chain_shield

    if package.typosquatting == true {
      sandbox verify
      block
      notify admin
    } else {
      allow
    }
  }
}
```

### 3. Modo Oráculo (Privacidad)

```sentinel
workflow "oracle-privacy" {
  target repo
  profile oracle

  when repo.authorized == false {
    run risk_orchestrator mode="oracle"

    redact evidence, file_paths, lines

    if risk.band in ["HIGH", "HIGH_AGGREGATED", "CRITICAL"] {
      block
      audit trace
    } else {
      allow
    }
  }
}
```

### 4. Detección de Riesgo Distribuido

```sentinel
workflow "distributed-risk" {
  target repo
  profile strict

  when signals.count >= 3 and risk.band in ["HIGH_AGGREGATED", "CRITICAL"] {
    run risk_orchestrator
    block
    notify admin
    audit trace
  }
}
```

### 5. PR Firewall Completo

```sentinel
workflow "pr-firewall" {
  target pr
  profile strict

  when change in ["src/security/*", "db/schema.sql", "package.json"] {
    run pr_policy_engine
    run risk_orchestrator

    if risk.band == "CRITICAL" {
      block
      notify admin channel "slack:#secops"
      audit trace
    } else if policy.requires_review == true {
      review from "security-team"
    } else {
      allow
    }
  }
}
```

---

## Comandos CLI

```bash
sentinel playbook validate <file.sentinel>    # Verificar sintaxis
sentinel playbook compile  <file.sentinel>    # Emitir JSON compilado
sentinel playbook run      <file.sentinel>    # Ejecutar con contexto
```

### Ejecutar con contexto personalizado

```bash
sentinel playbook run policy.sentinel --context '{"event":{"changedFiles":["package.json"]},"risk":{"band":"HIGH"}}'
```

---

## Comentarios

```sentinel
// Comentario de una línea

/*
  Comentario
  de bloque
*/
```

---

## Lo que NO soporta v0.1

Para mantener el lenguaje simple, predecible y seguro:

- ❌ Funciones definidas por el usuario
- ❌ Loops (`while`, `for`)
- ❌ Variables mutables
- ❌ Imports de módulos externos
- ❌ Ejecución de código arbitrario
- ❌ Acceso libre al sistema de archivos
- ❌ Networking

> [!IMPORTANT]
> Sentinel Playbooks describe **políticas**, no programan software general. Si necesitas lógica arbitraria, usa los scripts de tu CI/CD y llama a `sentinel` como herramienta.

---

## Fail-Closed

Si algo falla durante la ejecución de un playbook:

| Situación | Resultado |
|---|---|
| Sintaxis inválida | Error con línea y columna |
| Motor no encontrado | Warning, ejecución continúa |
| Motor crashea | Veredicto automático: `block` |
| Sin veredicto explícito (profile `strict`) | `block` |
| Sin veredicto explícito (profile `balanced`) | `allow` |
