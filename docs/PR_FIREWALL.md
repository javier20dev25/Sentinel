# PR Firewall (Policy Enforcement)

El **PR Firewall** de Sentinel (v3.8.0) te permite establecer políticas de acceso granulares sobre archivos y carpetas de tu repositorio. Actúa como un guardián automatizado en tus Pull Requests, bloqueando modificaciones no autorizadas a nivel de CI/CD.

## ¿Por qué usar el PR Firewall?

- **Proteger configuraciones críticas:** Evita que atacantes o scripts modifiquen el `package.json` o `.github/workflows`.
- **Prevención Defensiva:** Actúa directamente en el ciclo de vida del CI/CD.

> [!WARNING]
> **Requisitos de la GitHub Checks API:**
> Para que Sentinel pueda **publicar Check Runs** (y bloquear merges de forma nativa en la UI de GitHub), el workflow debe ejecutarse bajo un token con permisos de escritura (`checks: write`). Si se requiere publicar verificaciones avanzadas desde sistemas externos, GitHub exige hacerlo mediante una **GitHub App** autorizada. 
> 
> En entornos locales, o si el CI carece de los permisos adecuados, Sentinel cambiará automáticamente a un modo **Dry-Run** (evaluando las políticas y retornando un exit code `1` para fallar el CI, pero sin intentar escribir en la Checks API nativa).

---

## 1. Instalación Rápida

La forma más rápida de proteger un archivo es usando el comando `protect`. 

Por ejemplo, para proteger tu `package.json`:

```bash
sentinel policy protect package.json
```

Esto generará la política y la guardará en `.sentinel/policies.json`. ¡Debes hacer commit de este archivo!

Luego, para instalar la acción automatizada que evalúa las Pull Requests:

```bash
sentinel pr hook
```

Esto generará el archivo `.github/workflows/sentinel-pr-firewall.yml`. Haz commit y empújalo a tu rama principal. A partir de ese momento, **todas las PRs serán evaluadas por Sentinel**.

---

## 2. Gestión de Políticas

Las políticas se gestionan vía CLI y se guardan como JSON dentro del directorio `.sentinel/`.

### Añadir Reglas

```bash
sentinel policy add --path "src/security/*" --rule "require-review" --reviewers "security-team"
```

**Parámetros:**
- `--path`: El archivo o carpeta a proteger (soporta wildcards simples como `/*`).
- `--rule`: `no-modify` (bloqueo total) o `require-review` (requiere aprobación).
- `--mode`: `strict` (falla el Check Run y bloquea el merge) o `advisory` (solo muestra una advertencia neutral).

### Listar Reglas Activas

```bash
sentinel policy list
```

### Eliminar Reglas

```bash
sentinel policy remove "src/security/*"
```

---

## 3. Override Local (Avanzado)

El archivo `.sentinel/policies.json` es la fuente de verdad (Source of Truth) y debe estar en tu control de versiones.

Si un administrador necesita aplicar reglas temporales en su máquina sin afectar al repositorio, puede crear un archivo `.sentinel/policies.local.json`. Las reglas aquí sobreescribirán las del archivo principal de manera local.

*Asegúrate de agregar `.sentinel/policies.local.json` a tu `.gitignore`.*

---

## 4. Modo Auditoría (Evaluación Local)

Puedes auditar una Pull Request abierta en cualquier repositorio sin necesidad de esperar al CI, usando el comando `pr scan`.

```bash
sentinel pr scan tu-usuario/tu-repositorio 123
```

*(Donde 123 es el número de la PR).*

**Modo Dry-Run Automático:** 
Si ejecutas este comando desde tu terminal local, Sentinel hará un *[DRY-RUN]*: Evaluará las reglas y te mostrará qué archivos estarían bloqueados, pero **NO intentará publicar un Check Run** en GitHub para evitar sobreescribir el estado oficial del repositorio. El flag `--ci` es el que habilita la publicación y bloqueo duro.

---

## 5. Casos de Uso y Alcance

### Alcance Mínimo (Adopción Básica)
El caso de uso más sencillo para equipos pequeños o proyectos open-source.
- **Proteger manifiestos:** Bloquear cambios en `package.json` para prevenir ataques de *Dependency Confusion* o *Typosquatting* inyectados por contributors externos.
  - Regla: `sentinel policy protect package.json`
- **Proteger flujos CI/CD:** Evitar modificaciones encubiertas en `.github/workflows/*` que puedan exfiltrar tokens.

### Alcance Máximo (Enterprise / Cross-Layer Enforcement)
Para empresas con equipos dedicados de seguridad y arquitectura Zero Trust.
- **Protección de Base de Datos:** Bloquear cambios en `/db/schema.sql` (Require-Review) para que solo el equipo de DBAs pueda aprobar la migración.
- **Protección de Core Security:** Reglas estrictas en `/src/security/*` asegurando que los wrappers criptográficos no sean alterados o debilitados.
- **Pre-Execution Security (PR Sandbox):** Cuando un atacante modifica un `package.json` en un PR, el Firewall detecta el cambio, simula la instalación en un Sandbox de GitHub Actions (aislado), analiza telemetría de red, e impide el merge si la dependencia hace callbacks a servidores C2 maliciosos.

---

## 6. Exclusión de Responsabilidades (Liability Disclaimer)

El PR Firewall de Sentinel está diseñado como una capa de mitigación de riesgos de Defensa en Profundidad (Defense-in-Depth). 

> [!WARNING]
> **Legal & Liability Notice:**
> El uso de Sentinel PR Firewall **NO** garantiza la detección o bloqueo del 100% de los ataques de cadena de suministro o vulnerabilidades Zero-Day. Los administradores del repositorio siguen siendo los responsables finales de auditar el código que aprueban. Ni Sentinel, ni sus desarrolladores, asumen responsabilidad legal, financiera o de cualquier otra índole por fugas de información, compromisos de infraestructura, malware o brechas de seguridad resultantes de configuraciones incorrectas de políticas o por la evasión de los mecanismos de análisis. 
> 
> *Sentinel es una herramienta para empoderar a los equipos de seguridad, no para reemplazarlos.*
