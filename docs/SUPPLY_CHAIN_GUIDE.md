# Sentinel: Supply Chain Firewall — Guía del Desarrollador

> "No importa qué instales… si pasa por Sentinel, tú decides si vive o muere."

Esta guía explica cómo usar el Firewall de Instalación de Sentinel: qué detecta, cómo interpretar sus veredictos, y cuándo usar cada modo.

---

## ¿Por qué existe esta feature?

Cuando escribes `npm install axios`, confías ciegamente en que el nombre es correcto. **Esa confianza es el vector #1 de supply chain attacks** en 2024. Un atacante publica `axois` en npm, y miles de desarrolladores lo instalan por error de tipeo.

Sentinel intercepta esa instalación **antes** de que el paquete toque tu sistema.

---

## Inicio Rápido

```bash
# En lugar de:
npm install some-package

# Usa:
sentinel install npm some-package

# O activa la intercepción automática (Guard Mode):
sentinel guard enable
# → a partir de ahora, 'npm install' pasa por Sentinel automáticamente
```

---

## Veredictos

### ✓ SAFE — Instalación autorizada
El paquete pasa todos los controles. Se procede.

### ⚠ SUSPICIOUS — Flaggeado, sandbox recomendado
Señales ambiguas. La instalación procede, pero Sentinel registra el evento y recomienda:
```bash
sentinel verify-pkg docker bitnami/redis --sandbox
```

### ⛔ BLOCK — Política aplicada
La instalación no ocurre. `exit 1` en CI/CD. Para investigar en aislamiento:
```bash
sentinel verify-pkg npm axois --sandbox
```

---

## Modos de Enforcement

| Modo | Activación | Comportamiento en BLOCK |
|---|---|---|
| **Strict** | CI/CD auto-detectado (`CI=true`, no-TTY) | Hard block, `exit 1` |
| **Advisory** | `--advisory` flag o TTY interactivo | Advierte, pero procede |

El modo advisory existe para que Sentinel no rompa el flujo local de desarrollo. La educación sin fricción es más efectiva que el bloqueo que termina desactivado.

---

## Ecosistemas Soportados

| Adapter | Gestores | Qué detecta |
|---|---|---|
| **npm** | npm, yarn, pnpm | Typosquatting, scope camouflage (`@evil/react`), lifecycle scripts |
| **pip** | pip, pip3, poetry, uv | Typosquatting, PEP-503 confusion, `entry_points` abuse |
| **docker** | docker pull | Publisher tier, image mimicry, `:latest` sin digest |

---

## Docker: Zero Trust para Imágenes

| Caso | Veredicto |
|---|---|
| `nginx` (official, sin digest) | SUSPICIOUS — usar digest |
| `nginx@sha256:abc...` | SAFE |
| `bitnami/redis` (verified publisher) | SUSPICIOUS — usar digest |
| `evil-org/nginx` (mimicry) | BLOCK |
| `cryptojacker/miner` | BLOCK |

**Buena práctica para producción:**
```bash
sentinel install docker nginx@sha256:a484819eb60311fa89...   # SAFE ✓
```

---

## Trust Cache

Sentinel recuerda paquetes ya evaluados. Segunda instalación = instantánea:
```
Evaluating 'axios'... [cache:3f2a1b9c]
✓ SAFE
```

```bash
sentinel trust list                         # Ver todo
sentinel trust add axios --adapter npm      # Marcar confiable
sentinel trust block evil-pkg --adapter pip # Bloquear permanentemente
sentinel install npm pkg --force            # Re-evaluar (ignorar caché)
sentinel trust clear                        # Limpiar todo
```

---

## Política Local

Crea `~/.sentinel/sentinel-policy.json` para personalizar:

```json
{
  "enforcement_mode": "advisory",
  "install_policy": {
    "block_unpinned_docker": false,
    "sandbox_on_suspicious": true
  }
}
```

---

## Integración CI/CD

```yaml
# GitHub Actions
- name: Sentinel Security Gate
  run: node src/ui/cli/index.js install npm some-dependency
  # exit 1 automático si BLOCK → pipeline se detiene
```

---

## ¿Por qué Sentinel no explica exactamente qué está mal?

Por diseño. Revelar "esta versión tiene esta vulnerabilidad en esta función" crea un manual para atacantes. Solo los propietarios verificados (vía `gh auth`) reciben detalle técnico. El resto recibe solo el veredicto. Esto se llama **Silencio Táctico** y es lo que diferencia Sentinel de un scanner convencional.
