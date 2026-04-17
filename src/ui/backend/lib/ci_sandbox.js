/**
 * Sentinel: CI Sandbox Orchestrator (Modo Pasivo — Sentinel 3.0)
 *
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║  MODO PASIVO: Sentinel NO inyecta código en los repositorios.           ║
 * ║  En su lugar:                                                           ║
 * ║    1. Genera el archivo sentinel-sandbox.yml para que el usuario        ║
 * ║       lo agregue manualmente una vez a cada repo.                       ║
 * ║    2. Dispara runs existentes via workflow_dispatch (si el workflow      ║
 * ║       ya está presente).                                                ║
 * ║    3. Descarga y analiza los logs y artefactos producidos.              ║
 * ╚══════════════════════════════════════════════════════════════════════════╝
 *
 * ¿Por qué Modo Pasivo?
 *   En Modo Activo, Sentinel necesitaría contents:write en el repo, lo cual
 *   amplía la superficie de ataque: si el token se compromete, un atacante
 *   podría modificar workflows. El Modo Pasivo elimina ese riesgo.
 *
 * Flujo completo:
 *   ┌─ Usuario agrega sentinel-sandbox.yml al repo (una vez) ─┐
 *   │                                                          │
 *   └→ Sentinel CLI dispara workflow_dispatch via API ─────────┘
 *       → GitHub Actions ejecuta el workflow instrumentado
 *       → Harden-Runner / netstat capturan telemetría
 *       → Artefactos "sentinel-telemetry" se suben al runner
 *       → Sentinel descarga el ZIP y analiza los resultados
 *
 * SECURITY:
 *   - Solo usa execFileSync para llamadas a `gh` — nunca shell:true
 *   - El token se pasa como variable de entorno GH_TOKEN, nunca en args
 *   - Todos los inputs son validados antes de pasar a la API
 *   - Los archivos descargados se escriben en un dir temporal controlado
 *
 * Dependencia: Requiere `gh` CLI autenticado (gh auth login)
 */

'use strict';

const fs   = require('fs');
const path = require('path');
const os   = require('os');
const { execFileSync } = require('child_process');
const { isValidOwnerRepo } = require('./sanitizer');

// ── Constantes ────────────────────────────────────────────────────────────────

/** Nombre del workflow que Sentinel espera encontrar en el repo */
const WORKFLOW_FILENAME = 'sentinel-sandbox.yml';

/** Timeout máximo para esperar que el workflow termine (15 minutos) */
const WORKFLOW_TIMEOUT_MS = 15 * 60 * 1000;

/** Intervalo de polling para verificar el estado del run (20 segundos) */
const POLL_INTERVAL_MS = 20 * 1000;

/** Directorio donde se almacena el template del workflow */
const WORKFLOW_TEMPLATE_PATH = path.join(__dirname, '..', 'scanner', 'workflow', WORKFLOW_FILENAME);

/** Máximo de reintentos para llamadas fallidas a la API (5xx) */
const MAX_RETRIES = 3;

/** Intervalo base para polling (incrementa con backoff) */
const BASE_POLL_INTERVAL_MS = 10000; // 10s inicial

// ── Helpers internos ──────────────────────────────────────────────────────────

/**
 * Ejecuta un comando `gh api` con reintentos para errores transitorios (5xx).
 * SECURITY: No usa shell. Los argumentos se pasan como array.
 *
 * @param {string[]} args      - Argumentos para `gh api`
 * @param {string}   [token]   - Token de GitHub (se inyecta como GH_TOKEN)
 * @param {number}   [attempt] - Intento actual
 * @returns {object}           - Respuesta JSON de la API
 */
function ghApi(args, token = null, attempt = 1) {
    const env = { ...process.env };
    if (token) env.GH_TOKEN = token;

    try {
        const output = execFileSync('gh', ['api', ...args], {
            encoding: 'utf-8',
            timeout: 30000,
            env
        });
        return JSON.parse(output);
    } catch (e) {
        const isTransient = e.message && (e.message.includes('500') || e.message.includes('502') || e.message.includes('503') || e.message.includes('504'));
        
        if (isTransient && attempt < MAX_RETRIES) {
            console.warn(`[CI_SANDBOX] Error 5xx en GitHub API (Intento ${attempt}/${MAX_RETRIES}). Reintentando en 2s...`);
            execFileSync('node', ['-e', 'setTimeout(()=>{},2000)']); // Bloqueo corto síncrono para reintento
            return ghApi(args, token, attempt + 1);
        }
        
        throw e;
    }
}

/**
 * Pausa la ejecución por N milisegundos (promesa).
 * Útil para polling con backoff.
 * @param {number} ms
 */
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// ── API Pública ───────────────────────────────────────────────────────────────

/**
 * Genera el contenido del workflow sentinel-sandbox.yml para que el usuario
 * lo agregue manualmente al repositorio.
 *
 * En Modo Pasivo, esta función es el punto de inicio: el usuario obtiene
 * el archivo, lo agrega al repo una vez, y Sentinel puede dispararlo
 * via `triggerSandboxRun()` en adelante.
 *
 * @returns {{ success: boolean, workflowContent: string, instructions: string[] }}
 */
function generateWorkflowTemplate() {
    try {
        if (!fs.existsSync(WORKFLOW_TEMPLATE_PATH)) {
            return {
                success: false,
                error: `Template no encontrado en ${WORKFLOW_TEMPLATE_PATH}. Verifica la instalación de Sentinel.`
            };
        }

        const workflowContent = fs.readFileSync(WORKFLOW_TEMPLATE_PATH, 'utf8');

        return {
            success: true,
            workflowContent,
            filename: WORKFLOW_FILENAME,
            instructions: [
                '1. En tu repositorio, crea el directorio .github/workflows/ si no existe.',
                `2. Guarda este archivo como .github/workflows/${WORKFLOW_FILENAME}`,
                '3. Configura branch protection: Settings → Branches → Add rule → "Require PR reviews"',
                '   para que NADIE pueda modificar este archivo sin revisión.',
                '4. Haz commit y push del workflow a la rama principal.',
                '5. Vuelve a Sentinel — ahora puedes lanzar análisis dinamicos desde el panel.',
                '',
                'NOTA SEGURIDAD: Harden-Runner es gratuito para repos públicos.',
                'Para repos privados: omite el paso "Habilitar Harden-Runner" en el workflow',
                'y usa la alternativa con netstat (ya incluida como fallback automático).'
            ]
        };
    } catch (e) {
        return { success: false, error: `Error generando template: ${e.message}` };
    }
}

/**
 * Verifica si el workflow sentinel-sandbox.yml ya existe en el repositorio.
 * Usa la API de GitHub Contents para verificar sin clonar el repo.
 *
 * @param {string}  ownerRepo - "owner/repo"
 * @param {string}  [token]   - Token de GitHub (opcional, usa gh auth si no se pasa)
 * @param {string}  [branch]  - Rama a verificar (default: rama default del repo)
 * @returns {{ installed: boolean, path?: string, sha?: string }}
 */
function checkWorkflowInstalled(ownerRepo, token = null, branch = null) {
    if (!isValidOwnerRepo(ownerRepo)) {
        return { installed: false, error: 'Invalid repo format' };
    }

    try {
        const workflowPath = `.github/workflows/${WORKFLOW_FILENAME}`;
        const args = [`/repos/${ownerRepo}/contents/${workflowPath}`];
        if (branch) args.push(`--field`, `ref=${branch}`);

        const data = ghApi(args, token);
        return {
            installed: true,
            path: data.path,
            sha: data.sha,
            lastModified: data.committed_date
        };
    } catch (e) {
        // 404 = no instalado, cualquier otro error = problema de acceso
        if (e.message && e.message.includes('404')) {
            return { installed: false };
        }
        return { installed: false, error: `GitHub API error: ${e.message}` };
    }
}

/**
 * Dispara un análisis sandbox en el repositorio vía workflow_dispatch.
 *
 * Prerequisito: el workflow sentinel-sandbox.yml debe estar instalado en el repo.
 * Usá `checkWorkflowInstalled()` para verificar antes de llamar esta función.
 *
 * @param {string}  ownerRepo    - "owner/repo"
 * @param {string}  [branch]     - Rama a analizar (default: "main")
 * @param {string}  [token]      - Token de GitHub
 * @returns {{ success: boolean, runId?: number, message?: string }}
 */
async function triggerSandboxRun(ownerRepo, branch = 'main', token = null) {
    if (!isValidOwnerRepo(ownerRepo)) {
        return { success: false, error: 'Invalid repo format' };
    }

    try {
        // 1. Disparar el workflow via gh CLI (evita manejar autenticación manualmente)
        // La API de dispatch no devuelve el run ID directamente,
        // así que guardamos el timestamp y lo buscamos después.
        const beforeDispatch = Date.now();

        execFileSync('gh', [
            'workflow', 'run', WORKFLOW_FILENAME,
            '--repo', ownerRepo,
            '--ref', branch,
            '--field', `target_branch=${branch}`
        ], {
            encoding: 'utf-8',
            timeout: 30000,
            env: token ? { ...process.env, GH_TOKEN: token } : process.env
        });

        // 2. Esperar un momento y buscar el run recién disparado
        await sleep(3000);

        const runs = ghApi([
            `/repos/${ownerRepo}/actions/workflows/${WORKFLOW_FILENAME}/runs`,
            '--jq', '.workflow_runs[0]'
        ], token);

        return {
            success: true,
            runId: runs.id,
            status: runs.status,
            url: runs.html_url,
            triggeredAt: new Date(beforeDispatch).toISOString()
        };
    } catch (e) {
        // Parsear el error más común: workflow no instalado
        if (e.message && (e.message.includes('not found') || e.message.includes('404'))) {
            return {
                success: false,
                error: `El workflow '${WORKFLOW_FILENAME}' no está instalado en ${ownerRepo}. Usa generateWorkflowTemplate() para obtener el archivo.`
            };
        }
        return { success: false, error: e.message };
    }
}

/**
 * Verifica el estado actual de un run de GitHub Actions.
 *
 * @param {string}  ownerRepo - "owner/repo"
 * @param {number}  runId     - ID del workflow run
 * @param {string}  [token]   - Token de GitHub
 * @returns {{ status: string, conclusion?: string, url?: string, durationMs?: number }}
 */
function getSandboxRunStatus(ownerRepo, runId, token = null) {
    if (!isValidOwnerRepo(ownerRepo) || !Number.isInteger(runId)) {
        return { error: 'Invalid parameters' };
    }

    try {
        const run = ghApi([`/repos/${ownerRepo}/actions/runs/${runId}`], token);
        const startedAt = run.run_started_at ? new Date(run.run_started_at) : null;

        return {
            status: run.status,       // queued | in_progress | completed
            conclusion: run.conclusion, // success | failure | cancelled | null
            url: run.html_url,
            branch: run.head_branch,
            commit: run.head_sha?.substring(0, 8),
            startedAt: startedAt?.toISOString(),
            durationMs: startedAt ? Date.now() - startedAt.getTime() : null
        };
    } catch (e) {
        return { error: e.message };
    }
}

/**
 * Espera activamente a que un run de GitHub Actions termine.
 * Implementa polling con backoff progresivo (10s -> 20s -> 30s max).
 *
 * @param {string}  ownerRepo  - "owner/repo"
 * @param {number}  runId      - ID del workflow run
 * @param {string}  [token]    - Token de GitHub
 * @param {number}  [timeout]  - Timeout en ms (default: 15 min)
 * @param {function} [onStep]  - Callback opcional para reportar progreso
 * @returns {Promise<object>}  - Resultado del run
 */
async function waitForSandboxRun(ownerRepo, runId, token = null, timeout = WORKFLOW_TIMEOUT_MS, onStep = null) {
    const startTime = Date.now();
    let pollInterval = BASE_POLL_INTERVAL_MS;

    while (Date.now() - startTime < timeout) {
        const status = getSandboxRunStatus(ownerRepo, runId, token);

        if (status.error) return { concluded: false, error: status.error };

        if (onStep) onStep(status);

        if (status.status === 'completed') {
            return {
                concluded: true,
                conclusion: status.conclusion,
                url: status.url,
                durationMs: Date.now() - startTime
            };
        }

        // Backoff progresivo: cada polling esperamos 5s más, hasta un tope de 30s
        pollInterval = Math.min(30000, pollInterval + 5000);
        await sleep(pollInterval);
    }

    return { concluded: false, timedOut: true, message: `El análisis excedió el tiempo límite de ${timeout/60000} min.` };
}

/**
 * Descarga los artefactos de telemetría de un run completado.
 * El artefacto "sentinel-telemetry" contiene:
 *   - lockfile-diff.txt    → cambios en package-lock.json
 *   - wasm-files.txt       → archivos .wasm en node_modules
 *   - netstat-diff.txt     → conexiones de red nuevas durante instalación
 *   - npm-install-output.txt → output completo de npm ci
 *   - executables.txt      → binarios ejecutables en node_modules
 *
 * @param {string}  ownerRepo - "owner/repo"
 * @param {number}  runId     - ID del workflow run
 * @param {string}  [token]   - Token de GitHub
 * @returns {{ success: boolean, tempDir?: string, files?: string[] }}
 */
function downloadSandboxArtifacts(ownerRepo, runId, token = null) {
    if (!isValidOwnerRepo(ownerRepo) || !Number.isInteger(runId)) {
        return { success: false, error: 'Invalid parameters' };
    }

    // Crear directorio temporal seguro para los artefactos
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-sandbox-'));

    try {
        // Listar artefactos del run para encontrar "sentinel-telemetry"
        const artifacts = ghApi([
            `/repos/${ownerRepo}/actions/runs/${runId}/artifacts`
        ], token);

        const telemetryArtifact = artifacts.artifacts?.find(a => a.name === 'sentinel-telemetry');
        if (!telemetryArtifact) {
            return {
                success: false,
                error: 'Artefacto "sentinel-telemetry" no encontrado. El workflow puede haber fallado o el repo no tiene el sandbox instalado.'
            };
        }

        // Descargar el artefacto como ZIP usando gh CLI
        execFileSync('gh', [
            'api',
            `/repos/${ownerRepo}/actions/artifacts/${telemetryArtifact.id}/zip`,
            '--output', path.join(tempDir, 'telemetry.zip')
        ], {
            encoding: 'buffer',
            timeout: 60000,
            env: token ? { ...process.env, GH_TOKEN: token } : process.env
        });

        // Extraer el ZIP (usando unzip disponible en Linux/Mac, o PowerShell en Windows)
        const zipPath = path.join(tempDir, 'telemetry.zip');
        try {
            execFileSync('unzip', ['-q', zipPath, '-d', tempDir], { timeout: 30000 });
        } catch (_) {
            // Fallback para Windows: usar PowerShell
            execFileSync('powershell', [
                '-Command',
                `Expand-Archive -Path '${zipPath}' -DestinationPath '${tempDir}' -Force`
            ], { timeout: 30000 });
        }

        // Listar archivos extraídos
        const files = fs.readdirSync(tempDir).filter(f => f.endsWith('.txt'));

        return { success: true, tempDir, files };
    } catch (e) {
        // Limpiar el directorio temporal si algo falla
        try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch (_) {}
        return { success: false, error: e.message };
    }
}

/**
 * Analiza la telemetría descargada del sandbox y genera un reporte de amenazas.
 *
 * Señales que se buscan:
 *   1. Diff en lockfile → possible phantom dep o manifest-swap
 *   2. Archivos .wasm → posible código binario ofuscado
 *   3. Binarios ejecutables en node_modules → sospechoso, pocos paquetes los necesitan
 *   4. Conexiones de red nuevas → C2 contact durante instalación
 *   5. Variables npm anómalas → registry override en tiempo de ejecución
 *
 * @param {string} tempDir    - Directorio con los archivos .txt descargados
 * @param {string} ownerRepo  - Repo analizado (para contexto en alertas)
 * @returns {{ riskScore: number, threats: Array, summary: string }}
 */
function analyzeTelemetry(tempDir, ownerRepo) {
    const threats = [];
    let riskScore = 0;

    /** Helper: Lee un archivo del tempDir de forma segura */
    const readFile = (filename) => {
        try {
            const filePath = path.join(tempDir, filename);
            return fs.existsSync(filePath) ? fs.readFileSync(filePath, 'utf8') : '';
        } catch (_) { return ''; }
    };

    // ── 1. Diff de lockfile ──────────────────────────────────────────────────
    const lockfileDiff = readFile('lockfile-diff.txt');
    if (lockfileDiff && !lockfileDiff.includes('No diff found') && lockfileDiff.trim().length > 0) {
        const addedLines = lockfileDiff.split('\n').filter(l => l.startsWith('>')).length;
        if (addedLines > 0) {
            threats.push({
                type: 'LOCKFILE_MODIFIED_AT_INSTALL',
                severity: 'HIGH',
                riskLevel: 8,
                message: `[SANDBOX] El lockfile de ${ownerRepo} se modificó durante la instalación. ${addedLines} líneas añadidas. Posible phantom dependency o manifest-swap.`,
                evidence: lockfileDiff.substring(0, 500),
                recommendation: 'Revisar las líneas nuevas del lockfile y verificar que corresponden a dependencias esperadas.'
            });
            riskScore += 25;
        }
    }

    // ── 2. Archivos .wasm en node_modules ────────────────────────────────────
    const wasmFiles = readFile('wasm-files.txt');
    if (wasmFiles && !wasmFiles.includes('No .wasm files') && wasmFiles.trim().length > 0) {
        const wasmList = wasmFiles.split('\n').filter(Boolean);
        threats.push({
            type: 'WASM_MODULE_DETECTED',
            severity: wasmList.length > 3 ? 'HIGH' : 'MEDIUM',
            riskLevel: wasmList.length > 3 ? 7 : 5,
            message: `[SANDBOX] ${wasmList.length} archivo(s) .wasm encontrados en node_modules de ${ownerRepo}. Pueden contener código ofuscado que el análisis AST de JS no detecta.`,
            evidence: wasmList.slice(0, 10).join('\n'),
            recommendation: 'Investigar manualmente cada .wasm. Usar wasm2wat para convertir a texto legible si está disponible.'
        });
        riskScore += wasmList.length > 3 ? 20 : 10;
    }

    // ── 3. Conexiones de red nuevas durante instalación ──────────────────────
    const netstatDiff = readFile('netstat-diff.txt');
    if (netstatDiff && netstatDiff.trim().length > 0) {
        // Filtrar solo conexiones ESTABLECIDAS (no locales)
        const newConnections = netstatDiff
            .split('\n')
            .filter(l => l.startsWith('>') && !l.includes('127.0.0.1') && !l.includes('::1'));

        if (newConnections.length > 0) {
            threats.push({
                type: 'UNEXPECTED_NETWORK_CONNECTIONS',
                severity: 'HIGH',
                riskLevel: 8,
                message: `[SANDBOX] ${newConnections.length} conexión(es) de red nuevas detectadas durante npm install en ${ownerRepo}. Posible contacto con servidor C2.`,
                evidence: newConnections.slice(0, 5).join('\n'),
                recommendation: 'Verificar destinos de red con herramientas OSINT (Shodan, VirusTotal) y comparar con la lista de IOCs de Sentinel.'
            });
            riskScore += 30;
        }
    }

    // ── 4. Binarios ejecutables en node_modules ───────────────────────────────
    const executables = readFile('executables.txt');
    if (executables && !executables.includes('No executables') && executables.trim().length > 0) {
        const execList = executables.split('\n').filter(Boolean);
        // Filtrar los que son claramente legítimos (node_modules/.bin/*)
        const suspicious = execList.filter(f => !f.includes('node_modules/.bin/') && !f.includes('node_modules/.cache/'));

        if (suspicious.length > 0) {
            threats.push({
                type: 'EXECUTABLES_IN_NODE_MODULES',
                severity: 'MEDIUM',
                riskLevel: 6,
                message: `[SANDBOX] ${suspicious.length} binario(s) ejecutable(s) encontrados en node_modules (fuera de .bin/) de ${ownerRepo}.`,
                evidence: suspicious.slice(0, 5).join('\n'),
                recommendation: 'Investigar cada binario. Los paquetes npm normales no deberían instalar ejecutables fuera de .bin/.'
            });
            riskScore += 15;
        }
    }

    // ── 5. Variables de entorno npm anómalas ──────────────────────────────────
    const npmEnv = readFile('npm-env.txt');
    if (npmEnv && npmEnv.length > 0) {
        // Detectar registry override en variables de entorno
        if (/npm_config_registry\s*=\s*(?!https?:\/\/registry\.npmjs\.org)/i.test(npmEnv)) {
            threats.push({
                type: 'RUNTIME_REGISTRY_OVERRIDE',
                severity: 'CRITICAL',
                riskLevel: 10,
                message: `[SANDBOX] La variable npm_config_registry apunta a un registry NO oficial durante la instalación en ${ownerRepo}. Ataque de registry poisoning activo.`,
                evidence: npmEnv.substring(0, 300),
                recommendation: 'URGENTE: Verificar cómo se está modificando el registry. Revisar .npmrc, scripts de CI y variables de entorno del runner.'
            });
            riskScore += 40;
        }
    }

    // ── Score final ───────────────────────────────────────────────────────────

    // Normalizar a 0-10
    const normalizedScore = Math.min(10, riskScore / 10);

    let summary = '';
    if (threats.length === 0) {
        summary = `✅ Sandbox limpio. No se detectaron comportamientos anómalos durante la instalación.`;
    } else {
        const critical = threats.filter(t => t.severity === 'CRITICAL').length;
        const high     = threats.filter(t => t.severity === 'HIGH').length;
        summary = `⚠️ ${threats.length} amenaza(s) detectadas (${critical} CRÍTICAS, ${high} ALTAS). Score de riesgo: ${normalizedScore.toFixed(1)}/10`;
    }

    return {
        riskScore: normalizedScore,
        riskScoreRaw: riskScore,
        threats,
        summary,
        analyzedAt: new Date().toISOString()
    };
}

/**
 * Limpia el directorio temporal creado por downloadSandboxArtifacts().
 * Llamar siempre después de analyzeTelemetry() para no acumular archivos.
 *
 * @param {string} tempDir - Directorio a eliminar
 */
function cleanupTempDir(tempDir) {
    try {
        if (tempDir && tempDir.includes('sentinel-sandbox-')) {
            fs.rmSync(tempDir, { recursive: true, force: true });
        }
    } catch (e) {
        console.warn(`[CI_SANDBOX] No se pudo limpiar directorio temporal ${tempDir}: ${e.message}`);
    }
}

module.exports = {
    generateWorkflowTemplate,
    checkWorkflowInstalled,
    triggerSandboxRun,
    getSandboxRunStatus,
    waitForSandboxRun,
    downloadSandboxArtifacts,
    analyzeTelemetry,
    cleanupTempDir,
    WORKFLOW_FILENAME
};
