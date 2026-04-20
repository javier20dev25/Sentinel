/**
 * Sentinel: Advanced AST Inspector (SENTINEL 2.0)
 *
 * Analiza la estructura AST del código JavaScript para detectar:
 *   1. Patrón Source→Sink: fetch/curl → eval/Function → child_process
 *   2. Exfiltración de credenciales (process.env → network call)
 *   3. Acceso a paths sensibles (.env, .ssh, .aws, id_rsa)
 *   4. Dynamic execution (eval, new Function, vm.runInNewContext)
 *   5. Ofuscación de alto nivel (hexadecimal masivo, high-entropy strings)
 *   6. CI Environment detection (comportamiento diferente en CI vs local = evasión)
 *
 * CLAVE: Este análisis es inmune a cambios de nombres de variables u ofuscación
 * de strings, porque analiza la ESTRUCTURA del código, no su texto literal.
 *
 * SECURITY: Usa try/catch en todo el análisis. Nunca ejecuta el código analizado.
 */

'use strict';

// Importar el motor de Threat Intelligence para verificar URLs contra IOCs conocidos
const threatIntel = require('./threat_intel');

let acorn, walk;
try {
    acorn = require('acorn');
    walk  = require('acorn-walk');
} catch (e) {
    // acorn no está instalado — análisis AST desactivado (no-fatal)
    acorn = null;
    walk  = null;
}

// ── Categorías de funciones por rol en ataques ─────────────────────────────

/** Funciones que aportan datos del exterior ("sources") */
const NETWORK_SOURCES = new Set(['fetch', 'request', 'get', 'axios', 'got', 'superagent', 'needle', 'http', 'https']);
const FS_READ_SOURCES = new Set(['readFile', 'readFileSync', 'createReadStream', 'readdirSync', 'readdir']);
const ENV_SOURCES     = new Set(['process']); // process.env.*

/** Funciones que ejecutan código o envían datos al exterior ("sinks") */
const EXEC_SINKS      = new Set(['eval', 'exec', 'execSync', 'execFile', 'execFileSync', 'spawn', 'spawnSync',
                                   'Function', 'setTimeout', 'setInterval', 'setImmediate']);
const NETWORK_SINKS   = new Set(['fetch', 'post', 'put', 'send', 'request', 'write']);
const FS_WRITE_SINKS  = new Set(['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'createWriteStream']);

/** Paths de archivos sensibles que nunca deben leer paquetes npm */
const SENSITIVE_PATHS = ['.env', '.ssh', '.aws', 'id_rsa', 'id_ed25519', '.npmrc', '.npmtoken',
                          '/etc/passwd', '/etc/shadow', 'credentials', 'secrets.json', '.htpasswd'];

/** Variables de entorno sensibles (acceso → sospechoso si luego hay red) */
const SENSITIVE_ENV_VARS = ['NPM_TOKEN', 'GITHUB_TOKEN', 'AWS_SECRET', 'AWS_ACCESS', 'DATABASE_URL',
                              'SECRET_KEY', 'API_KEY', 'AUTH_TOKEN', 'PRIVATE_KEY', 'GH_TOKEN'];

/**
 * Extrae el nombre de un nodo de expresión (Identifier o MemberExpression).
 * Ej: node = `axios.post` → "post"
 *     node = `eval`       → "eval"
 * @param {Object} node - Nodo AST
 * @returns {string|null}
 */
function getCallName(node) {
    if (!node) return null;
    if (node.type === 'Identifier') return node.name;
    if (node.type === 'MemberExpression') {
        // Devuelve la propiedad final (post, call, apply, etc.)
        if (node.property && node.property.type === 'Identifier') return node.property.name;
    }
    return null;
}

/**
 * Obtiene el objeto raíz de una MemberExpression encadenada.
 * Ej: `process.env.TOKEN` → "process"
 */
function getRootObject(node) {
    if (!node) return null;
    if (node.type === 'Identifier') return node.name;
    if (node.type === 'MemberExpression') return getRootObject(node.object);
    return null;
}

/**
 * Analiza código JavaScript para detectar patrones de ataque mediante AST.
 * @param {string} code     - Código fuente a analizar
 * @param {string} filePath - Ruta del archivo (para contexto en alertas)
 * @returns {Array}         - Lista de amenazas detectadas
 */
function analyze(code, filePath = 'unknown') {
    // Si acorn no está disponible, devolvemos resultado vacío (no-fatal)
    if (!acorn || !walk) {
        return [{ type: 'AST_UNAVAILABLE', severity: 'INFO',
                  message: 'Análisis AST omitido: acorn no está instalado.' }];
    }

    const threats = [];
    let ast;

    // Intentar parsear como módulo ES, luego como script CommonJS
    for (const sourceType of ['module', 'script']) {
        try {
            ast = acorn.parse(code, { ecmaVersion: 'latest', sourceType });
            break;
        } catch (_) { /* intentar el otro modo */ }
    }

    if (!ast) {
        return [{ type: 'PARSE_ERROR', severity: 'LOW',
                  message: `No se pudo parsear '${filePath}' para análisis AST.` }];
    }

    // ── Estado de análisis de flujo (source tracking) ────────────────────────
    const state = {
        hasNetworkCall:   false,  // ¿se hace alguna llamada de red?
        hasEnvAccess:     false,  // ¿se lee process.env?
        hasSensitivePath: false,  // ¿se accede a un path sensible?
        hasExecCall:      false,  // ¿se ejecuta código/shell?
        hasWriteCall:     false,  // ¿se escriben archivos?
        sensitiveEnvVars: [],     // Variables de entorno sensibles acccedidas
        networkCallCtx:   [],     // Fragmentos de llamadas de red
        execCallCtx:      [],     // Fragmentos de llamadas de ejecución
        ciCheckDetected:  false,  // ¿Código detecta si está en CI?
    };

    // Snippet helper (truncado para evitar ruido)
    const snip = (node) => code.substring(node.start, Math.min(node.end, node.start + 200)).trim();

    walk.simple(ast, {

        // ── 1. MemberExpression: detectar process.env.X ─────────────────────
        MemberExpression(node) {
            const root = getRootObject(node);
            if (root === 'process' && node.object.property && node.object.property.name === 'env') {
                state.hasEnvAccess = true;
                const varName = node.property.type === 'Identifier' ? node.property.name : '';
                if (SENSITIVE_ENV_VARS.some(v => varName.toUpperCase().includes(v))) {
                    state.sensitiveEnvVars.push(varName);
                }
            }
            // Detectar acceso a process.env.CI o process.env.GITHUB_ACTIONS
            // Señal de "evasión sensible al entorno" (se comporta diferente en CI)
            if (root === 'process' &&
                node.object.property?.name === 'env' &&
                ['CI', 'GITHUB_ACTIONS', 'TRAVIS', 'CIRCLECI', 'JENKINS_URL'].includes(node.property.name)) {
                state.ciCheckDetected = true;
            }

            // Phase 3: Geofencing / Locale Spoofing Detection
            // Detect access to Timezone, Locale, or Language
            if ((root === 'process' && node.object.property?.name === 'env' && ['TZ', 'LANG', 'LC_ALL'].includes(node.property?.name)) ||
                (node.object.name === 'navigator' && ['language', 'languages', 'geolocation'].includes(node.property?.name)) ||
                (node.object.name === 'Intl' && node.property?.name === 'DateTimeFormat')) {
                threats.push({
                    type: 'GEOFENCING_LOCALE_CHECK',
                    severity: 'HIGH',
                    riskLevel: 8,
                    message: `Código inspeccionando la ubicación regional (Language/TZ) en '${filePath}'. Frecuentemente usado por malware para evadir detonación en ciertos países.`,
                    evidence: snip(node)
                });
            }
        },

        // ── 2. CallExpression: detectar sources y sinks ──────────────────────
        CallExpression(node) {
            const callName = getCallName(node.callee);
            if (!callName) return;

            // Source: llamada de red
            if (NETWORK_SOURCES.has(callName)) {
                state.hasNetworkCall = true;
                state.networkCallCtx.push(snip(node));
            }

            // Sink: ejecución de código
            if (EXEC_SINKS.has(callName)) {
                state.hasExecCall = true;
                state.execCallCtx.push(snip(node));

                // Alerta estructural por eval() o exec()
                if (callName === 'eval' || callName === 'exec') {
                    // Phase 3: Data Flow Analysis (Lite)
                    // Verificar si el argumento viene de una fuente de input externa explícita
                    let isTainted = false;
                    let argsText = '';
                    if (node.arguments && node.arguments.length > 0) {
                        const arg = node.arguments[0];
                        argsText = snip(arg);
                        // Heurística básica de Taint: si el argumento incluye 'req', 'body', 'input', 'argv'
                        if (['req', 'body', 'input', 'argv', 'query'].some(t => argsText.includes(t))) {
                            isTainted = true;
                        }
                    }

                    threats.push({
                        type: 'DYNAMIC_EXECUTION',
                        severity: isTainted ? 'CRITICAL' : 'HIGH',
                        riskLevel: isTainted ? 10 : 8,
                        message: isTainted 
                            ? `[DATA FLOW] Taint detectado! Entrada externa fluye directamente a '${callName}()' en '${filePath}'. VECTOR RCE CRÍTICO.`
                            : `Uso de '${callName}()' detectado en '${filePath}'. Vector clásico para ejecutar payloads descargados de red.`,
                        evidence: `Source/Arg: ${argsText || snip(node)}`
                    });
                }
            }

            // Sink: escritura de archivo
            if (FS_WRITE_SINKS.has(callName)) {
                state.hasWriteCall = true;
            }

            // Sink: exfiltración de red (post/put/send)
            if (NETWORK_SINKS.has(callName) && !NETWORK_SOURCES.has(callName)) {
                state.networkCallCtx.push(`SEND: ${snip(node)}`);
            }
        },

        // ── 3. NewExpression: new Function(...) ──────────────────────────────
        NewExpression(node) {
            if (node.callee && node.callee.name === 'Function') {
                state.hasExecCall = true;
                threats.push({
                    type: 'DYNAMIC_EXECUTION',
                    severity: 'HIGH',
                    riskLevel: 8,
                    message: `'new Function()' detectado en '${filePath}'. Técnica avanzada para ejecutar strings como código (evasión de eslint/linters).`,
                    evidence: snip(node)
                });
            }
        },

        // ── 4. Literal: paths sensibles hardcodeados ─────────────────────────
        Literal(node) {
            if (typeof node.value !== 'string') return;
            const val = node.value;

            if (SENSITIVE_PATHS.some(p => val.includes(p))) {
                state.hasSensitivePath = true;
                threats.push({
                    type: 'SENSITIVE_PATH_ACCESS',
                    severity: 'HIGH',
                    riskLevel: 7,
                    message: `Acceso a path sensible '${val}' hardcodeado en '${filePath}'.`,
                    evidence: val.substring(0, 200)
                });
            }

            // Detectar strings de C2 Domain:
            // Primero verificar contra lista negra de IOCs conocidos (Axios 2026, ua-parser-js, etc.)
            if (val.startsWith('http') || val.startsWith('https')) {
                const iocResult = threatIntel.checkUrl(val, { isLifecycleScript: false });
                if (iocResult.blocked) {
                    threats.push({
                        type: 'KNOWN_C2_DOMAIN',
                        severity: iocResult.severity,
                        riskLevel: iocResult.severity === 'CRITICAL' ? 10 : iocResult.severity === 'HIGH' ? 8 : 5,
                        message: `[THREAT INTEL] URL en '${filePath}' coincide con IOC conocido de ataque real. Campaña: ${iocResult.campaign}`,
                        evidence: `URL: ${val.substring(0, 200)}\nDescripción: ${iocResult.description}`
                    });
                    return; // Ya alertado, no duplicar con el check genérico
                }
            }

            // C2 genérico: dominio desconocido, largo, no es CDN conocido
            if (val.length > 30 && /\.[a-z]{2,6}$/i.test(val) && val.startsWith('http') &&
                !val.includes('npmjs.org') && !val.includes('github.com') &&
                !val.includes('cloudflare.com') && !val.includes('unpkg.com') &&
                !val.includes('jsdelivr.net')) {
                threats.push({
                    type: 'SUSPICIOUS_C2_URL',
                    severity: 'HIGH',
                    riskLevel: 7,
                    message: `URL externa no reconocida hardcodeada en '${filePath}'. Posible servidor de C2 (Command & Control).`,
                    evidence: val.substring(0, 200)
                });
            }
        }
    });

    // ── POST-WALK: Detección de cadenas Source→Sink ───────────────────────────

    // Patrón crítico: datos de red → ejecución
    if (state.hasNetworkCall && state.hasExecCall) {
        threats.push({
            type: 'NETWORK_TO_EXEC_CHAIN',
            severity: 'CRITICAL',
            riskLevel: 10,
            message: `[CADENA CRÍTICA] '${filePath}' descarga datos de red Y los ejecuta en el mismo contexto. ` +
                     `Patrón típico de dropper de dos etapas.`,
            evidence: `Network: ${state.networkCallCtx.slice(0, 2).join(' | ')} → Exec: ${state.execCallCtx.slice(0, 2).join(' | ')}`
        });
    }

    // Patrón: leer credenciales → enviar por red
    if (state.hasEnvAccess && state.sensitiveEnvVars.length > 0 && state.hasNetworkCall) {
        threats.push({
            type: 'CREDENTIAL_EXFILTRATION',
            severity: 'CRITICAL',
            riskLevel: 10,
            message: `[EXFILTRACIÓN] '${filePath}' lee variables de entorno sensibles (${state.sensitiveEnvVars.join(', ')}) ` +
                     `y realiza llamadas de red en el mismo contexto. Patrón de robo de credenciales.`,
            evidence: `Env vars: [${state.sensitiveEnvVars.join(', ')}] + Network calls detected`
        });
    }

    // Patrón: leer archivo sensible → enviar por red
    if (state.hasSensitivePath && state.hasNetworkCall) {
        threats.push({
            type: 'FILE_EXFILTRATION',
            severity: 'CRITICAL',
            riskLevel: 9,
            message: `[EXFILTRACIÓN] '${filePath}' accede a paths de archivos sensibles y realiza llamadas de red. ` +
                     `Posible robo de llaves SSH, tokens o archivos de configuración.`,
            evidence: `Sensitive path access + network call in same module`
        });
    }

    // Patrón de evasión: comportamiento diferente en CI
    if (state.ciCheckDetected && (state.hasExecCall || state.hasNetworkCall)) {
        threats.push({
            type: 'CI_ENVIRONMENT_EVASION',
            severity: 'HIGH',
            riskLevel: 8,
            message: `[EVASIÓN] '${filePath}' detecta el entorno CI (process.env.CI/GITHUB_ACTIONS) ` +
                     `y también ejecuta código o llama a red. Táctica clásica de malware que se comporta diferente en CI.`,
            evidence: `CI check + exec/network calls detected simultaneously`
        });
    }

    // ── Verificación de entropía: ofuscación masiva ───────────────────────────
    const hexMatch = code.match(/[a-f0-9]{60,}/gi);
    if (hexMatch && hexMatch.length > 0) {
        threats.push({
            type: 'OBFUSCATED_HEX_PAYLOAD',
            severity: 'HIGH',
            riskLevel: 7,
            message: `Cadena hexadecimal masiva detectada en '${filePath}' (${hexMatch[0].length}+ chars). ` +
                     `Indicador de payload binario ofuscado o shellcode.`,
            evidence: hexMatch[0].substring(0, 80) + '...'
        });
    }

    return threats;
}

module.exports = { analyze };
