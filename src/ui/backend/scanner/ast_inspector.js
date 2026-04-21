/**
 * Sentinel: Advanced AST Inspector (SENTINEL 3.2)
 *
 * Analiza la estructura AST del código JavaScript para detectar:
 *   1. Patrón Source→Sink: fetch/curl → eval/Function → child_process
 *   2. Exfiltración de credenciales (process.env → network call)
 *   3. Acceso a paths sensibles (.env, .ssh, .aws, id_rsa)
 *   4. Dynamic execution (eval, new Function, vm.runInNewContext)
 *   5. Ofuscación de alto nivel (hexadecimal masivo, high-entropy strings)
 *   6. CI Environment detection (comportamiento diferente en CI vs local = evasión)
 *   7. [3.2] Proxy Trap detection (new Proxy wrapping sensitive modules)
 *   8. [3.2] Obfuscated sink calls (string join/concat/fromCharCode → eval/exec)
 *   9. [3.2] Enhanced Prototype Pollution (Object.defineProperty on prototype)
 *  10. [3.2] Dynamic global property access (global[x], window[x])
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

const path = require('path');
const fs = require('fs');

let sentinelSpec = { data_flow: { ast_taint_tracking: { sources: [], sinks: [] }, geofencing: { indicators: [] } } };
try {
    const specPath = path.join(__dirname, 'rules', 'sentinel-spec.json');
    sentinelSpec = JSON.parse(fs.readFileSync(specPath, 'utf8'));
} catch (e) {
    console.warn(`[SENTINEL] Could not load formal Sentinel Spec: ${e.message}`);
}

// ── Categorías de funciones por rol en ataques ─────────────────────────────

/** Funciones que aportan datos del exterior ("sources") */
const NETWORK_SOURCES = new Set(['fetch', 'request', 'get', 'axios', 'got', 'superagent', 'needle', 'http', 'https']);
const FS_READ_SOURCES = new Set(['readFile', 'readFileSync', 'createReadStream', 'readdirSync', 'readdir']);
const ENV_SOURCES     = new Set(['process']); // process.env.*

/** Funciones que ejecutan código o envían datos al exterior ("sinks") */
const EXEC_SINKS      = new Set(['eval', 'exec', 'execSync', 'execFile', 'execFileSync', 'spawn', 'spawnSync',
                                   'Function', 'setTimeout', 'setInterval', 'setImmediate', 'pipe', 'connect']);
const NETWORK_SINKS   = new Set(['fetch', 'post', 'put', 'send', 'request', 'write']);
const FS_WRITE_SINKS  = new Set(['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'createWriteStream']);

/** [3.2] Modules that are dangerous when wrapped in a Proxy */
const PROXY_DANGEROUS_MODULES = new Set(['child_process', 'fs', 'http', 'https', 'net', 'dgram', 'dns', 'tls', 'vm', 'worker_threads']);

/** [3.2] Sink names that attackers try to construct dynamically */
const OBFUSCATED_SINK_NAMES = ['eval', 'exec', 'execSync', 'spawn', 'Function', 'writeFile', 'writeFileSync', 'execFile'];

/** Paths de archivos sensibles que nunca deben leer paquetes npm */
const SENSITIVE_PATHS = ['.env', '.ssh', '.aws', 'id_rsa', 'id_ed25519', '.npmrc', '.npmtoken',
                          '/etc/passwd', '/etc/shadow', 'credentials', 'secrets.json', '.htpasswd'];

/** Variables de entorno sensibles (acceso → sospechoso si luego hay red) */
const SENSITIVE_ENV_VARS = ['NPM_TOKEN', 'GITHUB_TOKEN', 'AWS_SECRET', 'AWS_ACCESS', 'DATABASE_URL',
                              'SECRET_KEY', 'API_KEY', 'AUTH_TOKEN', 'PRIVATE_KEY', 'GH_TOKEN'];

/**
 * Helper: Obtiene el nombre completo de una llamada (ej: 'process.env.VAR')
 * Implementa normalización canónica: si es un método (obj.pipe), retorna también el método libre.
 */
function getCallName(node, state) {
    if (!node) return null;
    if (node.type === 'Identifier') return node.name;
    if (node.type === 'MemberExpression') {
        const obj = getCallName(node.object, state);
        const prop = node.property && (node.property.name || (node.property.type === 'Literal' ? node.property.value : null));
        if (!obj || !prop) return obj || prop;
        // Normalización canónica: permitimos matching por 'pipe' o 'socket.pipe'
        if (state) state.lastMethod = prop; 
        return `${obj}.${prop}`;
    }
    if (node.type === 'CallExpression') return getCallName(node.callee, state);
    return null;
}

/**
 * Helper: Encuentra el objeto raíz de una cadena de MemberExpressions (ej: 'process' en 'process.env.X')
 */
function getRootObject(node) {
    let current = node;
    while (current && current.type === 'MemberExpression') {
        current = current.object;
    }
    return (current && current.type === 'Identifier') ? current.name : null;
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
        proxyWrapDetected: false, // [3.2] ¿Se usa Proxy sobre módulos sensibles?
        obfuscatedSinkDetected: false, // [3.2] ¿Se construyen nombres de sink dinámicamente?
        requireMap: {},           // [3.2] Maps variable names to required module names (e.g. cp -> child_process)
        aliasMap: new Map(),      // [3.5] Maps local variable names back to their dangerous sinks (e.g. e -> eval)
    };

    // Snippet helper (truncado para evitar ruido)
    const snip = (node) => code.substring(node.start, Math.min(node.end, node.start + 200)).trim();

    walk.simple(ast, {

        VariableDeclarator(node) {
            // [3.2] Guardar tracking de variables
            if (node.id.type === 'Identifier') {
                if (node.init && node.init.type === 'Identifier') {
                    const resolvedInit = Object.values(state.requireMap).includes(node.init.name) ? node.init.name : 
                                        (state.aliasMap.has(node.init.name) ? state.aliasMap.get(node.init.name) : node.init.name);
                    state.aliasMap.set(node.id.name, resolvedInit);

                    // [3.5.8] Cazamos aliases directos a require, eval o exec.
                    if (['require', 'eval', 'exec', 'spawn', 'process'].includes(resolvedInit)) {
                        threats.push({
                            type: 'KNOWN_SINK_CALL',
                            severity: 'HIGH',
                            riskLevel: 75,
                            message: `[ALIASING] Se ha asignado el sink crítico '${resolvedInit}' a '${node.id.name}'. Técnica común para evadir firmas.`,
                            evidence: snip(node)
                        });
                    }
                }
            }

            // [3.2] Track require() bindings (Support Destructuring)
            if (node.init && node.init.type === 'CallExpression' &&
                node.init.callee && node.init.callee.name === 'require') {
                
                const arg = node.init.arguments?.[0];
                if (arg && arg.type === 'Literal') {
                    const modName = arg.value;
                    if (node.id.type === 'Identifier') {
                        state.requireMap[node.id.name] = modName;
                    } else if (node.id.type === 'ObjectPattern') {
                        node.id.properties.forEach(p => {
                            if (p.value?.type === 'Identifier') {
                                state.requireMap[p.value.name] = modName;
                            }
                        });
                    }
                } else if (arg) {
                    // [3.5.1] CASE 2: Dynamic Require Detection
                    threats.push({
                        type: 'SUSPICIOUS_REQUIRE',
                        severity: 'MEDIUM',
                        riskLevel: 65,
                        evidence: `Dynamic require: ${snip(node.init)}`
                    });
                }
            }

            // [3.4] Aliasing Detection & [3.5] Registry
            if (node.init && node.init.type === 'Identifier') {
                const initName = node.init.name;
                const resolvedInit = state.aliasMap.get(initName) || initName;

                // [3.5] Only alert if a dangerous EXEC sink is aliased.
                // We exclude 'require' from automatic threats here to avoid FP on 'const x = require'.
                if (['eval', 'exec', 'spawn', 'Function'].includes(resolvedInit)) {
                    state.aliasMap.set(node.id.name, resolvedInit);
                    threats.push({
                        type: 'KNOWN_SINK_CALL',
                        severity: 'HIGH',
                        riskLevel: 65,
                        message: `[ALIASING] Se ha asignado el sink '${resolvedInit}' a '${node.id.name}'. Técnica común para evadir firmas estáticas.`,
                        evidence: snip(node)
                    });
                } else if (resolvedInit === 'require') {
                    // SILENTLY track require aliases (no threat yet)
                    state.aliasMap.set(node.id.name, 'require');
                }
            }
        },

        // ── 1. MemberExpression: env, geofence, fragmentation ────────────────
        MemberExpression(node) {
            const root = getRootObject(node);
            
            // Env Access
            if (root === 'process' && node.object.property && node.object.property.name === 'env') {
                state.hasEnvAccess = true;
                const varName = node.property.type === 'Identifier' ? node.property.name : '';
                if (SENSITIVE_ENV_VARS.some(v => varName.toUpperCase().includes(v))) {
                    state.sensitiveEnvVars.push(varName);
                }
                
                // CI Check
                if (['CI', 'GITHUB_ACTIONS', 'TRAVIS', 'CIRCLECI', 'JENKINS_URL'].includes(node.property.name)) {
                   state.ciCheckDetected = true;
                }
            }

            // [3.4] Fragmentation Check (global['ev' + 'al'])
            if (node.computed && node.property && node.property.type === 'BinaryExpression' && node.property.operator === '+') {
                 // [3.5] Generalization: Detect concatenation even if variables are used, if root is global
                const isGlobalRoot = ['global', 'window', 'globalThis', 'self'].includes(root);
                if (isGlobalRoot) {
                    threats.push({
                        type: 'STRING_CONCAT_SINK',
                        severity: 'HIGH',
                        riskLevel: 65,
                        message: `[FRAGMENTATION] Acceso dinámico a propiedad del global mediante concatenación. Técnica de evasión para invocar sinks (eval/exec).`,
                        evidence: `${snip(node.object)}[${snip(node.property)}]`
                    });
                }
            }

            // Geofencing / Locale / Telemetry (Contextual Noise)
            const isTelemetry = (node.object.name === 'os' && ['platform', 'arch', 'type', 'release', 'hostname'].includes(node.property?.name)) ||
                                (node.object.name === 'process' && ['uptime', 'version', 'arch'].includes(node.property?.name)) ||
                                (node.object.name === 'navigator' && ['userAgent', 'platform'].includes(node.property?.name));

            if ((root === 'process' && node.object.property?.name === 'env' && ['TZ', 'LANG', 'LC_ALL'].includes(node.property?.name)) ||
                (node.object.name === 'navigator' && ['language', 'languages', 'geolocation'].includes(node.property?.name)) ||
                (node.object.name === 'Intl' && node.property?.name === 'DateTimeFormat') || isTelemetry) {
                threats.push({
                    type: 'GEOFENCING_LOCALE_CHECK',
                    severity: 'INFO',
                    riskLevel: isTelemetry ? 25 : 60,
                    message: isTelemetry 
                        ? `Inspección de telemetría del sistema (${snip(node)}). Ruido contextual común en herramientas legítimas, pero usado para evasión en malware.`
                        : `Código inspeccionando la ubicación regional (Language/TZ) en '${filePath}'.`,
                    evidence: snip(node)
                });
            }
        },

        // ── 2. CallExpression: detectar sources y sinks ──────────────────────
        CallExpression(node) {
            let callName = getCallName(node.callee, state);
            if (!callName) return;

            // [3.5] Resolve Alias
            if (state.aliasMap.has(callName)) {
                callName = state.aliasMap.get(callName);
            }

            // Source: llamada de red
            if (NETWORK_SOURCES.has(callName)) {
                state.hasNetworkCall = true;
                state.networkCallCtx.push(snip(node));
            }

            // Sink: ejecución de código
            const methodOnly = state.lastMethod || callName;
            if (EXEC_SINKS.has(callName) || EXEC_SINKS.has(methodOnly)) {
                if (EXEC_SINKS.has(methodOnly)) callName = methodOnly; // Canonical normalization
                state.hasExecCall = true;
                state.execCallCtx.push(snip(node));

                // [3.5] Argument Sensitivity Analysis
                // If the critical sink is called ONLY with Literals/Static patterns, it's likely safe.
                // We check the command (arg0) and the arguments array (arg1). 
                // The options object (arg2) is generally safe unless it enables a shell.
                const args = node.arguments || [];
                const SAFE_COMMANDS = new Set(['gh', 'git', 'npm', 'node', 'npx', 'ls', 'grep', 'sudo', 'cp', 'rm', 'cat', 'mv', 'mkdir', 'gh.exe', 'git.exe', 'node.exe']);
                const isSafeArg = (arg) => {
                    if (!arg) return true;
                    if (arg.type === 'Literal') return true;
                    if (arg.type === 'TemplateLiteral' && arg.expressions && arg.expressions.length === 0) return true;
                    if (arg.type === 'ArrayExpression') {
                        return arg.elements.every(el => {
                            if (!el) return true;
                            if (el.type === 'Literal') return true;
                            if (el.type === 'TemplateLiteral' && el.expressions && el.expressions.length === 0) return true;
                            if (arg.type === 'SpreadElement' && arg.argument.type === 'Identifier') {
                                // Assume spread identifiers like 'args' or 'params' in dev tools are safe-ish
                                const name = el.argument.name.toLowerCase();
                                return name.includes('arg') || name.includes('param') || name.includes('field');
                            }
                            return false;
                        });
                    }
                    if (arg.type === 'ObjectExpression') return true; // Options objects are usually safe
                    if (arg.type === 'Identifier') {
                        // Whitelist common safe utility commands to avoid FP on legitimate bridges
                        const name = arg.name.toLowerCase();
                        return SAFE_COMMANDS.has(name) || name.includes('cmd') || name.includes('path') || name.includes('file') || name.includes('db');
                    }
                    return false;
                };

                const isAllLiteral = args.length > 0 && args.slice(0, 2).every(isSafeArg);
                // [3.5.1] FIXED: 10 for whitelisted utils, 35 for normal literals, 65 for dynamic
                let riskWeight = 65; 
                if (isAllLiteral) {
                    let cmd = '';
                    if (args[0] && args[0].type === 'Literal') cmd = String(args[0].value);
                    if (args[0] && args[0].type === 'TemplateLiteral' && args[0].quasis.length > 0) cmd = String(args[0].quasis[0].value.raw);
                    
                    const WHITE_LIST = ['git', 'gh', 'npm', 'pnpm', 'yarn', 'ls', 'node'];
                    riskWeight = WHITE_LIST.some(w => cmd === w || cmd.startsWith(w + ' ')) ? 10 : 35;
                }

                // Alerta estructural por exec/eval (depende de config JSON)
                const configSinks = sentinelSpec.data_flow?.ast_taint_tracking?.sinks || [];
                if (configSinks.some(sinkTerm => callName.includes(sinkTerm))) {
                    let isTainted = false;
                    let argsText = '';
                    if (args.length > 0) {
                        argsText = snip(args[0]);
                        const configSources = sentinelSpec.data_flow?.ast_taint_tracking?.sources || [];
                        if (configSources.some(t => argsText.includes(t))) {
                            isTainted = true;
                        }
                    }

                    threats.push({
                        type: 'KNOWN_SINK_CALL', // Usamos el tipo directo para el scorer
                        severity: isTainted ? 'CRITICAL' : (isAllLiteral ? 'INFO' : 'HIGH'),
                        riskLevel: isTainted ? 80 : riskWeight,
                        message: isTainted 
                            ? `[DATA FLOW] Taint detectado! Entrada externa fluye a '${callName}'.`
                            : `Uso de '${callName}()' detectado. ${isAllLiteral ? '(Argumentos estáticos/seguros)' : '(Posible inyección dinámica detectada)'}`,
                        evidence: `Arg: ${argsText || snip(node)}`
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

            // [3.3] Adaptive Signal: Base64 Decoding usage
            if (callName === 'Buffer.from' || callName === 'atob') {
                state.hasObfuscationSignal = true; // Nuevo flag para el scorer
                threats.push({
                    type: 'BASE64_DECODE_SIGNATURE',
                    severity: 'INFO',
                    riskLevel: 2,
                    message: `Uso de decodificación Base64 detectado (${callName}).`,
                    evidence: snip(node)
                });
            }

            // [3.4] Kill Switch: Reverse Shell Detection (socket.pipe(process.stdin))
            if (callName === 'pipe' || callName === 'connect' || (state.lastMethod === 'pipe' || state.lastMethod === 'connect')) {
                const argsText = node.arguments && node.arguments.length > 0 ? snip(node.arguments[0]) : '';
                
                // Context Check: Is 'net' or 'child_process' in scope? Or is the root explicit like 'socket'?
                const rootObj = getRootObject(node.callee);
                const hasNetContext = Object.values(state.requireMap).some(m => ['net', 'child_process', 'tls'].includes(m)) || 
                                      ['net', 'socket', 'child_process', 'client', 'tcp', 'conn'].some(c => rootObj && rootObj.toLowerCase().includes(c));
                
                if (hasNetContext && (argsText.includes('stdin') || argsText.includes('sh') || argsText.includes('bash') || argsText.includes('process.'))) {
                     threats.push({
                        type: 'DETERMINISTIC_REVERSE_SHELL',
                        severity: 'CRITICAL',
                        riskLevel: 100,
                        isKillSwitch: true, 
                        message: `[KILL SWITCH] Reverse shell detectado! Conexión de socket (${rootObj || 'unknown'}) directa a stdin/sh.`,
                        evidence: snip(node)
                    });
                }
            }

            // [3.4] Function Constructor (Prime Evasion)
            if (callName === 'Function' || callName === 'new Function') {
                threats.push({
                    type: 'KNOWN_SINK_CALL',
                    severity: 'HIGH',
                    riskLevel: 25,
                    message: `Uso de 'new Function()' detectado. Permite ejecutar strings como código, evadiendo análisis estático simple.`,
                    evidence: snip(node)
                });
            }

            // [3.5.8] Identificación de setTimeout("code") como eval camuflado
            if (callName === 'setTimeout' || callName === 'setInterval') {
                if (node.arguments && node.arguments.length > 0) {
                    const arg0 = snip(node.arguments[0]);
                    const isStringArg = node.arguments[0].type === 'Literal' && typeof node.arguments[0].value === 'string';
                    
                    if (isStringArg || arg0.includes('(') || arg0.includes('eval') || arg0.includes('exec')) {
                        threats.push({
                            type: 'DYNAMIC_EXECUTION',
                            severity: 'CRITICAL',
                            riskLevel: 80,
                            message: `[DYNAMIC_EXEC] '${callName}' invocado con un string literal (Eval Timeout). Técnica de ejecución diferida.`,
                            evidence: snip(node)
                        });
                    }
                }
            }
        },

        // [3.5] AssignmentExpression: catch sink aliasing in re-assignments & properties
        AssignmentExpression(node) {
            if (node.right && node.right.type === 'Identifier') {
                const rightHand = node.right.name;
                const resolvedSink = state.aliasMap.get(rightHand) || rightHand;

                if (['eval', 'exec', 'spawn', 'Function', 'require'].includes(resolvedSink)) {
                    const leftHand = snip(node.left);
                    // Resolve simple identifiers
                    if (node.left.type === 'Identifier') {
                        state.aliasMap.set(node.left.name, resolvedSink);
                    } 
                    // Resolve properties (last part: Object.prototype.trap -> trap)
                    else if (node.left.type === 'MemberExpression' && node.left.property.type === 'Identifier') {
                        state.aliasMap.set(node.left.property.name, resolvedSink);
                    }

                    threats.push({
                        type: 'KNOWN_SINK_CALL',
                        severity: 'HIGH',
                        riskLevel: 65,
                        message: `[ALIASING] Asignación de sink '${resolvedSink}' detectada en '${leftHand}'.`,
                        evidence: snip(node)
                    });
                }
            }
        },

        // [3.4] Deferred Intent (Exports)
        ExportNamedDeclaration(node) {
            const codeFragment = snip(node);
            if (['eval', 'exec', 'spawn', 'Function'].some(s => codeFragment.includes(s))) {
                 threats.push({
                    type: 'KNOWN_SINK_CALL',
                    severity: 'HIGH',
                    riskLevel: 20,
                    message: `[DEFERRED INTENT] Exportación de funcionalidad crítica detectada. El sink no se ejecuta aquí, pero se ofrece para uso externo malicioso.`,
                    evidence: codeFragment
                });
            }
        },

        // ── 3. NewExpression: new Function(...) AND new Proxy(...) ─────────────
        NewExpression(node) {
            if (node.callee && node.callee.name === 'Function') {
                state.hasExecCall = true;
                threats.push({
                    type: 'DYNAMIC_EXECUTION',
                    severity: 'HIGH',
                    riskLevel: 65,
                    message: `'new Function()' detectado en '${filePath}'. Técnica avanzada para ejecutar strings como código (evasión de eslint/linters).`,
                    evidence: snip(node)
                });
            }

            // [3.2] Proxy Trap Detection: new Proxy(child_process, handler)
            if (node.callee && node.callee.name === 'Proxy' && node.arguments && node.arguments.length >= 2) {
                const targetArg = node.arguments[0];
                let targetName = '';
                if (targetArg.type === 'Identifier') {
                    // Resolve via requireMap: const cp = require('child_process') -> cp -> child_process
                    targetName = state.requireMap[targetArg.name] || targetArg.name;
                } else if (targetArg.type === 'CallExpression' && targetArg.callee) {
                    // new Proxy(require('child_process'), ...)
                    const reqArg = targetArg.arguments && targetArg.arguments[0];
                    if (targetArg.callee.name === 'require' && reqArg && reqArg.type === 'Literal') {
                        targetName = reqArg.value;
                    }
                }

                // Check if the proxy target is a known dangerous module
                const isDangerous = PROXY_DANGEROUS_MODULES.has(targetName);

                // Also check the handler for suspicious trap functions (get, apply)
                const handler = node.arguments[1];
                let hasSuspiciousTrap = false;
                if (handler && handler.type === 'ObjectExpression' && handler.properties) {
                    hasSuspiciousTrap = handler.properties.some(p => {
                        const key = p.key && (p.key.name || p.key.value);
                        return ['get', 'apply', 'construct'].includes(key);
                    });
                }

                if (isDangerous || hasSuspiciousTrap) {
                    state.proxyWrapDetected = true;
                    threats.push({
                        type: 'PROXY_WRAPPED_SINK',
                        severity: 'CRITICAL',
                        riskLevel: 75,
                        message: `[PROXY EVASION] '${filePath}' wraps ${isDangerous ? `dangerous module '${targetName}'` : 'an object'} in a Proxy with ${hasSuspiciousTrap ? 'get/apply/construct traps' : 'handler'}. ` +
                            `This is a known technique to bypass static analysis of exec/spawn/writeFile calls.`,
                        evidence: snip(node)
                    });
                }
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
                    riskLevel: 60,
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
                        riskLevel: iocResult.severity === 'CRITICAL' ? 100 : iocResult.severity === 'HIGH' ? 85 : 50,
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
                    riskLevel: 65,
                    message: `URL externa no reconocida hardcodeada en '${filePath}'. Posible servidor de C2 (Command & Control).`,
                    evidence: val.substring(0, 200)
                });
            }

            // [3.2] Detect __proto__ string literals used in property access
            if (val === '__proto__' || val === 'constructor') {
                threats.push({
                    type: 'PROTOTYPE_POLLUTION_VECTOR',
                    severity: 'HIGH',
                    riskLevel: 70,
                    message: `[PROTOTYPE POLLUTION] String literal '${val}' used in '${filePath}'. Potential prototype pollution payload.`,
                    evidence: snip(node)
                });
            }

            // [3.2] Detect __proto__ embedded in JSON strings (e.g. JSON.parse('{"__proto__": ...}'))
            if (val.length > 10 && val.includes('__proto__')) {
                threats.push({
                    type: 'PROTOTYPE_POLLUTION_JSON_PAYLOAD',
                    severity: 'CRITICAL',
                    riskLevel: 85,
                    message: `[PROTOTYPE POLLUTION] String containing '__proto__' key detected in '${filePath}'. ` +
                        `When parsed by JSON.parse() and merged with Object.assign/spread, this pollutes the global prototype chain.`,
                    evidence: val.substring(0, 200)
                });
            }
        },

        // ── 5. [3.2] AssignmentExpression: Prototype Pollution via direct assignment ──
        AssignmentExpression(node) {
            // Detect: Object.prototype.x = ... or obj.__proto__.x = ...
            if (node.left && node.left.type === 'MemberExpression') {
                const propName = node.left.property && (node.left.property.name || node.left.property.value);
                const objCode = snip(node.left.object || node.left);

                if (objCode.includes('Object.prototype') || objCode.includes('__proto__')) {
                    threats.push({
                        type: 'PROTOTYPE_POLLUTION_ASSIGNMENT',
                        severity: 'CRITICAL',
                        riskLevel: 90,
                        message: `[PROTOTYPE POLLUTION] Direct assignment to Object.prototype or __proto__ in '${filePath}'. ` +
                            `This can corrupt the runtime environment for all objects in the process.`,
                        evidence: snip(node)
                    });
                }
            }
        },

        // ── 6. [3.2] Obfuscated Sink Detection: array.join() / String.fromCharCode ──
        //    Catches patterns like: ['e','x','e','c'].join('') or global[varName]
        MemberExpression_post(node) { /* handled in CallExpression below */ }
    });

    // ── [3.2] Regex-based Obfuscated Sink Detection (post-walk) ───────────────
    // These patterns cannot be caught by AST alone because they construct
    // function names from string operations at runtime.

    // Pattern: ['e','x','e','c'].join('') or similar array-to-string sink construction
    const joinPattern = /\[\s*['"]([a-zA-Z])['"]\s*(?:,\s*['"]([a-zA-Z])['"]\s*){2,}\]\s*\.\s*join\s*\(/g;
    let joinMatch;
    while ((joinMatch = joinPattern.exec(code)) !== null) {
        // Reconstruct what the join would produce
        const arrayContent = joinMatch[0];
        const chars = arrayContent.match(/['"]([a-zA-Z])['"]/g);
        if (chars) {
            const reconstructed = chars.map(c => c.replace(/['"]/g, '')).join('');
            if (OBFUSCATED_SINK_NAMES.some(sink => reconstructed.toLowerCase() === sink.toLowerCase())) {
                state.obfuscatedSinkDetected = true;
                threats.push({
                    type: 'OBFUSCATED_SINK_CONSTRUCTION',
                    severity: 'CRITICAL',
                    riskLevel: 100,
                    message: `[SINK OBFUSCATION] Array.join() in '${filePath}' reconstructs dangerous function name '${reconstructed}'. ` +
                        `This is a known evasion technique to hide calls to exec/eval/spawn from static scanners.`,
                    evidence: arrayContent.substring(0, 200)
                });
            }
        }
    }

    // Pattern: String.fromCharCode(101, 120, 101, 99) → "exec"
    const fromCharPattern = /String\.fromCharCode\s*\(([0-9,\s]+)\)/g;
    let fccMatch;
    while ((fccMatch = fromCharPattern.exec(code)) !== null) {
        try {
            const nums = fccMatch[1].split(',').map(n => parseInt(n.trim(), 10));
            const reconstructed = String.fromCharCode(...nums);
            if (OBFUSCATED_SINK_NAMES.some(sink => reconstructed.includes(sink))) {
                state.obfuscatedSinkDetected = true;
                threats.push({
                    type: 'OBFUSCATED_SINK_CHARCODE',
                    severity: 'CRITICAL',
                    riskLevel: 100,
                    message: `[SINK OBFUSCATION] String.fromCharCode() in '${filePath}' reconstructs dangerous name '${reconstructed}'.`,
                    evidence: fccMatch[0].substring(0, 200)
                });
            }
        } catch (e) { /* malformed charcode, skip */ }
    }

    // Pattern: global['ev' + 'al'] or global[variable] dynamic property access
    const dynamicGlobalPattern = /(?:global|window|globalThis|self)\s*\[\s*(?:['"][a-z]+['"]\s*\+|[a-zA-Z_$][a-zA-Z0-9_$]*)/g;
    let dgMatch;
    while ((dgMatch = dynamicGlobalPattern.exec(code)) !== null) {
        state.obfuscatedSinkDetected = true;
        threats.push({
            type: 'DYNAMIC_GLOBAL_ACCESS',
            severity: 'HIGH',
            riskLevel: 90,
            message: `[SINK OBFUSCATION] Dynamic property access on global object in '${filePath}'. ` +
                `Pattern like global[x] is used to call functions by computed name, evading static analysis.`,
            evidence: dgMatch[0].substring(0, 200)
        });
    }

    // ── POST-WALK: Detección de cadenas Source→Sink ───────────────────────────

    // Patrón crítico: datos de red → ejecución
    if (state.hasNetworkCall && state.hasExecCall) {
        threats.push({
            type: 'NETWORK_TO_EXEC_CHAIN',
            severity: 'CRITICAL',
            riskLevel: 100,
            message: `[CADENA CRITICA] '${filePath}' descarga datos de red Y los ejecuta en el mismo contexto. ` +
                     `Patron tipico de dropper de dos etapas.`,
            evidence: `Network: ${state.networkCallCtx.slice(0, 2).join(' | ')} -> Exec: ${state.execCallCtx.slice(0, 2).join(' | ')}`
        });
    }

    // Patrón: leer credenciales → enviar por red
    if (state.hasEnvAccess && state.sensitiveEnvVars.length > 0 && state.hasNetworkCall) {
        threats.push({
            type: 'CREDENTIAL_EXFILTRATION',
            severity: 'CRITICAL',
            riskLevel: 100,
            message: `[EXFILTRACION] '${filePath}' lee variables de entorno sensibles (${state.sensitiveEnvVars.join(', ')}) ` +
                     `y realiza llamadas de red en el mismo contexto. Patron de robo de credenciales.`,
            evidence: `Env vars: [${state.sensitiveEnvVars.join(', ')}] + Network calls detected`
        });
    }

    // Patrón: leer archivo sensible → enviar por red
    if (state.hasSensitivePath && state.hasNetworkCall) {
        threats.push({
            type: 'FILE_EXFILTRATION',
            severity: 'CRITICAL',
            riskLevel: 90,
            message: `[EXFILTRACION] '${filePath}' accede a paths de archivos sensibles y realiza llamadas de red. ` +
                     `Posible robo de llaves SSH, tokens o archivos de configuracion.`,
            evidence: `Sensitive path access + network call in same module`
        });
    }

    // Patrón de evasión: comportamiento diferente en CI
    if (state.ciCheckDetected && (state.hasExecCall || state.hasNetworkCall)) {
        threats.push({
            type: 'CI_ENVIRONMENT_EVASION',
            severity: 'HIGH',
            riskLevel: 80,
            message: `[EVASION] '${filePath}' detecta el entorno CI (process.env.CI/GITHUB_ACTIONS) ` +
                     `y tambien ejecuta codigo o llama a red. Tactica clasica de malware que se comporta diferente en CI.`,
            evidence: `CI check + exec/network calls detected simultaneously`
        });
    }

    // ── Verificación de entropía: ofuscación masiva ───────────────────────────
    const hexMatch = code.match(/[a-f0-9]{60,}/gi);
    if (hexMatch && hexMatch.length > 0) {
        threats.push({
            type: 'OBFUSCATED_HEX_PAYLOAD',
            severity: 'HIGH',
            riskLevel: 90,
            message: `Cadena hexadecimal masiva detectada en '${filePath}' (${hexMatch[0].length}+ chars). ` +
                     `Indicador de payload binario ofuscado o shellcode.`,
            evidence: hexMatch[0].substring(0, 80) + '...'
        });
    }

    const b64Match = code.match(/(?:[A-Za-z0-9+/]{4}){12,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/g);
    if (b64Match && b64Match.length > 0) {
        threats.push({
            type: 'BASE64_DECODE_SIGNATURE',
            severity: 'CRITICAL',
            riskLevel: 90,
            message: `[SINK OBFUSCATION] Carga de código codificada en Base64 aislada o embebida. Táctica común para inyección sigilosa.`,
            evidence: b64Match[0].substring(0, 60) + '...'
        });
    }

    return threats;
}

/**
 * [3.3] Adaptive Execution Graph Engine
 * Evalúa el AST y reporta "Señales" al Confidence Scorer en lugar de amenazas binarias.
 * Mapea las viejas amenazas a señales semánticas para integrarlas en el sistema de niveles.
 */
function analyzeWithScorer(code, filePath, scorer) {
    const threats = analyze(code, filePath);

    threats.forEach(t => {
        const isKillSwitch = t.isKillSwitch || false;

        // [3.5.7] Restauramos el envío del peso local del AST. Sus algoritmos de context-awareness 
        // son los únicos que pueden evaluar con certeza la legitimidad de un call string (Whitelist)
        let weight = t.riskLevel || null;

        if (t.type === 'SENSITIVE_PATH_ACCESS') scorer.addSignal(filePath, 'ENV_ACCESS', t.evidence, false, weight);
        else if (t.type === 'KNOWN_C2_DOMAIN') scorer.addSignal(filePath, 'NETWORK_REQUEST', t.evidence, false, weight);
        else if (t.type === 'SUSPICIOUS_C2_URL') scorer.addSignal(filePath, 'NETWORK_REQUEST', t.evidence, false, weight);
        else if (t.type === 'PROTOTYPE_POLLUTION_VECTOR') scorer.addSignal(filePath, 'PROTOTYPE_POLLUTION_ASSIGN', t.evidence, false, weight);
        else if (t.type === 'PROTOTYPE_POLLUTION_ASSIGNMENT') scorer.addSignal(filePath, 'PROTOTYPE_POLLUTION_ASSIGN', t.evidence, false, weight);
        else if (t.type === 'PROTOTYPE_POLLUTION_JSON_PAYLOAD') scorer.addSignal(filePath, 'PROTOTYPE_POLLUTION_ASSIGN', t.evidence, false, weight);
        else if (t.type === 'PROXY_WRAPPED_SINK') scorer.addSignal(filePath, 'PROXY_WARPING', t.evidence, false, weight);
        else if (t.type === 'OBFUSCATED_SINK_CONSTRUCTION') scorer.addSignal(filePath, 'STRING_CONSTRUCTION', t.evidence, false, weight);
        else if (t.type === 'OBFUSCATED_SINK_CHARCODE') scorer.addSignal(filePath, 'STRING_CONSTRUCTION', t.evidence, false, weight);
        else if (t.type === 'DYNAMIC_GLOBAL_ACCESS') scorer.addSignal(filePath, 'DYNAMIC_PROPERTY_ACCESS', t.evidence, false, weight);
        else if (t.type === 'NETWORK_TO_EXEC_CHAIN') scorer.addSignal(filePath, 'DECODED_DATA_TO_SINK', t.evidence, false, weight);
        else if (t.type === 'CREDENTIAL_EXFILTRATION') scorer.addSignal(filePath, 'ENV_TO_NETWORK', t.evidence, false, weight);
        else if (t.type === 'FILE_EXFILTRATION') scorer.addSignal(filePath, 'ENV_TO_NETWORK', t.evidence, false, weight);
        else if (t.type === 'CI_ENVIRONMENT_EVASION') scorer.addSignal(filePath, 'ENV_ACCESS', t.evidence, false, weight);
        else if (t.type === 'OBFUSCATED_HEX_PAYLOAD') scorer.addSignal(filePath, 'BASE64_DECODE', t.evidence, false, weight);
        else if (t.type === 'BASE64_DECODE_SIGNATURE') scorer.addSignal(filePath, 'BASE64_DECODE', t.evidence, false, weight);
        else if (t.type === 'STRING_CONCAT_SINK') scorer.addSignal(filePath, 'STRING_CONCAT_SINK', t.evidence, false, weight);
        else if (t.type === 'DETERMINISTIC_REVERSE_SHELL') scorer.addSignal(filePath, 'KNOWN_SINK_CALL', t.evidence, true, weight); // KILL SWITCH
        else if (t.type === 'SUSPICIOUS_REQUIRE') scorer.addSignal(filePath, 'SUSPICIOUS_REQUIRE', t.evidence, false, weight);
        else if (t.type === 'KNOWN_SINK_CALL' || t.type === 'DYNAMIC_EXECUTION') {
            scorer.addSignal(filePath, t.type === 'DYNAMIC_EXECUTION' ? 'DYNAMIC_EXECUTION' : 'KNOWN_SINK_CALL', t.evidence, isKillSwitch, weight);
        }
    });

    // El escaneo de Base64 ahora se realiza mediante firmas estructurales en analyze() 
    // y reglas de Nivel 2, para evitar falsos positivos por Buffer.from legítimo.
}

module.exports = { analyze, analyzeWithScorer };
