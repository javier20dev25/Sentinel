/**
 * Sentinel: Configuration Integrity Monitor (SENTINEL 2.0)
 *
 * Escanea archivos de configuración de gestores de paquetes para detectar:
 *   1. Registry Override — se redirige a un servidor malicioso
 *   2. always-auth: false — desactiva autenticación (vector de MITM)
 *   3. Proxy Injection — se inyecta un proxy para interceptar tráfico de instalación
 *   4. Token Exfiltration Config — `//registry.example.com/:_authToken` hardcodeado
 *   5. Script Hooks de npm — hooks en .npmrc que ejecutan código al instalar
 *
 * Archivos analizados: .npmrc, .yarnrc, .yarnrc.yml, .npmrc.local
 *
 * SECURITY: Solo lectura de texto. Sin ejecución, sin red.
 */

'use strict';

// Registros de confianza para comparación
const TRUSTED_REGISTRIES = [
    'registry.npmjs.org',
    'registry.yarnpkg.com',
    'npm.pkg.github.com'  // GitHub Packages es legítimo
];

/**
 * Verifica si un valor de registry es de confianza.
 * @param {string} value
 * @returns {boolean}
 */
function isTrustedRegistry(value) {
    if (!value) return true;
    return TRUSTED_REGISTRIES.some(trusted => value.includes(trusted));
}

/**
 * Analiza el contenido de un archivo .npmrc o .yarnrc (formato INI).
 * @param {string} content - Contenido del archivo de configuración
 * @param {string} filename - Nombre del archivo (para contexto)
 * @returns {Array} Lista de alertas de seguridad
 */
function analyzeNpmrc(content, filename = '.npmrc') {
    const alerts = [];
    const lines = content.split('\n');

    lines.forEach((line, i) => {
        const trimmed = line.trim();

        // Ignorar líneas de comentarios o vacías
        if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith(';')) return;

        const lineNum = i + 1;

        // --- Amenaza 1: Registry Override ---
        // registry=http://evil-registry.com
        if (/^registry\s*=/i.test(trimmed)) {
            const val = trimmed.split('=').slice(1).join('=').trim();
            if (!isTrustedRegistry(val)) {
                alerts.push({
                    type: 'REGISTRY_OVERRIDE',
                    severity: 'CRITICAL',
                    riskLevel: 10,
                    message: `${filename}:${lineNum} — El registry ha sido redirigido a un servidor externo no oficial.`,
                    evidence: trimmed,
                    recommendation: 'Verifica si este cambio fue autorizado. Si no, remuévelo y ejecuta npm config set registry https://registry.npmjs.org'
                });
            }
        }

        // --- Amenaza 2: Proxy Injection ---
        // proxy=http://attacker-proxy.com
        if (/^(https?-)?proxy\s*=/i.test(trimmed)) {
            alerts.push({
                type: 'PROXY_INJECTION',
                severity: 'HIGH',
                riskLevel: 8,
                message: `${filename}:${lineNum} — Configuración de proxy detectada. Un atacante puede usarlo para interceptar tokens y paquetes.`,
                evidence: trimmed,
                recommendation: 'Solo permite proxies corporativos verificados. Reporta al equipo de seguridad si no lo reconoces.'
            });
        }

        // --- Amenaza 3: always-auth = false ---
        if (/^always-auth\s*=\s*false/i.test(trimmed)) {
            alerts.push({
                type: 'AUTH_BYPASS',
                severity: 'HIGH',
                riskLevel: 7,
                message: `${filename}:${lineNum} — 'always-auth' está desactivado. Esto expone tu cliente a ataques MITM durante la instalación de paquetes.`,
                evidence: trimmed,
                recommendation: 'Establece always-auth=true o elimina esta línea.'
            });
        }

        // --- Amenaza 4: Hardcoded Auth Token ---
        // //registry.npmjs.org/:_authToken=npm_xxxxxxxx
        if (trimmed.includes(':_authToken=') || trimmed.includes(':_password=') || trimmed.includes(':_auth=')) {
            // Hardcoded tokens en repositorios compartidos son un riesgo crítico
            alerts.push({
                type: 'HARDCODED_AUTH_TOKEN',
                severity: 'CRITICAL',
                riskLevel: 9,
                message: `${filename}:${lineNum} — Token de autenticación hardcodeado encontrado. Si este archivo está en el repo, el token está expuesto.`,
                evidence: trimmed.replace(/=.+/, '=***REDACTED***'),
                recommendation: 'Usa variables de entorno (NPM_TOKEN) en lugar de tokens hardcodeados. Agrega .npmrc a .gitignore.'
            });
        }

        // --- Amenaza 5: Script Hook en npm 7+ ---
        // npm tiene hooks como "preinstall", "postinstall" en .npmrc de proyectos
        if (/^(pre|post)(install|pack|publish|prepare)\s*=/i.test(trimmed)) {
            alerts.push({
                type: 'NPMRC_SCRIPT_HOOK',
                severity: 'CRITICAL',
                riskLevel: 9,
                message: `${filename}:${lineNum} — Script hook detectado en ${filename}. Puede ejecutar código arbitrario en la instalación.`,
                evidence: trimmed,
                recommendation: 'Revisa manualmente si este hook es legítimo. Elimínalo si no reconoces su origen.'
            });
        }

        // --- Amenaza 6: Scope registry redirect ---
        // @malicious:registry=https://evil.example.com
        if (/^@\w+:registry\s*=/i.test(trimmed)) {
            const val = trimmed.split('=').slice(1).join('=').trim();
            if (!isTrustedRegistry(val)) {
                alerts.push({
                    type: 'SCOPED_REGISTRY_OVERRIDE',
                    severity: 'HIGH',
                    riskLevel: 8,
                    message: `${filename}:${lineNum} — Un scope de paquete está siendo redirigido a un registro externo no oficial.`,
                    evidence: trimmed,
                    recommendation: 'Solo acepta registros corporativos conocidos (GitHub Packages, Artifactory). Reporta cualquier dominio desconocido.'
                });
            }
        }
    });

    return alerts;
}

/**
 * Analiza el contenido de un .yarnrc.yml (formato YAML de Yarn 2/Berry).
 * @param {string} content - Contenido del archivo
 * @param {string} filename - Nombre del archivo para contexto
 * @returns {Array} Lista de alertas
 */
function analyzeYarnrcYml(content, filename = '.yarnrc.yml') {
    const alerts = [];
    const lines = content.split('\n');

    lines.forEach((line, i) => {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) return;

        const lineNum = i + 1;

        // npmRegistryServer override
        if (/^npmRegistryServer\s*:/i.test(trimmed)) {
            const val = trimmed.split(':').slice(1).join(':').trim();
            if (val && !isTrustedRegistry(val)) {
                alerts.push({
                    type: 'YARN_REGISTRY_OVERRIDE',
                    severity: 'CRITICAL',
                    riskLevel: 10,
                    message: `${filename}:${lineNum} — Yarn Berry está configurado para usar un registro externo no oficial.`,
                    evidence: trimmed,
                    recommendation: 'Verifica el origen de este cambio. Remueve si no está autorizado.'
                });
            }
        }

        // httpProxy / httpsProxy
        if (/^https?Proxy\s*:/i.test(trimmed)) {
            alerts.push({
                type: 'YARN_PROXY_INJECTION',
                severity: 'HIGH',
                riskLevel: 8,
                message: `${filename}:${lineNum} — Configuración de proxy detectada en Yarn Berry.`,
                evidence: trimmed
            });
        }

        // enableScripts: false puede ser anulado maliciosamente a true
        if (/^enableScripts\s*:\s*true/i.test(trimmed)) {
            alerts.push({
                type: 'YARN_SCRIPTS_ENABLED',
                severity: 'MEDIUM',
                riskLevel: 5,
                message: `${filename}:${lineNum} — Scripts de lifecycle están habilitados explícitamente en Yarn Berry. Verifica que sea intencional.`,
                evidence: trimmed
            });
        }
    });

    return alerts;
}

module.exports = { analyzeNpmrc, analyzeYarnrcYml };
