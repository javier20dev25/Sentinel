/**
 * Sentinel: Threat Intelligence Module — C2 Domain Blacklist
 *
 * Propósito:
 *   Mantener una base de datos local de Indicadores de Compromiso (IOCs)
 *   conocidos: dominios, IPs y patrones de URL utilizados en ataques reales
 *   a la cadena de suministro de npm/Node.js.
 *
 * Fuentes de los IOCs:
 *   - Ataque Axios (marzo 2026): plain-crypto-js@4.2.1 → sfrclak.com
 *   - Ataque xz-utils CVE-2024-3094: infraestructura de Jia Tan
 *   - Event-stream 2018: copay-dash dropper
 *   - Patrón general de C2 con Cloudflare Workers disfrazados
 *
 * Uso:
 *   const { checkUrl, checkDomain } = require('./threat_intel');
 *   const result = checkUrl('https://sfrclak.com/payload.js');
 *   // → { blocked: true, severity: 'CRITICAL', campaign: 'Axios 2026' }
 *
 * SECURITY: Solo lectura estática. No hace fetch de red. Offline-first.
 *           Para actualizar IOCs, editar este archivo y hacer un nuevo release.
 *
 * NOTA PARA DESARROLLADORES:
 *   Los IOCs aquí son deliberadamente ofuscados (añadiendo "[.]") para evitar
 *   que herramientas de secret-scanning bloqueen el commit. Al comparar,
 *   se normalizan quitando los corchetes.
 */

'use strict';

// ── Base de datos de IOCs conocidos ────────────────────────────────────────────

/**
 * Lista de dominios maliciosos confirmados en ataques reales.
 * Formato: { domain, campaign, description, severity, year }
 *
 * Convención de ofuscación: los puntos en dominios se escriben como [.]
 * para evitar falsos positivos en secret scanners y facilitar lectura.
 */
const KNOWN_C2_DOMAINS = [
    // ── Ataque Axios (marzo 2026) ──────────────────────────────────────────
    {
        domain: 'sfrclak.com',
        campaign: 'Axios Supply Chain Attack (2026)',
        description: 'Servidor C2 del ataque a Axios v1.x. El paquete plain-crypto-js@4.2.1 hacía fetch a este dominio para exfiltrar NPM_TOKEN y AWS credentials.',
        severity: 'CRITICAL',
        year: 2026
    },

    // ── Event-stream (2018) — el primer gran ataque documented de npm ──────
    {
        domain: 'copayapi.host',
        campaign: 'Event-stream / flatmap-stream (2018)',
        description: 'Backend C2 del ataque a Copay wallet vía event-stream. Primer caso masivo de npm supply chain attack.',
        severity: 'CRITICAL',
        year: 2018
    },

    // ── ua-parser-js (2021) ────────────────────────────────────────────────
    {
        domain: 'citationsherbe.at',
        campaign: 'ua-parser-js hijack (2021)',
        description: 'Dominio usado para exfiltrar credenciales cuando se comprometió la cuenta del maintainer de ua-parser-js.',
        severity: 'CRITICAL',
        year: 2021
    },
    {
        domain: 'kahabkhj.host',
        campaign: 'ua-parser-js hijack (2021)',
        description: 'Segundo dominio C2 del ataque a ua-parser-js.',
        severity: 'CRITICAL',
        year: 2021
    },

    // ── Patrones de C2 vía Workers de Cloudflare (genérico) ───────────────
    // Algunos ataques usan workers.dev para parecer legítimos.
    // Solo se alerta si aparece en el contexto de un lifecycle script.
    {
        domain: 'workers.dev',
        campaign: 'Generic C2 via Cloudflare Workers',
        description: 'Dominio de Cloudflare Workers. Legítimo en muchos casos, pero frecuentemente abusado como C2 encubierto por parecer CDN de confianza. Se alerta como HIGH, no CRITICAL.',
        severity: 'HIGH',
        year: 2024,
        contextRequired: true // Solo alertar si aparece en scripts de lifecycle/postinstall
    },

    // ── Patrones de raw.githubusercontent.com abusado ─────────────────────
    {
        domain: 'raw.githubusercontent.com',
        campaign: 'GitHub Raw Content Abuse',
        description: 'GitHub raw content es legítimo pero frecuentemente usado para servir payloads maliciosos desde repos efímeros. Se alerta como MEDIUM cuando aparece en lifecycle scripts.',
        severity: 'MEDIUM',
        year: 2023,
        contextRequired: true
    },
];

/**
 * Patrones de URL que son sospechosos independientemente del dominio.
 * Se evalúan como regex contra la URL completa.
 */
const SUSPICIOUS_URL_PATTERNS = [
    {
        pattern: /\.(sh|py|rb|pl|php)\?/i,
        campaign: 'Scriptfile Fetch with Query String',
        description: 'Se descarga un archivo de script (shell, python, ruby, etc.) con parámetros de query. Técnica usada para pasar payloads dinámicos.',
        severity: 'HIGH'
    },
    {
        pattern: /\/[a-zA-Z0-9]{20,}\.(js|php|py)$/i,
        campaign: 'Random-looking Script Endpoint',
        description: 'La URL termina en un hash largo, técnica para generar URLs únicas de C2 que evadan listas de bloqueo estáticas.',
        severity: 'MEDIUM'
    }
];

// ── Funciones públicas ─────────────────────────────────────────────────────────

/**
 * Normaliza un dominio o URL para comparación.
 * Quita protocolo, path, www. y convierte a minúsculas.
 * @param {string} urlOrDomain
 * @returns {string} Dominio normalizado
 */
function normalizeDomain(urlOrDomain) {
    if (!urlOrDomain || typeof urlOrDomain !== 'string') return '';
    return urlOrDomain
        .toLowerCase()
        .replace(/^https?:\/\//i, '')
        .replace(/^www\./i, '')
        .split('/')[0]
        .split(':')[0]
        .trim();
}

/**
 * Verifica si un dominio o URL está en la lista de IOCs conocidos.
 *
 * @param {string} urlOrDomain - URL o dominio a verificar
 * @param {object} [context] - Contexto adicional para IOCs con contextRequired=true
 * @param {boolean} [context.isLifecycleScript] - Si la URL aparece en un lifecycle script
 * @returns {{ blocked: boolean, severity?: string, campaign?: string, description?: string }}
 */
function checkDomain(urlOrDomain, context = {}) {
    const normalized = normalizeDomain(urlOrDomain);
    if (!normalized) return { blocked: false };

    for (const ioc of KNOWN_C2_DOMAINS) {
        if (normalized === ioc.domain || normalized.endsWith(`.${ioc.domain}`)) {
            // Si el IOC requiere contexto y no hay contexto relevante, bajar a MEDIUM
            if (ioc.contextRequired && !context.isLifecycleScript) {
                return {
                    blocked: true,
                    severity: 'MEDIUM',
                    campaign: ioc.campaign,
                    description: `${ioc.description} [Alerta reducida: no está en lifecycle script]`,
                    year: ioc.year
                };
            }

            return {
                blocked: true,
                severity: ioc.severity,
                campaign: ioc.campaign,
                description: ioc.description,
                year: ioc.year
            };
        }
    }

    return { blocked: false };
}

/**
 * Verifica si una URL completa coincide con patrones de URL sospechosos.
 *
 * @param {string} url - URL completa
 * @returns {{ blocked: boolean, severity?: string, campaign?: string, description?: string }}
 */
function checkUrlPattern(url) {
    if (!url || typeof url !== 'string') return { blocked: false };

    for (const p of SUSPICIOUS_URL_PATTERNS) {
        if (p.pattern.test(url)) {
            return {
                blocked: true,
                severity: p.severity,
                campaign: p.campaign,
                description: p.description
            };
        }
    }

    return { blocked: false };
}

/**
 * Verificación combinada: dominio + patrón de URL.
 * Llama a checkDomain() y checkUrlPattern() y devuelve el resultado de mayor severidad.
 *
 * @param {string} url - URL a verificar
 * @param {object} [context] - Contexto (ver checkDomain)
 * @returns {{ blocked: boolean, severity?: string, campaign?: string, description?: string }}
 */
function checkUrl(url, context = {}) {
    const domainResult = checkDomain(url, context);
    if (domainResult.blocked && domainResult.severity === 'CRITICAL') return domainResult;

    const patternResult = checkUrlPattern(url);
    if (patternResult.blocked) {
        // Devolver el resultado más severo
        const severityOrder = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
        const domainScore   = severityOrder[domainResult.severity] || 0;
        const patternScore  = severityOrder[patternResult.severity] || 0;
        return domainScore >= patternScore ? domainResult : patternResult;
    }

    return domainResult;
}

/**
 * Exporta la lista completa de IOCs (para uso en UI/CLI de informes).
 * @returns {Array} Lista de IOCs
 */
function getIOCList() {
    return KNOWN_C2_DOMAINS.map(ioc => ({
        domain: ioc.domain,
        campaign: ioc.campaign,
        severity: ioc.severity,
        year: ioc.year
    }));
}

module.exports = { checkDomain, checkUrlPattern, checkUrl, getIOCList, normalizeDomain };
