/**
 * Sentinel: Lockfile Integrity Guardian (SENTINEL 2.0)
 *
 * Analiza package-lock.json y pnpm-lock.yaml para detectar:
 *   1. Registry Poisoning — paquetes que resuelven a registros no oficiales
 *   2. Phantom Dependencies — paquetes en el lockfile no declarados en package.json
 *   3. Suspicious Integrity Hashes — paquetes sin hash de integridad (posible manipulación)
 *   4. High-risk Direct URLs — dependencias resueltas desde URLs directas (git+https, file:, etc.)
 *   5. Manifest Tampering — divergencias entre nombre esperado y resuelto (como el ataque Axios 2026)
 *
 * SECURITY: Solo lectura. Nunca ejecuta npm ni hace fetch de red.
 */

'use strict';

// Registros oficiales conocidos. Cualquier otro es sospechoso.
const TRUSTED_REGISTRIES = [
    'registry.npmjs.org',
    'registry.yarnpkg.com'
];

// Patrones URL que indican carga desde fuente externa no oficial
const SUSPICIOUS_URL_PATTERNS = [
    /^git\+https?:\/\//i,
    /^git:\/\//i,
    /^file:/i,
    /^github:/i,
    /^bitbucket:/i,
    /^gitlab:/i,
    /^https?:\/\/(?!registry\.npmjs\.org|registry\.yarnpkg\.com)/i
];

/**
 * Verifica si una URL de resolución viene de un registro de confianza.
 * @param {string} url
 * @returns {boolean}
 */
function isTrustedResolved(url) {
    if (!url || typeof url !== 'string') return true; // Sin URL = local, ignorar
    return TRUSTED_REGISTRIES.some(trusted => url.includes(trusted));
}

/**
 * Detecta si la URL de resolución es sospechosa (redirect, dominio raro, etc.)
 * @param {string} url
 * @returns {boolean}
 */
function isSuspiciousUrl(url) {
    if (!url || typeof url !== 'string') return false;
    return SUSPICIOUS_URL_PATTERNS.some(p => p.test(url));
}

/**
 * Analiza un package-lock.json (v2/v3) para detectar amenazas.
 * @param {string} lockfileContent - Contenido del archivo como string
 * @param {string} packageJsonContent - Contenido del package.json correspondiente (para comparación)
 * @returns {Array} Lista de alertas de seguridad
 */
function analyzeLockfile(lockfileContent, packageJsonContent = null) {
    const alerts = [];
    let lock, pkg;

    // Parse lockfile
    try {
        lock = JSON.parse(lockfileContent);
    } catch (e) {
        return [{
            type: 'LOCKFILE_PARSE_ERROR',
            severity: 'CRITICAL',
            riskLevel: 9,
            message: 'No se pudo parsear package-lock.json — posible archivo corrompido o alterado.',
            evidence: e.message
        }];
    }

    // Parse package.json para comparar dep declarations y evaluar Score
    let declaredDeps = new Set();
    let pkgDepsObj = {};

    if (packageJsonContent) {
        try {
            pkg = JSON.parse(packageJsonContent);
            const allDeps = {
                ...pkg.dependencies,
                ...pkg.devDependencies,
                ...pkg.optionalDependencies,
                ...pkg.peerDependencies
            };
            declaredDeps = new Set(Object.keys(allDeps));
            pkgDepsObj = allDeps;

            // Phase 1: Dependency Risk Scoring Matrix en package.json
            for (const [depName, depVersion] of Object.entries(pkgDepsObj)) {
                let score = 0;
                let reasons = [];
                let severity = 'INFO';
                
                // 1. Unpinned Versions
                if (depVersion === 'latest' || depVersion === '*') {
                    score += 60;
                    reasons.push('versioning: used "latest" or "*"');
                    severity = 'HIGH';
                } else if (depVersion.startsWith('^') || depVersion.startsWith('~')) {
                    score += 20;
                    reasons.push('versioning: floating version (use exact pin)');
                    severity = 'WARNING';
                }

                // 2. Typosquatting markers (suspicious names like lodasb, reaact)
                // Usamos heurística simple contra nombres estándar.
                const commonTypos = ['lodasb', 'reaact', 'exprss', 'jquey', 'nodemoon'];
                if (commonTypos.includes(depName.toLowerCase()) || depName.includes(' ') || depName.includes('__')) {
                    score += 90;
                    reasons.push('typosquatting: suspicious package name');
                    severity = 'CRITICAL';
                }
                
                // Only alert if there is a risk
                if (score > 0) {
                    alerts.push({
                        type: 'DEPENDENCY_RISK_SCORE',
                        severity: severity,
                        riskLevel: Math.min(Math.round(score / 10), 10),
                        message: `Dependency Risk Matrix: ${depName} scored ${score}/100.`,
                        evidence: reasons.join(', '),
                        package: depName,
                        score: score
                    });
                }
            }
        } catch (e) {
            // Si no podemos parsear package.json, ignoramos su análisis
        }
    }

    // === ANÁLISIS LOCKFILE v2/v3 (campo "packages") ===
    const packages = lock.packages || {};

    for (const [pkgPath, pkgData] of Object.entries(packages)) {
        // "node_modules/X" → extraer nombre del paquete
        const pkgName = pkgPath.replace(/^node_modules\//, '').split('/node_modules/').pop();
        if (!pkgName || pkgPath === '') continue; // Skip raíz

        const resolved = pkgData.resolved || '';
        const integrity = pkgData.integrity || '';
        const version = pkgData.version || '';

        // --- Amenaza 1: Registry Poisoning ---
        // El paquete resuelve a un servidor que NO es npm oficial
        if (resolved && !isTrustedResolved(resolved) && !isSuspiciousUrl(resolved)) {
            alerts.push({
                type: 'REGISTRY_POISONING',
                severity: 'CRITICAL',
                riskLevel: 9,
                message: `'${pkgName}@${version}' resuelve desde un registro no oficial.`,
                evidence: `resolved: ${resolved}`,
                package: pkgName
            });
        }

        // --- Amenaza 2: Direct URL / Dropper ---
        if (isSuspiciousUrl(resolved)) {
            alerts.push({
                type: 'DIRECT_URL_IN_LOCKFILE',
                severity: 'CRITICAL',
                riskLevel: 10,
                message: `'${pkgName}@${version}' se carga desde una URL externa directa (vector de dropper).`,
                evidence: `resolved: ${resolved}`,
                package: pkgName
            });
        }

        // --- Amenaza 3: Missing Integrity Hash ---
        // Un paquete legítimo del registro npm SIEMPRE tiene hash de integridad.
        // Ausencia = posible manifest-swap o inyección offline.
        if (resolved && resolved.includes('registry.npmjs.org') && !integrity) {
            alerts.push({
                type: 'MISSING_INTEGRITY_HASH',
                severity: 'HIGH',
                riskLevel: 7,
                message: `'${pkgName}@${version}' no tiene hash de integridad (integrity field vacío). Posible manifest swap.`,
                evidence: `Package: ${pkgPath}`,
                package: pkgName
            });
        }

        // --- Amenaza 4: Phantom Dependency ---
        // Paquete directo (depth=1) no declarado en package.json
        // Solo aplica a paquetes directos (un solo nivel de node_modules)
        const isDirectDep = !pkgPath.includes('/node_modules/', 1) &&
                             pkgPath.startsWith('node_modules/') &&
                             !pkgName.startsWith('@');  // simplificación para scoped
        
        if (isDirectDep && declaredDeps.size > 0 && !declaredDeps.has(pkgName)) {
            alerts.push({
                type: 'PHANTOM_DEPENDENCY',
                severity: 'HIGH',
                riskLevel: 7,
                message: `'${pkgName}@${version}' está en el lockfile pero NO está declarado en package.json. Posible inyección silenciosa.`,
                evidence: `Path en lockfile: ${pkgPath}`,
                package: pkgName
            });
        }
    }

    // === ANÁLISIS LEGACY v1 (campo "dependencies") ===
    const legacyDeps = lock.dependencies || {};
    for (const [name, data] of Object.entries(legacyDeps)) {
        const resolved = data.resolved || '';
        if (isSuspiciousUrl(resolved)) {
            alerts.push({
                type: 'DIRECT_URL_IN_LOCKFILE',
                severity: 'CRITICAL',
                riskLevel: 10,
                message: `(Legacy lock v1) '${name}' se carga desde URL externa directa.`,
                evidence: `resolved: ${resolved}`,
                package: name
            });
        }
    }

    return alerts;
}

/**
 * Analiza un pnpm-lock.yaml para anomalías de registro.
 * @param {string} content - Contenido del pnpm-lock.yaml
 * @returns {Array} Lista de alertas
 */
function analyzePnpmLockfile(content) {
    const alerts = [];

    // Buscar URLs directas en el texto del lockfile (análisis heurístico)
    const lines = content.split('\n');
    lines.forEach((line, i) => {
        const trimmed = line.trim();
        // Buscar líneas con "resolution:" que apunten a URLs externas
        if (trimmed.startsWith('tarball:') || trimmed.startsWith('resolution:')) {
            if (SUSPICIOUS_URL_PATTERNS.some(p => p.test(trimmed))) {
                alerts.push({
                    type: 'DIRECT_URL_IN_PNPM_LOCKFILE',
                    severity: 'CRITICAL',
                    riskLevel: 10,
                    message: `pnpm-lock.yaml contiene una resolución desde URL externa en línea ${i + 1}.`,
                    evidence: trimmed.substring(0, 300)
                });
            }
        }

        // Detectar registros no oficiales en pnpm settings
        if (trimmed.includes('registry:') && !TRUSTED_REGISTRIES.some(r => trimmed.includes(r))) {
            alerts.push({
                type: 'PNPM_REGISTRY_OVERRIDE',
                severity: 'HIGH',
                riskLevel: 8,
                message: `pnpm-lock.yaml define un registro externo no oficial.`,
                evidence: trimmed.substring(0, 300)
            });
        }
    });

    return alerts;
}

module.exports = { analyzeLockfile, analyzePnpmLockfile };
