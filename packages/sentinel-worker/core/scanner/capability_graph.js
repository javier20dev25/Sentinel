/**
 * Sentinel: Capability Graph & Taint Tracker (v6.9 - Sovereign)
 * 
 * Implements a lightweight flow analysis engine to identify data paths
 * from SENSITIVE SOURCES to SUSPICIOUS SINKS, even across transformations.
 */

'use strict';

class CapabilityGraph {
    constructor() {
        this.nodes = {
            SOURCES: {
                'SECRET': [/process\.env\.[A-Z_]+/, /require\(['"]fs['"]\)\.readFileSync\(['"].*\.env['"]\)/, /auth_token/, /api_key/i],
                'SYSTEM': [/process(?!\.nextTick)/, /os\.(userInfo|homedir|hostname)/, /require\(['"](os|fs)['"]\)/, /process\.cwd\(\)/],
                'PROTOTYPE': [/\[\s*['"]constructor['"]\s*\]/, /\.(filter|map|reduce|find|forEach)\.constructor/, /prototype\.pollute/],
                'CREDENTIALS': [/\.pem['"]/, /\.key['"]/, /password/i]
            },
            TRANSFORMS: {
                'ENCODING': [/Buffer\.from\(/, /String\.fromCharCode\(/, /\.toString\(['"]hex['"]\)/],
                'OBFUSCATION': [/\.split\(['"]['"]\)\.reverse\(\)\.join\(['"]['"]\)/, /eval\(.*fromCharCode/],
                'COMPRESSION': [/require\(['"]zlib['"]\)/, /\.gzip\(/]
            },
            SINKS: {
                'NETWORK': [/fetch\s*\(/, /axios\s*\./, /https?\.get\(/, /new\s+WebSocket\(/, /Reflect\.get\(.*['"]fetch['"]\)/, /dns\.lookup\(/, /XMLHttpRequest/],
                'EXECUTION': [/eval\s*\(/, /Function\s*\(/, /constructor\.constructor/, /child_process\.(exec|spawn)/, /vm\.runInContext/, /require\(['"](child_process|vm)['"]\)/],
                'PERSISTENCE': [/fs\.(write|rm|unlink|rename|mkdir)/, /git\s+config/, /npm_config_registry/]
            }
        };
    }

    /**
     * Analyzes content for source-sink flows.
     */
    trace(content) {
        const findings = {
            sources: [],
            transforms: [],
            sinks: [],
            paths: []
        };

        // 1. Identify active nodes
        for (const [cat, items] of Object.entries(this.nodes)) {
            for (const [name, patterns] of Object.entries(items)) {
                if (patterns.some(p => p.test(content))) {
                    findings[cat.toLowerCase()].push(name);
                }
            }
        }

        // 2. Synthesize Evidence Paths (Capability Chains)
        if (findings.sinks.length > 0) {
            const sources = findings.sources.length > 0 ? findings.sources : ['IMPLICIT'];
            sources.forEach(src => {
                findings.sinks.forEach(sink => {
                    const hasTransform = findings.transforms.length > 0;
                    findings.paths.push({
                        origin: src,
                        intermediate: findings.transforms,
                        destination: sink,
                        severity: this._calcChainSeverity(src, sink, hasTransform)
                    });
                });
            });
        }

        // 3. Heuristic Fallback (v7.2 - Trace Metadata)
        // Ensure every scan with suspicious nodes has at least one path for explainability
        if (findings.paths.length === 0 && (findings.sources.length > 0 || findings.transforms.length > 0)) {
            const origin = findings.sources[0] || 'HEURISTIC';
            
            let destination = 'LIKELY_EXECUTION';
            const heuristicReasons = [];

            if (/http|fetch|dns|axios|net\./i.test(content)) {
                destination = 'LIKELY_EXFILTRATION';
                heuristicReasons.push({ signal: 'network resolution/transport patterns detected', weight: 0.85 });
            } else if (/fs\.|rm\s+-|unlink|writeFile/i.test(content)) {
                destination = 'LIKELY_SABOTAGE';
                heuristicReasons.push({ signal: 'destructive filesystem operations detected', weight: 0.95 });
            } else {
                heuristicReasons.push({ signal: 'dynamic execution/evaluation keywords detected', weight: 0.70 });
            }

            if (findings.transforms.length > 0) {
                heuristicReasons.push({ signal: `obfuscation/encoding detected: ${findings.transforms.join(', ')}`, weight: 0.60 });
            }

            findings.paths.push({
                origin,
                intermediate: findings.transforms,
                destination,
                severity: 3,
                isHeuristic: true,
                heuristicReasons
            });
        }

        return findings;
    }

    _calcChainSeverity(src, sink, hasTransform) {
        let base = (src === 'IMPLICIT' || src === 'HEURISTIC') ? 4 : 5;
        if (src === 'SECRET' && sink === 'NETWORK') base = 10;
        if (src === 'CREDENTIALS' && sink === 'NETWORK') base = 10;
        if (src === 'SYSTEM' && (sink === 'EXECUTION' || sink === 'PERSISTENCE')) base = 9;
        if (src === 'PROTOTYPE' && sink === 'EXECUTION') base = 10;
        if (hasTransform) base += 1; 
        return Math.min(10, base);
    }

    /**
     * Generates an Evidence Graph for explainability.
     */
    getEvidenceGraph(findings) {
        if (findings.paths.length === 0) return null;
        return findings.paths.map(p => {
            const chain = [p.origin, ...p.intermediate, p.destination].join(' → ');
            return `Capability Path: ${chain} (Severity: ${p.severity})`;
        });
    }
}

module.exports = new CapabilityGraph();
