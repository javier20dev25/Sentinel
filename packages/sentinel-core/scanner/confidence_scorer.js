/**
 * Sentinel 3.3: Confidence Scorer
 *
 * Core engine for Adaptive Analysis. Instead of binary CRITICAL/OK heuristics,
 * this engine accumulates "Signals" of suspicious behavior. If the cumulative
 * score passes the threshold, a concrete, explainable Threat is emitted.
 *
 * This prevents false positives (e.g. innocent use of Base64) while catching
 * sophisticated attacks (e.g. Base64 + dynamic access + proxy evasion).
 */

'use strict';

// Normalización de Scores (Sentinel 3.4)
const THRESHOLDS = {
    NOISE: 29,
    SUSPICIOUS: 40,
    HIGH_RISK: 79,
    CRITICAL: 80 // Bloqueo a partir de aquí
};

const SIGNAL_WEIGHTS = {
    // Level 1
    'BASE64_DECODE': 25,            
    'DYNAMIC_PROPERTY_ACCESS': 60, 
    'ENV_ACCESS': 20,              
    'NETWORK_REQUEST': 30,         
    'STRING_CONCAT_SINK': 70,     
    'OBFUSCATED_HEX_PAYLOAD': 60,

    // Level 2
    'PROXY_WARPING': 75,          
    'PROTOTYPE_POLLUTION_ASSIGN': 85, 
    'SUSPICIOUS_REQUIRE': 60,      
    'OBSCURE_WASM_IMPORT': 60,     
    'STRING_CONSTRUCTION': 80,

    // Level 3 / Complex
    'DECODED_DATA_TO_SINK': 90,    
    'ENV_TO_NETWORK': 90,          
    'KNOWN_SINK_CALL': 80,
    'DYNAMIC_EXECUTION': 80
};

// [3.5.1] Grupos de Intención Estratégica (Modo Ofensivo)
const INTENT_GROUPS = {
    'SURVEILLANCE': ['ENV_ACCESS', 'GEOFENCING_LOCALE_CHECK', 'SENSITIVE_PATH_ACCESS', 'CI_ENVIRONMENT_EVASION'],
    'EVASION':      ['BASE64_DECODE', 'DYNAMIC_PROPERTY_ACCESS', 'PROXY_WARPING', 'SUSPICIOUS_REQUIRE', 'STRING_CONSTRUCTION', 'OBFUSCATED_HEX_PAYLOAD', 'STRING_CONCAT_SINK', 'PROTOTYPE_POLLUTION_ASSIGN'],
    'EXFILTRATION': ['NETWORK_REQUEST', 'ENV_TO_NETWORK', 'FILE_EXFILTRATION'],
    'EXECUTION':    ['KNOWN_SINK_CALL', 'STRING_CONCAT_SINK', 'DYNAMIC_EXECUTION', 'DETERMINISTIC_REVERSE_SHELL', 'DECODED_DATA_TO_SINK']
};

const CATEGORY_WEIGHTS = {
    'EXECUTION':    1.0,
    'EXFILTRATION': 0.95,
    'EVASION':      0.85,
    'SURVEILLANCE': 0.5
};

class ConfidenceScorer {
    constructor() {
        this.records = new Map();
    }

    addSignal(file, signalType, evidence, isKillSwitch = false, manualWeight = null) {
        if (!this.records.has(file)) {
            this.records.set(file, { score: 0, signals: [], killSwitch: false });
        }

        const record = this.records.get(file);
        
        if (isKillSwitch) {
            record.killSwitch = true;
            record.score = 100;
        }

        const weight = manualWeight !== null ? manualWeight : (SIGNAL_WEIGHTS[signalType] || 5);
        record.signals.push({ type: signalType, weight, evidence: evidence.substring(0, 150) });
        
        this._recalculateScore(file);
    }

    /**
     * Implementa el flujo de evaluación v3.5.1 (Modo Ofensivo).
     * Secuencia: Dominant Risk -> Diversity Check -> Composite Scaling -> Actions.
     */
    _recalculateScore(file) {
        const record = this.records.get(file);
        if (record.killSwitch) return;

        if (record.signals.length === 0) {
            record.score = 0;
            return;
        }

        // 1. Atenuación de Inflación (Diminishing Returns) y Pesos Estratégicos
        const typeCounts = {};
        const weightedSignals = record.signals.map(s => {
            typeCounts[s.type] = (typeCounts[s.type] || 0) + 1;
            
            // Mitigar spameo de la misma señal (0.5 factor de atenuación)
            const countFactor = 1 / (1 + (typeCounts[s.type] - 1) * 0.5);
            
            // Encontrar categoría para peso estratégico
            let catWeight = 0.5; // default surveillance
            for (const [cat, types] of Object.entries(INTENT_GROUPS)) {
                if (types.includes(s.type)) {
                    catWeight = CATEGORY_WEIGHTS[cat];
                    break;
                }
            }

            return { ...s, effectiveWeight: s.weight * countFactor * catWeight };
        });

        // [3.5.1] FIXED: Cálculo de Riesgo Dominante (Saneado)
        const sortedSignals = [...weightedSignals].sort((a, b) => b.effectiveWeight - a.effectiveWeight);
        const maxWeight = sortedSignals[0] ? sortedSignals[0].effectiveWeight : 0;
        const restWeight = sortedSignals.slice(1).reduce((acc, s) => acc + s.effectiveWeight, 0);

        // 3. Detección de Diversidad de Intención (Modo Ofensivo)
        const activeGroups = new Set();
        let maxCategoryRisk = 0;
        
        weightedSignals.forEach(s => {
            for (const [cat, types] of Object.entries(INTENT_GROUPS)) {
                if (types.includes(s.type)) {
                    activeGroups.add(cat);
                    if (s.effectiveWeight > maxCategoryRisk) maxCategoryRisk = s.effectiveWeight;
                }
            }
        });

        const diversity = activeGroups.size;
        const hasCriticalIntent = activeGroups.has('EXECUTION') || activeGroups.has('EXFILTRATION');
        
        let residualFactor = 0.10;
        let dynamicCap = 55;
        let isCompositeMode = false;

        // [3.5.1] GUARDIA ENTERPRISE (Calibrada v3.5.1.2): 
        // Solo entramos en modo compuesto si hay diversidad real (3+) Y una señal suspicaz fuerte (>30).
        // Esto evita que el ruido de herramientas de sistema active bloqueos accidentalmente.
        if (diversity >= 3 && hasCriticalIntent && maxWeight > 30) {
            isCompositeMode = true;
            residualFactor = 0.20; // v3.5.2: Atemperamos la suma de señales débiles
            dynamicCap = 60 + (diversity * 5); // v3.5.1 Dynamic CAP
        }

        let effectiveCap = isCompositeMode ? dynamicCap : 55;
        // Escape Hatch: Si hay una señal individual lo bastante ruidosa (ej. SARB Evasión), puede romper el techo corporativo.
        if (maxWeight > effectiveCap) {
             effectiveCap = maxWeight;
        }
        
        let rawScore = maxWeight + (restWeight * residualFactor);
        
        // [3.5.1] FIXED: CAP estricto para evitar FP en herramientas de sistema.
        rawScore = Math.min(rawScore, effectiveCap);

        // 5. Función Logística y Reglas de Bloqueo Forzado
        const k = 0.15; 
        const mid = 50; // v3.5.2: Punto de equilibrio recuperado
        let finalScore = 100 / (1 + Math.exp(-k * (rawScore - mid)));

        // FORCE BLOCK RULE: Si modo ofensivo sospecha fuertemente (75+), bloquear.
        if (isCompositeMode && finalScore >= 75) {
            finalScore = 82; // Trigger crítico
        }

        record.score = Math.round(finalScore);
        record.diversity = diversity;
        record.isComposite = isCompositeMode;
        
        record.metrics = {
             rawScore,
             finalScore,
             effectiveCap,
             residualFactor,
             maxWeight,
             restWeight
        };
    }

    evaluateFile(file) {
        const record = this.records.get(file);
        if (!record) return null;

        // [3.5.1] Near-Miss Logic: Files that are suspicious but didn't hit the 80+ block.
        const isNearMiss = record.score >= 65 && record.score < THRESHOLDS.CRITICAL;
        
        if (record.score < THRESHOLDS.SUSPICIOUS && !isNearMiss) return null;

        const threat = this._generateThreat(file, record);
        
        // Inject immutability for CLI Explain Tools & Forensic Mode
        threat._rawRecord = JSON.parse(JSON.stringify(record));
        threat.intentFingerprint = this._generateFingerprint(record);

        if (isNearMiss) {
            threat.nearMissIntelligence = threat.intentFingerprint;
            threat.category = 'near-miss-audit';
        }

        return threat;
    }

    /**
     * Genera una huella estructural para análisis de campañas (Sentinel 3.5.1).
     */
    _generateFingerprint(record) {
        const intentSignature = new Set();
        const signalPattern = new Set();
        
        record.signals.forEach(s => {
            signalPattern.add(s.type);
            for (const [cat, types] of Object.entries(INTENT_GROUPS)) {
                if (types.includes(s.type)) intentSignature.add(cat);
            }
        });

        return {
            intent_signature: Array.from(intentSignature).sort(),
            signal_pattern: Array.from(signalPattern).sort(),
            composite: record.isComposite,
            diversity: record.diversity
        };
    }

    evaluateAll() {
        const threats = [];
        for (const file of this.records.keys()) {
            const threat = this.evaluateFile(file);
            if (threat) threats.push(threat);
        }
        return threats;
    }

    _generateThreat(file, record) {
        let category = "SUSPICIOUS";
        let severity = "MEDIUM";
        
        if (record.score >= THRESHOLDS.CRITICAL) {
            category = "CRITICAL";
            severity = "CRITICAL";
        } else if (record.score >= THRESHOLDS.HIGH_RISK) {
            category = "HIGH_RISK";
            severity = "HIGH";
        }

        const logicPath = record.signals.map(s => s.type).join(' → ');
        
        return {
            ruleName: `Adaptive Engine [${category}][Score: ${record.score}/100]`,
            category: 'behavior-graph',
            riskLevel: record.score, 
            severity: severity,
            description: record.killSwitch 
                ? `[KILL SWITCH] Amenaza determinística detectada. Bloqueo inmediato.`
                : `Combinación de señales detectada con confianza ${record.score}/100.`,
            evidence: `Cadena Causal: [ ${logicPath} ]\nSignals:\n` + 
                      record.signals.map(s => ` - ${s.type}: ${s.evidence}`).join('\n')
        };
    }
}

module.exports = ConfidenceScorer;
