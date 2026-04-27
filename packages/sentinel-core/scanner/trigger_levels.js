/**
 * Sentinel 3.3: Trigger Levels Orchestrator
 *
 * Implements the Adaptive Graph approach. Analysis escalates through levels
 * only when suspicious signals push the Confidence Score higher. This saves
 * CPU time by avoiding deep cross-taint analysis on harmless files.
 */

'use strict';

const astInspector = require('./ast_inspector');
// const { analyzeBinary } = require('./detector_binary');
// Level 3 analyzers would go here (e.g. cross_file_taint.js)

class TriggerLevelOrchestrator {
    constructor(scorer) {
        this.scorer = scorer;
    }

    /**
     * Nivel 1: AST Rápido y recolección de firmas estructurales.
     * Genera el puntaje base del archivo.
     */
    runLevel1(content, filename) {
        // Enlazar el inspector de AST para que envíe sus señales directas a nuestro Scorer.
        // astInspector.analyze ahora retorna señales, no amenazas absolutas.
        astInspector.analyzeWithScorer(content, filename, this.scorer);
        
        return this.scorer.records.get(filename)?.score || 0;
    }

    /**
     * Nivel 2: Análisis Semántico en Profundidad (Solo si Nivel 1 vio algo extraño).
     * Ejemplo: Si Nivel 1 vio un base64, el Nivel 2 intenta decodificarlo y ver si 
     * su contenido se asemeja a código o a datos inofensivos.
     */
    runLevel2(content, filename) {
        const record = this.scorer.records.get(filename);
        if (!record) return;

        // Comportamiento semántico 1: Decodificación perezosa
        const hasBase64Signal = record.signals.some(s => s.type === 'BASE64_DECODE');
        if (hasBase64Signal) {
            this._runLazyBase64Decode(content, filename);
        }

        // Comportamiento semántico 2: Evaluación de Sink Dinámico
        const hasDynamicAccess = record.signals.some(s => s.type === 'DYNAMIC_PROPERTY_ACCESS');
        if (hasDynamicAccess && record.score >= 5) {
            // Re-evaluar el contenido para buscar si tras la ofuscación dinámica se llama a la ejecución
            // (Simulación simple)
            if (content.includes('global[') || content.includes('window[')) {
                 if (content.includes('eval') || content.includes('exec')) {
                     this.scorer.addSignal(filename, 'DECODED_DATA_TO_SINK', 'Base64/Dynamic code resolved to execution sink (eval/exec)');
                 }
            }
        }
    }

    /**
     * Extrae literales sospechosos y los decodifica como B64.
     */
    _runLazyBase64Decode(content, filename) {
        // [3.3] Contextual Decoding: Scan entire file for Base64-like strings if Level 1 triggered
        // This catches cases where the string is in a variable separate from Buffer.from
        const b64Regex = /['"]([A-Za-z0-9+/=]{12,})['"]/g;
        let match;
        while ((match = b64Regex.exec(content)) !== null) {
            const potentialB64 = match[1];
            try {
                const decoded = Buffer.from(potentialB64, 'base64').toString('utf8');
                // Check if decoded string contains a dangerous sink
                const sinks = ['eval', 'exec', 'spawn', 'Function', 'setTimeout', 'setInterval'];
                const hasSink = sinks.some(s => decoded.includes(s));
                
                if (hasSink && /^[\x20-\x7E\s]{5,}$/.test(decoded)) {
                    this.scorer.addSignal(filename, 'DECODED_DATA_TO_SINK', 
                        `Payload ofuscado detectado: "${potentialB64.substring(0, 30)}..." decodifica a código: "${decoded.substring(0, 50)}..."`);
                }
            } catch (e) {
                // Ignore decoding errors
            }
        }
    }

    /**
     * Ejecuta el pipeline completo de manera escalonada (Sentinel 3.4).
     * O(1) en archivos limpios, O(n) en sospechosos, O(n2) solo en alto riesgo.
     */
    analyze(content, filename) {
        // Nivel 1: Siempre obligatorio
        const baseScore = this.runLevel1(content, filename);

        // Nivel 2: Semantic Analysis (Sólo si Score >= 30)
        if (baseScore >= 30) {
            this.runLevel2(content, filename);
        }

        // Nivel 3: Execution Graph / Cross-file (Sólo si Score >= 60)
        const currentScore = this.scorer.records.get(filename)?.score || 0;
        if (currentScore >= 60 && currentScore < 80) {
            this.runLevel3(filename, content);
        }
    }

    /**
     * Nivel 3: Deep Execution Graph (Simulado con Depth Cap Híbrido)
     */
    runLevel3(filename, content, depth = 0) {
        const record = this.scorer.records.get(filename);
        if (!record || record.score >= 80) return; // Early stop si ya es crítico

        // Cap Híbrido: Soft 3, Hard 5.
        const SOFT_CAP = 3;
        const HARD_CAP = 5;

        if (depth >= HARD_CAP) return;
        
        // Si estamos entre soft y hard, solo seguimos si el score es ascendente
        if (depth >= SOFT_CAP && !this._isHighConfidencePath(record)) return;

        // Simulación de búsqueda de saltos de dependencia (Aliasing entre archivos)
        // [TODO: Integración con cross_file_taint.js en Fase 4]
        if (content.includes('import') || content.includes('require')) {
            // Lógica de expansión de grafo aquí...
        }
    }

    _isHighConfidencePath(record) {
        // El grafo solo se extiende si detectamos señales que sumen (no que se enfríen)
        return record.signals.length > 2;
    }
}

module.exports = TriggerLevelOrchestrator;
