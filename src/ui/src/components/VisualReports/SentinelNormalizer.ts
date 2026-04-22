import { SentinelReport_v361 } from './SentinelReportSchema';

export type NormalizedFinding = {
    id: string;
    ruleId: string;
    explanation: string;
    matchedPatterns: string[];
    targetName: string;
    targetPath?: string;
    riskScore: number;
    severityLabel: string;
    intents: string[];
    traceContext?: any[];
    logisticRecord?: any;
    ruleName?: string;
};

export type NormalizedReportModel = {
    meta: {
        version: string;
        rulepack: string;
        source: string;
        analysisMode: string;
        executionScope: string;
    };
    summary: {
        threatsCount: number;
        filesScanned: number;
        averageRisk: number;
        confidence_score: number;
        confidence_source: "engine" | "derived";
    };
    findings: NormalizedFinding[];
};

export function computeConfidence(executionMode: string): number {
    if (executionMode === "isolated") return 92;
    if (executionMode === "none") return 65;
    return 50;
}

/**
 * Transforms a raw v3.6.1 parsed dictionary into a stable, agnostic UI Model.
 */
export function normalizeReport_v361(raw: SentinelReport_v361): NormalizedReportModel {
    
    const threats = raw.rawAlerts || [];
    const averageRisk = threats.length > 0 
        ? Math.round(threats.reduce((acc, t) => acc + t.riskLevel, 0) / threats.length)
        : 0;
        
    const engineConfidence = raw.summary;
    
    return {
        meta: {
            version: raw.version,
            rulepack: raw.rulepack_version || 'unknown',
            source: raw.context?.source || 'unknown',
            analysisMode: raw.context?.analysis_mode || 'unknown',
            executionScope: raw.context?.execution || 'unknown'
        },
        summary: {
            threatsCount: threats.length,
            filesScanned: raw.filesScanned || 0,
            averageRisk: averageRisk,
            confidence_score: engineConfidence?.confidence_score || computeConfidence(raw.context?.execution || 'unknown'),
            confidence_source: engineConfidence?.confidence_source || 'derived'
        },
        findings: threats.map((t, idx) => ({
            id: `finding-${idx}-${Math.random().toString(36).substr(2, 5)}`,
            ruleId: t.rule_id,
            explanation: t.explanation,
            matchedPatterns: t.matched_patterns || [],
            targetName: t._file || t.ruleName || 'Unknown',
            targetPath: t._fullPath,
            riskScore: t.riskLevel,
            severityLabel: t.severity,
            ruleName: t.ruleName,
            intents: t.intentFingerprint?.intent_signature || [],
            traceContext: t._rawRecord?.signals || [],
            logisticRecord: t._rawRecord || {}
        }))
    };
}
