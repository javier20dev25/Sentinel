import React from 'react';
import { Target, Activity, ShieldAlert, Zap, Layers, Cpu } from 'lucide-react';
import { NormalizedFinding } from './SentinelNormalizer';

export const ThreatDrillDown: React.FC<{ threat: NormalizedFinding, context: any }> = ({ threat, context }) => {
    
    const rec = threat.logisticRecord;
    const isIsolated = context?.executionScope === 'isolated';

    // Safely parse metrics
    const metrics = rec?.metrics || { rawScore: threat.riskScore, finalScore: threat.riskScore, maxWeight: 0, restWeight: 0, effectiveCap: 100, residualFactor: 1.0 };
    const intents = threat.intents.length > 0 ? threat.intents.join(' + ') : 'General Offset';

    return (
        <div className="space-y-6">
            
            {/* 1. Header / Intent Context */}
            <div className="bg-black/40 border border-white/10 rounded-2xl p-6">
                <div className="flex items-start justify-between">
                    <div>
                        <h3 className="text-lg font-black text-white">{threat.ruleName || 'Heuristic Detection'}</h3>
                        <div className="flex items-center gap-3 mt-2">
                            <span className={`px-2 py-1 rounded text-[10px] font-bold tracking-widest ${threat.riskScore >= 80 ? 'bg-red-500/20 text-red-400' : 'bg-amber-500/20 text-amber-400'}`}>
                                {threat.severityLabel}
                            </span>
                            <span className="text-zinc-500 text-xs flex items-center gap-1">
                                <Target className="w-3.5 h-3.5" /> Intent: <span className="text-zinc-300 font-mono">{intents}</span>
                            </span>
                        </div>
                    </div>
                    <div className="text-right">
                        <p className="text-[10px] uppercase tracking-widest text-zinc-500 font-bold mb-1">Final Score</p>
                        <p className={`text-4xl font-black ${threat.riskScore >= 80 ? 'text-red-400' : 'text-amber-400'}`}>
                            {threat.riskScore}
                        </p>
                    </div>
                </div>
            </div>

            {/* 1.5. Audit Evidence (Governance Trace) */}
            <div className="bg-blue-500/5 border border-blue-500/20 rounded-2xl p-6 relative overflow-hidden">
                <div className="absolute top-0 right-0 w-32 h-32 bg-blue-500/10 blur-[40px] -z-10" />
                <div className="flex items-center gap-3 mb-4">
                    <span className="text-[10px] px-2 py-0.5 rounded font-mono font-bold bg-blue-500/20 text-blue-300 border border-blue-500/30">
                        {threat.ruleId || 'SARB-LEGACY-000'}
                    </span>
                    <h4 className="text-xs font-bold uppercase tracking-widest text-zinc-400">Formal Audit Evidence</h4>
                </div>
                
                <p className="text-sm text-zinc-300 leading-relaxed mb-4">
                    {threat.explanation || 'Legacy rule triggering detected without formal audit explanation.'}
                </p>
                
                {(threat.matchedPatterns && threat.matchedPatterns.length > 0) && (
                     <div className="bg-black/50 border border-blue-500/10 rounded-xl p-3">
                         <p className="text-[10px] text-zinc-500 uppercase tracking-widest font-black mb-2">Matched Signatures:</p>
                         <div className="flex flex-wrap gap-2">
                             {threat.matchedPatterns.map((p, i) => (
                                 <span key={i} className="text-xs font-mono text-zinc-400 bg-white/5 border border-white/5 px-2 py-0.5 rounded">
                                     {p}
                                 </span>
                             ))}
                         </div>
                     </div>
                )}
            </div>

            {/* 2. Attack Trace (Flow) */}
            <div className="bg-white/[0.02] border border-white/[0.05] rounded-2xl p-6">
                <h4 className="text-xs font-bold uppercase tracking-widest text-zinc-400 mb-6 flex items-center gap-2">
                    <Activity className="w-4 h-4 text-blue-400" /> Executive Trace Flow
                </h4>
                
                {(!threat.traceContext || threat.traceContext.length === 0) ? (
                     <div className="text-sm text-zinc-500 italic">No formal trace built for this threat. (Legacy Rule).</div>
                ) : (
                    <div className="space-y-0 relative ml-4">
                        {/* Vertical Connector Line */}
                        <div className="absolute left-[15px] top-4 bottom-8 w-[2px] bg-white/10 z-0" />
                        
                        {threat.traceContext.map((s: any, idx: number) => {
                            let Icon = Activity;
                            let colorClass = "text-white";
                            let bgClass = "bg-zinc-800 border-zinc-700";

                            if (s.type.includes('ACCESS') || s.type.includes('REQUIRE')) {
                                Icon = Layers; colorClass = "text-blue-400"; bgClass = "bg-blue-500/10 border-blue-500/20";
                            }
                            if (s.type.includes('OBFUSCATION') || s.type.includes('POLLUTION') || s.type.includes('BASE64')) {
                                Icon = Cpu; colorClass = "text-amber-400"; bgClass = "bg-amber-500/10 border-amber-500/20";
                            }
                            if (s.type.includes('EXECUTION') || s.type.includes('SINK_CALL') || s.type.includes('SHELL')) {
                                Icon = Zap; colorClass = "text-red-400"; bgClass = "bg-red-500/10 border-red-500/20";
                            }

                            return (
                                <div key={idx} className="relative z-10 flex gap-4 pb-6">
                                    <div className={`w-8 h-8 shrink-0 rounded-full border ${bgClass} flex items-center justify-center mt-1`}>
                                        <Icon className={`w-4 h-4 ${colorClass}`} />
                                    </div>
                                    <div className="bg-black/50 border border-white/5 rounded-xl p-4 flex-1">
                                        <div className="flex items-center justify-between mb-2">
                                            <span className={`text-sm font-bold ${colorClass}`}>{s.type}</span>
                                            <span className="text-[10px] font-mono text-zinc-500 bg-white/5 px-2 py-0.5 rounded">W: {s.weight}</span>
                                        </div>
                                        <div className="text-xs font-mono text-zinc-400 bg-black/60 p-2 rounded whitespace-pre-wrap break-all border border-white/5">
                                            {s.evidence || 'No contextual evidence'}
                                        </div>
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                )}
            </div>

            {/* 3. Logic & Explainability Deck */}
            <div className="bg-white/[0.02] border border-white/[0.05] rounded-2xl p-6">
                <h4 className="text-xs font-bold uppercase tracking-widest text-zinc-400 mb-6 flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-purple-400" /> Logistic Mathematics Breakdown
                </h4>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="bg-black/30 border border-white/5 rounded-xl p-4">
                        <p className="text-[10px] text-zinc-500 font-bold uppercase tracking-widest mb-1">Max Signal Node (Peak)</p>
                        <p className="text-xl font-black text-white">{metrics.maxWeight.toFixed(1)}</p>
                    </div>
                    <div className="bg-black/30 border border-white/5 rounded-xl p-4">
                        <p className="text-[10px] text-zinc-500 font-bold uppercase tracking-widest mb-1">Residual Overlap</p>
                        <p className="text-xl font-black text-white">{metrics.restWeight.toFixed(1)} <span className="text-sm font-normal text-zinc-500">× {(metrics.residualFactor || 1.0).toFixed(2)}</span></p>
                    </div>
                    <div className="bg-black/30 border border-white/5 rounded-xl p-4">
                        <p className="text-[10px] text-zinc-500 font-bold uppercase tracking-widest mb-1">Corporate Noise Cap</p>
                        <p className="text-xl font-black text-white">Math.min({metrics.rawScore.toFixed(0)}, {metrics.effectiveCap.toFixed(0)})</p>
                    </div>
                    <div className="bg-black/30 border border-white/5 rounded-xl p-4">
                        <p className="text-[10px] text-zinc-500 font-bold uppercase tracking-widest mb-1">Logistic Transformed Score</p>
                        <p className="text-xl font-black text-purple-400">{metrics.finalScore.toFixed(2)}</p>
                    </div>
                </div>

                {rec?.isComposite && metrics.finalScore >= 75 && (
                     <div className="mt-4 p-3 bg-red-500/10 border border-red-500/30 rounded-xl text-xs text-red-400 font-medium">
                         🔥 <strong>COMPOSITE ESCALATION:</strong> Multiple distinct suspicious intent layers detected simultaneously. Automatically escalated to CRITICAL to bypass noise filters.
                     </div>
                )}
                
                {!isIsolated && threat.riskScore >= 80 && (
                     <div className="mt-4 p-3 bg-indigo-500/10 border border-indigo-500/30 rounded-xl text-xs text-indigo-400 font-medium">
                         ⚠️ <strong>STATIC ALERT:</strong> Triggered purely on Static AST structure. Consider escalating this package to a Sentinel Sandbox environment for dynamic runtime verification.
                     </div>
                )}

            </div>
        </div>
    );
};
