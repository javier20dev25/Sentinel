import React, { useMemo } from 'react';
import { Target, ArrowRight } from 'lucide-react';
import { NormalizedFinding } from './SentinelNormalizer';

export const SemanticFindings: React.FC<{ alerts: NormalizedFinding[], onSelectThreat: (threat: NormalizedFinding) => void }> = ({ alerts, onSelectThreat }) => {
    
    const groupedAlerts = useMemo(() => {
        const groups: Record<string, NormalizedFinding[]> = {
            'CRITICAL_INTENT': [],
            'HIGH_INTENT': [],
            'SUSPICIOUS': []
        };

        alerts.forEach(a => {
            const isCritical = a.riskScore >= 80;
            const isHigh = a.riskScore >= 65 && a.riskScore < 80;
            
            if (isCritical) groups['CRITICAL_INTENT'].push(a);
            else if (isHigh) groups['HIGH_INTENT'].push(a);
            else groups['SUSPICIOUS'].push(a);
        });

        Object.keys(groups).forEach(key => {
            groups[key].sort((a, b) => b.riskScore - a.riskScore);
        });

        return groups;
    }, [alerts]);

    if (alerts.length === 0) {
        return (
            <div className="p-8 text-center bg-white/[0.02] border border-white/[0.05] rounded-2xl">
                <p className="text-zinc-500 font-bold">✅ No threats detected in this scan.</p>
            </div>
        );
    }

    const renderGroup = (title: string, group: NormalizedFinding[], emptyMsg: string, dotColor: string) => {
        if (group.length === 0) return null;
        
        return (
            <div className="mb-8">
                <h4 className="text-sm font-black text-white mb-4 flex items-center gap-2">
                    <span className={`w-2 h-2 rounded-full ${dotColor}`} />
                    {title} <span className="text-zinc-500 font-medium">({group.length})</span>
                </h4>
                <div className="space-y-3">
                    {group.map((threat) => {
                        const intents = threat.intents.length > 0 ? threat.intents.join(' + ') : 'General Threat';
                        
                        return (
                            <button 
                                key={threat.id}
                                onClick={() => onSelectThreat(threat)}
                                className="w-full text-left bg-black/40 hover:bg-white/5 border border-white/5 hover:border-white/10 rounded-xl p-4 transition-all group flex flex-col sm:flex-row sm:items-center justify-between gap-4"
                            >
                                <div>
                                    <h5 className="font-bold text-zinc-200 group-hover:text-blue-400 transition-colors">
                                        {threat.targetName}
                                    </h5>
                                    <div className="flex items-center gap-2 mt-2">
                                        <Target className="w-3.5 h-3.5 text-zinc-500" />
                                        <span className="text-xs font-mono text-zinc-400">{intents}</span>
                                    </div>
                                </div>
                                <div className="flex items-center gap-4 shrink-0">
                                    <div className="text-right">
                                        <p className="text-[10px] uppercase tracking-widest text-zinc-500 font-bold">Score</p>
                                        <p className={`text-base font-black ${threat.riskScore >= 80 ? 'text-red-400' : threat.riskScore >= 65 ? 'text-amber-400' : 'text-blue-400'}`}>
                                            {threat.riskScore}
                                        </p>
                                    </div>
                                    <div className="w-8 h-8 rounded-full bg-white/5 flex items-center justify-center group-hover:bg-blue-500/20 group-hover:text-blue-400 transition-colors">
                                        <ArrowRight className="w-4 h-4" />
                                    </div>
                                </div>
                            </button>
                        );
                    })}
                </div>
            </div>
        );
    };

    return (
        <div>
            {renderGroup('CRITICAL (Active Exploitation Potential)', groupedAlerts['CRITICAL_INTENT'], 'No critical threats.', 'bg-red-500')}
            {renderGroup('HIGH (Suspicious Behaviors)', groupedAlerts['HIGH_INTENT'], 'No high behavior threats.', 'bg-amber-500')}
            {renderGroup('WARNING (Anomalies)', groupedAlerts['SUSPICIOUS'], '', 'bg-blue-500')}
        </div>
    );
};
