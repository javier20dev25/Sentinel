import React, { useMemo } from 'react';
import { ShieldCheck, ShieldAlert, Activity, AlertTriangle } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { NormalizedReportModel } from './SentinelNormalizer';

export const PostureOverview: React.FC<{ data: NormalizedReportModel }> = ({ data }) => {
    
    // Calculate Stats from Normalized Layer
    const stats = useMemo(() => {
        const criticalCount = data.findings.filter(t => t.riskScore >= 80).length;
        const highCount = data.findings.filter(t => t.riskScore >= 65 && t.riskScore < 80).length;
        const mediumCount = data.findings.filter(t => t.riskScore >= 40 && t.riskScore < 65).length;
        
        // Distribution for Recharts
        const riskDist = [
            { name: 'Critical', value: criticalCount, color: '#ef4444' },
            { name: 'High', value: highCount, color: '#f59e0b' },
            { name: 'Medium', value: mediumCount, color: '#3b82f6' }
        ];

        // Intent Distribution Context
        const intentMap = new Map();
        data.findings.forEach(t => {
             const signature = t.intents;
             if (signature && signature.length > 0) {
                 signature.forEach(sig => {
                     intentMap.set(sig, (intentMap.get(sig) || 0) + 1);
                 });
             } else {
                 intentMap.set('General', (intentMap.get('General') || 0) + 1);
             }
        });

        const intentDist = Array.from(intentMap.entries())
            .map(([name, value]) => ({ name, value }))
            .sort((a, b) => b.value - a.value);

        return { criticalCount, riskDist, intentDist };
    }, [data.findings]);

    const isSecureContext = data.meta.executionScope === 'none';

    return (
        <div className="space-y-6">
            {/* Context Badge Row (Trust Layer) */}
            <div className={`p-4 rounded-2xl border flex items-center justify-between shadow-xl ${isSecureContext ? 'bg-amber-500/10 border-amber-500/20' : 'bg-red-500/10 border-red-500/20'}`}>
                <div className="flex items-center gap-4">
                    <div className={`w-12 h-12 rounded-xl flex items-center justify-center shrink-0 ${isSecureContext ? 'bg-amber-500/20' : 'bg-red-500/20'}`}>
                        {isSecureContext ? <ShieldCheck className="w-6 h-6 text-amber-500" /> : <ShieldAlert className="w-6 h-6 text-red-500" />}
                    </div>
                    <div>
                        <h3 className={`text-sm font-black uppercase tracking-widest flex items-center gap-2 ${isSecureContext ? 'text-amber-500' : 'text-red-500'}`}>
                            {isSecureContext ? '🟡 Medium Trust' : '🔴 High Trust'} 
                            <span className="text-[10px] bg-white/10 px-2 py-0.5 rounded text-white font-mono lowercase">
                                ({data.summary.confidence_score}%)
                            </span>
                        </h3>
                        <p className={`text-xs mt-1 ${isSecureContext ? 'text-amber-200/60' : 'text-red-200/60'}`}>
                            {isSecureContext 
                                ? 'Static analysis only. No sandbox runtime verification occurred. Potential false positives.' 
                                : 'Behavior confirmed in isolation. Danger verified by sandbox engine.'}
                        </p>
                    </div>
                </div>
                <div className="hidden sm:block text-right">
                    <p className="text-[10px] text-zinc-500 font-mono tracking-widest uppercase">Sentinel Source</p>
                    <p className="text-sm font-bold text-white capitalize">{data.meta.source}</p>
                </div>
            </div>

            {/* Quick Metrics */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="bg-white/[0.02] border border-white/[0.05] rounded-2xl p-6">
                    <p className="text-xs text-zinc-500 font-bold uppercase tracking-widest mb-2">Total Files Checked</p>
                    <p className="text-3xl font-black text-white">{data.summary.filesScanned}</p>
                </div>
                <div className="bg-white/[0.02] border border-white/[0.05] rounded-2xl p-6 relative overflow-hidden">
                    {stats.criticalCount > 0 && <div className="absolute top-0 right-0 w-32 h-32 bg-red-500/20 blur-[50px] -z-10" />}
                    <p className="text-xs text-zinc-500 font-bold uppercase tracking-widest mb-2 flex items-center gap-2">
                        Critical Findings {stats.criticalCount > 0 && <AlertTriangle className="w-3.5 h-3.5 text-red-400" />}
                    </p>
                    <p className={`text-3xl font-black ${stats.criticalCount > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                        {stats.criticalCount}
                    </p>
                </div>
                <div className="bg-white/[0.02] border border-white/[0.05] rounded-2xl p-6">
                    <p className="text-xs text-zinc-500 font-bold uppercase tracking-widest mb-2">Avg Risk Score</p>
                    <p className="text-3xl font-black text-white">{data.summary.averageRisk}<span className="text-base text-zinc-600">/100</span></p>
                </div>
            </div>

            {/* Charts Row */}
            {data.summary.threatsCount > 0 && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div className="bg-white/[0.02] border border-white/[0.05] rounded-2xl p-6">
                        <h4 className="text-xs font-bold uppercase tracking-widest text-zinc-400 mb-6">Risk Distribution</h4>
                        <div className="h-48 w-full">
                            <ResponsiveContainer width="100%" height="100%">
                                <BarChart data={stats.riskDist} layout="vertical" margin={{ top: 0, right: 30, left: 0, bottom: 0 }}>
                                    <XAxis type="number" hide />
                                    <YAxis dataKey="name" type="category" axisLine={false} tickLine={false} tick={{ fill: '#a1a1aa', fontSize: 12, fontWeight: 700 }} width={80} />
                                    <Tooltip cursor={{ fill: 'rgba(255,255,255,0.02)' }} contentStyle={{ backgroundColor: '#18181b', borderColor: '#27272a', borderRadius: '12px' }} />
                                    <Bar dataKey="value" radius={[0, 4, 4, 0]} barSize={20}>
                                        {stats.riskDist.map((entry, index) => <Cell key={`cell-${index}`} fill={entry.color} />)}
                                    </Bar>
                                </BarChart>
                            </ResponsiveContainer>
                        </div>
                    </div>

                    <div className="bg-white/[0.02] border border-white/[0.05] rounded-2xl p-6">
                        <h4 className="text-xs font-bold uppercase tracking-widest text-zinc-400 mb-6">Intent Mapping</h4>
                        <div className="h-48 w-full">
                            <ResponsiveContainer width="100%" height="100%">
                                <BarChart data={stats.intentDist} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
                                    <XAxis dataKey="name" axisLine={false} tickLine={false} tick={{ fill: '#a1a1aa', fontSize: 10, fontWeight: 700 }} />
                                    <YAxis hide />
                                    <Tooltip cursor={{ fill: 'rgba(255,255,255,0.02)' }} contentStyle={{ backgroundColor: '#18181b', borderColor: '#27272a', borderRadius: '12px' }} />
                                    <Bar dataKey="value" fill="#818cf8" radius={[4, 4, 0, 0]} barSize={32} />
                                </BarChart>
                            </ResponsiveContainer>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};
