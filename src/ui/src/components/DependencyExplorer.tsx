import React, { useState, useRef } from 'react';
import {
    AlertTriangle, CheckCircle, Upload, ChevronDown,
    ChevronUp, Package, Lock, Settings, Layers, Activity
} from 'lucide-react';
import { api } from '../lib/api';

// ── Types ────────────────────────────────────────────────────────────────────

interface DepAlert {
    type: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
    riskLevel: number;
    message: string;
    evidence?: string;
    package?: string;
    depth?: number;
    recommendation?: string;
}

interface ScanResult {
    filename: string;
    alertCount: number;
    alerts: DepAlert[];
    maxDepth?: number;
}

type ScanMode = 'lockfile' | 'config' | 'transitive';

// ── Helpers ──────────────────────────────────────────────────────────────────

const SEVERITY_STYLES: Record<string, string> = {
    CRITICAL: 'text-red-400 bg-red-500/10 border-red-500/30',
    HIGH:     'text-orange-400 bg-orange-500/10 border-orange-500/30',
    MEDIUM:   'text-yellow-400 bg-yellow-500/10 border-yellow-500/30',
    LOW:      'text-sky-400 bg-sky-500/10 border-sky-500/30',
    INFO:     'text-slate-400 bg-slate-500/10 border-slate-500/30',
};

const RISK_BAR_COLOR = (level: number) => {
    if (level >= 8) return 'bg-red-500';
    if (level >= 5) return 'bg-orange-400';
    return 'bg-yellow-400';
};

function RiskBar({ level }: { level: number }) {
    return (
        <div className="flex items-center gap-2 mt-1">
            <div className="flex-1 h-1 bg-slate-800 rounded-full overflow-hidden">
                <div
                    className={`h-full rounded-full transition-all duration-500 ${RISK_BAR_COLOR(level)}`}
                    style={{ width: `${(level / 10) * 100}%` }}
                />
            </div>
            <span className="text-[10px] font-black text-slate-400">{level}/10</span>
        </div>
    );
}

// ── Alert Card ────────────────────────────────────────────────────────────────

function AlertCard({ alert }: { alert: DepAlert }) {
    const [open, setOpen] = useState(false);
    const style = SEVERITY_STYLES[alert.severity] || SEVERITY_STYLES.INFO;

    return (
        <div className={`rounded-xl border p-3 transition-all duration-200 ${style}`}>
            <div className="flex items-start justify-between gap-3 cursor-pointer" onClick={() => setOpen(v => !v)}>
                <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                        <span className={`text-[9px] font-black uppercase tracking-widest px-1.5 py-0.5 rounded border ${style}`}>
                            {alert.severity}
                        </span>
                        {alert.package && (
                            <span className="text-[10px] font-mono text-slate-300 bg-slate-800/60 px-2 py-0.5 rounded">
                                {alert.package}
                                {alert.depth !== undefined && ` (depth ${alert.depth})`}
                            </span>
                        )}
                        <span className="text-[10px] text-slate-500 font-mono">{alert.type}</span>
                    </div>
                    <p className="text-xs text-slate-200 mt-1.5 leading-relaxed">{alert.message}</p>
                    <RiskBar level={alert.riskLevel} />
                </div>
                <button className="shrink-0 mt-1 text-slate-500">
                    {open ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                </button>
            </div>

            {open && (alert.evidence || alert.recommendation) && (
                <div className="mt-3 space-y-2 border-t border-white/5 pt-3">
                    {alert.evidence && (
                        <div>
                            <p className="text-[9px] uppercase tracking-wider text-slate-500 font-bold mb-1">Evidencia</p>
                            <pre className="text-[10px] font-mono bg-black/40 p-2 rounded border border-slate-800 text-slate-400 overflow-x-auto whitespace-pre-wrap break-all">
                                {alert.evidence}
                            </pre>
                        </div>
                    )}
                    {alert.recommendation && (
                        <div className="flex items-start gap-2 bg-emerald-500/5 border border-emerald-500/20 rounded p-2">
                            <CheckCircle className="w-3 h-3 text-emerald-400 shrink-0 mt-0.5" />
                            <p className="text-[11px] text-emerald-300">{alert.recommendation}</p>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}

// ── Main Component ────────────────────────────────────────────────────────────

export const DependencyExplorer: React.FC = () => {
    const [mode, setMode] = useState<ScanMode>('lockfile');
    const [result, setResult] = useState<ScanResult | null>(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const fileInputRef = useRef<HTMLInputElement>(null);

    const MODES: { id: ScanMode; label: string; icon: React.ElementType; desc: string }[] = [
        {
            id: 'lockfile',
            label: 'Lockfile Scanner',
            icon: Lock,
            desc: 'Detecta registry poisoning, phantom deps y hashes faltantes en package-lock.json'
        },
        {
            id: 'transitive',
            label: 'Análisis Transitivo',
            icon: Layers,
            desc: 'Escanea el árbol completo de sub-dependencias (cierra el vector del ataque Axios 2026)'
        },
        {
            id: 'config',
            label: 'Config Integrity',
            icon: Settings,
            desc: 'Verifica .npmrc y .yarnrc por registry overrides, proxies injectados y tokens hardcodeados'
        },
    ];

    const handleFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
        const file = e.target.files?.[0];
        if (!file) return;
        setLoading(true);
        setError('');
        setResult(null);

        try {
            const content = await file.text();
            let response;

            if (mode === 'lockfile') {
                response = await api.post('/api/supply/scan-lockfile', {
                    content,
                    filename: file.name
                });
            } else if (mode === 'transitive') {
                response = await api.post('/api/supply/scan-transitive', {
                    lockfileContent: content
                });
                // Normalise to common shape
                response.data = { filename: file.name, ...response.data };
            } else {
                response = await api.post('/api/supply/scan-config', {
                    content,
                    filename: file.name
                });
            }

            setResult(response.data);
        } catch (err: any) {
            setError(err.response?.data?.error || err.message || 'Error desconocido');
        } finally {
            setLoading(false);
            // Reset so the same file can be re-dropped
            if (fileInputRef.current) fileInputRef.current.value = '';
        }
    };

    const criticalCount = result?.alerts.filter(a => a.severity === 'CRITICAL').length ?? 0;
    const highCount     = result?.alerts.filter(a => a.severity === 'HIGH').length ?? 0;

    return (
        <div className="p-6 space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">

            {/* Header */}
            <div>
                <h1 className="text-2xl font-bold text-white flex items-center gap-2">
                    <Package className="w-6 h-6 text-violet-400" />
                    Dependency Explorer
                </h1>
                <p className="text-slate-400 text-sm mt-1">
                    Análisis profundo de dependencias: lockfiles, registros, sub-dependencias y configuración.
                </p>
            </div>

            {/* Mode Selector */}
            <div className="grid grid-cols-3 gap-3">
                {MODES.map(m => (
                    <button
                        key={m.id}
                        onClick={() => { setMode(m.id); setResult(null); setError(''); }}
                        className={`p-4 rounded-xl border text-left transition-all duration-200 ${
                            mode === m.id
                                ? 'border-violet-500/40 bg-violet-500/10 ring-1 ring-violet-500/20'
                                : 'border-slate-800 bg-slate-900/50 hover:border-slate-700'
                        }`}
                    >
                        <m.icon className={`w-5 h-5 mb-2 ${mode === m.id ? 'text-violet-400' : 'text-slate-500'}`} />
                        <p className={`text-sm font-semibold ${mode === m.id ? 'text-white' : 'text-slate-300'}`}>
                            {m.label}
                        </p>
                        <p className="text-[11px] text-slate-500 mt-1 leading-snug">{m.desc}</p>
                    </button>
                ))}
            </div>

            {/* Drop Zone */}
            <label
                className="block border-2 border-dashed border-slate-700 hover:border-violet-500/50 rounded-2xl p-10
                           text-center cursor-pointer transition-all duration-300 bg-slate-900/30 hover:bg-violet-500/5 group"
            >
                <input
                    ref={fileInputRef}
                    type="file"
                    className="hidden"
                    accept=".json,.yaml,.yml,.npmrc,.yarnrc,.lock"
                    onChange={handleFile}
                />
                <Upload className="w-10 h-10 mx-auto mb-3 text-slate-600 group-hover:text-violet-400 transition-colors" />
                <p className="text-slate-300 font-semibold">
                    {mode === 'lockfile' && 'Arrastra tu package-lock.json o pnpm-lock.yaml'}
                    {mode === 'transitive' && 'Arrastra tu package-lock.json'}
                    {mode === 'config' && 'Arrastra tu .npmrc, .yarnrc o .yarnrc.yml'}
                </p>
                <p className="text-slate-600 text-xs mt-1">o haz click para seleccionar</p>
            </label>

            {/* Loading */}
            {loading && (
                <div className="flex items-center gap-3 p-4 bg-violet-500/5 border border-violet-500/20 rounded-xl">
                    <div className="w-4 h-4 border-2 border-violet-400 border-t-transparent rounded-full animate-spin" />
                    <p className="text-violet-300 text-sm">Analizando...</p>
                </div>
            )}

            {/* Error */}
            {error && (
                <div className="flex items-center gap-3 p-4 bg-red-500/10 border border-red-500/20 rounded-xl">
                    <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
                    <p className="text-red-300 text-sm">{error}</p>
                </div>
            )}

            {/* Results */}
            {result && (
                <div className="space-y-4">
                    {/* Summary Bar */}
                    <div className="grid grid-cols-4 gap-3">
                        {[
                            { label: 'Total Alertas', value: result.alertCount, color: 'text-white' },
                            { label: 'Críticas',       value: criticalCount,       color: 'text-red-400' },
                            { label: 'Altas',          value: highCount,           color: 'text-orange-400' },
                            { label: 'Prof. máx.',     value: result.maxDepth ?? '—', color: 'text-violet-400' },
                        ].map(s => (
                            <div key={s.label} className="bg-slate-900/60 border border-slate-800 rounded-xl p-3 text-center">
                                <p className={`text-2xl font-black ${s.color}`}>{s.value}</p>
                                <p className="text-[10px] text-slate-500 uppercase tracking-wider mt-0.5">{s.label}</p>
                            </div>
                        ))}
                    </div>

                    {/* Clean State */}
                    {result.alertCount === 0 && (
                        <div className="p-8 rounded-xl border border-emerald-500/20 bg-emerald-500/5 text-center">
                            <CheckCircle className="w-10 h-10 text-emerald-400 mx-auto mb-3" />
                            <p className="text-emerald-300 font-semibold">No se detectaron amenazas</p>
                            <p className="text-slate-500 text-xs mt-1">
                                {result.filename} pasó todos los controles de integridad.
                            </p>
                        </div>
                    )}

                    {/* Alert List */}
                    {result.alerts.length > 0 && (
                        <div className="space-y-2">
                            <div className="flex items-center gap-2 mb-3">
                                <Activity className="w-4 h-4 text-slate-400" />
                                <h3 className="text-sm font-bold text-slate-300">
                                    Amenazas detectadas en <span className="font-mono text-violet-400">{result.filename}</span>
                                </h3>
                            </div>
                            {result.alerts
                                .sort((a, b) => b.riskLevel - a.riskLevel)
                                .map((alert, i) => (
                                    <AlertCard key={i} alert={alert} />
                                ))}
                        </div>
                    )}
                </div>
            )}
        </div>
    );
};
