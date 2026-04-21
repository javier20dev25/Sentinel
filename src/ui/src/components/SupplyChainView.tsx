import React, { useState, useEffect } from 'react';
import { Shield, AlertTriangle, User, ExternalLink, Terminal, ChevronDown, ChevronUp } from 'lucide-react';
import { RiskGauge } from './RiskGauge';
import { api } from '../lib/api';

interface SupplyChainAlert {
  script: string;
  type: string;
  message: string;
  evidence: string;
  riskLevel: number;
  severity: string;
  author: string;
}

interface ScanLog {
  id: number;
  repo_id: number;
  event_type: string;
  risk_level: number;
  description: string;
  evidence_metadata: string; // JSON string of Alert[]
  created_at: string;
  pinned: boolean;
}

export const SupplyChainView: React.FC = () => {
  const [logs, setLogs] = useState<ScanLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedLog, setExpandedLog] = useState<number | null>(null);

  useEffect(() => {
    fetchLogs();
  }, []);

  const fetchLogs = async () => {
    try {
      // Using shared API layer for consistency
      const { data: response } = await api.get('/api/audit/logs?repoId=all');
      const supplyLogs = response.filter((l: ScanLog) => 
        l.event_type.includes('SUPPLY_CHAIN') || l.description.includes('Risk Matrix')
      );
      setLogs(supplyLogs);
    } catch (err) {
      console.error('Failed to fetch supply chain logs:', err);
    } finally {
      setLoading(false);
    }
  };

  const parseEvidence = (json: string): SupplyChainAlert[] => {
    try {
      return JSON.parse(json);
    } catch {
      return [];
    }
  };

  const getRiskColor = (level: number) => {
    if (level >= 8) return 'text-red-500 bg-red-500/10 border-red-500/20';
    if (level >= 5) return 'text-orange-500 bg-orange-500/10 border-orange-500/20';
    return 'text-yellow-500 bg-yellow-500/10 border-yellow-500/20';
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-500"></div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="md:col-span-2">
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Shield className="w-6 h-6 text-indigo-400" />
            Supply Chain Shield
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            Hybrid Sandbox analysis of life-cycle scripts, unpinned dependencies, and typosquatting vectors.
          </p>
        </div>
        
        {logs.length > 0 && (
          <div className="bg-white/[0.03] border border-white/10 rounded-3xl p-6 flex flex-col items-center justify-center">
            <RiskGauge 
              score={Math.round(logs.reduce((acc, curr) => acc + curr.risk_level * 10, 0) / logs.length)} 
              size={140}
              label="Fleet Risk"
            />
          </div>
        )}
      </div>

      {logs.length === 0 ? (
        <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-12 text-center">
          <Shield className="w-12 h-12 text-slate-700 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-slate-300">No se detectaron amenazas</h3>
          <p className="text-slate-500 mt-2">Tu cadena de suministro parece estar limpia.</p>
        </div>
      ) : (
        <div className="grid gap-4">
          {logs.map((log) => {
            const alerts = parseEvidence(log.evidence_metadata);
            const isExpanded = expandedLog === log.id;

            return (
              <div 
                key={log.id} 
                className={`bg-slate-900/80 border rounded-xl overflow-hidden transition-all duration-300 ${
                  isExpanded ? 'border-indigo-500/50 ring-1 ring-indigo-500/20' : 'border-slate-800 hover:border-slate-700'
                }`}
              >
                <div 
                  className="p-4 cursor-pointer flex items-center justify-between"
                  onClick={() => setExpandedLog(isExpanded ? null : log.id)}
                >
                  <div className="flex items-center gap-4">
                    <div className={`px-2 py-1 rounded border text-xs font-bold ${getRiskColor(log.risk_level)}`}>
                      RIESGO {log.risk_level}/10
                    </div>
                    <div>
                      <h3 className="text-white font-medium">{log.description}</h3>
                      <div className="flex items-center gap-3 mt-1 text-xs text-slate-400">
                        <span className="flex items-center gap-1">
                          <User className="w-3 h-3" />
                          {alerts[0]?.author || 'Unknown'}
                        </span>
                        <span>•</span>
                        <span>{new Date(log.created_at).toLocaleString()}</span>
                      </div>
                    </div>
                  </div>
                  {isExpanded ? <ChevronUp className="w-5 h-5 text-slate-500" /> : <ChevronDown className="w-5 h-5 text-slate-500" />}
                </div>

                {isExpanded && (
                  <div className="px-4 pb-4 border-t border-slate-800/50 bg-slate-950/30">
                    <div className="mt-4 space-y-4">
                      {alerts.map((alert, i) => (
                        <div key={i} className="p-4 bg-slate-900/50 rounded-lg border border-slate-800">
                          <div className="flex items-start justify-between">
                            <div className="flex items-center gap-2 text-indigo-400 font-mono text-sm">
                              <Terminal className="w-4 h-4" />
                              {alert.script}
                            </div>
                            <span className="text-[10px] px-2 py-0.5 bg-slate-800 text-slate-400 rounded uppercase">
                              {alert.type}
                            </span>
                          </div>
                          
                          <p className="text-slate-300 mt-2 text-sm">{alert.message}</p>
                          
                          <div className="mt-3">
                            <h4 className="text-[10px] uppercase tracking-wider text-slate-500 font-bold mb-1">Evidencia Técnica</h4>
                            <pre className="text-xs bg-black/40 p-3 rounded border border-slate-800 text-slate-400 overflow-x-auto font-mono">
                              {alert.evidence}
                            </pre>
                          </div>

                          <div className="mt-4 flex gap-2">
                            <button className="text-xs px-3 py-1.5 bg-red-500/10 text-red-500 border border-red-500/20 rounded hover:bg-red-500/20 transition-colors">
                              Bloquear Merge
                            </button>
                            <button className="text-xs px-3 py-1.5 bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 rounded hover:bg-indigo-500/20 transition-colors">
                              Forzar --ignore-scripts
                            </button>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
