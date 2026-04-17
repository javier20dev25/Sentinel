import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  History, GitCommit, ShieldCheck, Lock, AlertTriangle, 
  ExternalLink, Search, Filter, Clock, ChevronRight, Globe
} from 'lucide-react';
import { api } from '../lib/api';

interface AuditLog {
  id: number;
  repo_id: number;
  github_full_name: string;
  event_type: 'PUSH' | 'DETECTION' | 'ASSET_TOGGLE' | 'SHIELD_HARDEN';
  description: string;
  target: string;
  commit_hash: string | null;
  created_at: string;
}

export const AuditTrailView: React.FC<{ repoId?: string }> = ({ repoId = 'all' }) => {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    fetchLogs();
    const interval = setInterval(fetchLogs, 10000); // Polling every 10s
    return () => clearInterval(interval);
  }, [repoId]);

  const fetchLogs = async () => {
    try {
      const { data } = await api.get(`/api/audit/logs?repoId=${repoId}`);
      setLogs(data);
    } catch (e) {
      console.error("Failed to fetch audit logs", e);
    } finally {
      setLoading(false);
    }
  };

  const getEventIcon = (type: string) => {
    switch (type) {
      case 'PUSH': return <GitCommit className="w-4 h-4 text-emerald-400" />;
      case 'DETECTION': return <AlertTriangle className="w-4 h-4 text-red-500" />;
      case 'ASSET_TOGGLE': return <Lock className="w-4 h-4 text-amber-500" />;
      case 'SHIELD_HARDEN': return <ShieldCheck className="w-4 h-4 text-blue-400" />;
      default: return <History className="w-4 h-4 text-zinc-400" />;
    }
  };

  const getEventColor = (type: string) => {
    switch (type) {
      case 'PUSH': return 'border-emerald-500/20 bg-emerald-500/5';
      case 'DETECTION': return 'border-red-500/20 bg-red-500/5';
      case 'ASSET_TOGGLE': return 'border-amber-500/20 bg-amber-500/5';
      case 'SHIELD_HARDEN': return 'border-blue-500/20 bg-blue-500/5';
      default: return 'border-white/5 bg-white/2';
    }
  };

  const filteredLogs = logs.filter(log => 
    log.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
    (log.github_full_name && log.github_full_name.toLowerCase().includes(searchTerm.toLowerCase())) ||
    log.event_type.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="space-y-6">
      {/* Header / Stats */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h3 className="text-xl font-black text-white flex items-center gap-3">
            <History className="w-6 h-6 text-blue-400" />
            Audit Trail
          </h3>
          <p className="text-xs text-zinc-500 font-medium">Historial completo de acciones y trazabilidad de seguridad</p>
        </div>

        <div className="flex items-center gap-3">
          <div className="relative group">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500 group-focus-within:text-blue-400 transition-colors" />
            <input 
              type="text"
              placeholder="Buscar acciones..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-white/5 border border-white/10 rounded-xl py-2.5 pl-10 pr-4 text-sm outline-none focus:border-blue-500/50 focus:ring-4 focus:ring-blue-500/10 transition-all w-64 text-white"
            />
          </div>
        </div>
      </div>

      {/* Timeline */}
      <div className="relative">
        {/* Timeline line */}
        <div className="absolute left-6 top-0 bottom-0 w-px bg-gradient-to-b from-blue-500/50 via-zinc-800 to-transparent ml-[-0.5px]" />

        <div className="space-y-6 relative">
          <AnimatePresence mode="popLayout">
            {loading ? (
              [1, 2, 3].map(i => (
                <div key={i} className="ml-14 glass p-6 rounded-2xl border border-white/5 animate-pulse">
                  <div className="h-4 bg-white/10 rounded w-1/4 mb-4" />
                  <div className="h-3 bg-white/5 rounded w-1/2" />
                </div>
              ))
            ) : filteredLogs.length === 0 ? (
              <div className="ml-14 p-12 text-center glass rounded-[32px] border border-dashed border-white/10">
                <History className="w-12 h-12 text-zinc-700 mx-auto mb-4" />
                <p className="text-zinc-500 font-bold">No se han registrado acciones aún.</p>
              </div>
            ) : (
              filteredLogs.map((log) => (
                <motion.div
                  key={log.id}
                  layout
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, scale: 0.95 }}
                  className="relative ml-14"
                >
                  {/* Event Point */}
                  <div className={`absolute -left-14 top-6 w-10 h-10 rounded-xl flex items-center justify-center border shadow-lg ${getEventColor(log.event_type)}`}>
                    {getEventIcon(log.event_type)}
                  </div>

                  {/* Card */}
                  <div className={`glass p-5 rounded-[22px] border transition-all hover:translate-x-1 ${getEventColor(log.event_type)}`}>
                    <div className="flex items-start justify-between gap-4">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2 mb-1">
                          <span className="text-[10px] font-black uppercase tracking-widest text-zinc-500">
                            {new Date(log.created_at).toLocaleTimeString()} · {new Date(log.created_at).toLocaleDateString()}
                          </span>
                          <span className="text-[10px] text-zinc-700 font-bold">•</span>
                          <span className="text-[10px] font-black text-blue-400 uppercase tracking-tighter">
                            {log.github_full_name || 'System'}
                          </span>
                        </div>
                        <h4 className="text-sm font-bold text-white tracking-tight leading-relaxed">
                          {log.description}
                        </h4>
                        {log.target && (
                          <div className="flex items-center gap-1.5 text-xs text-zinc-500 font-mono mt-2 italic">
                             <Globe className="w-3 h-3" />
                             {log.target}
                          </div>
                        )}
                      </div>

                      {log.commit_hash && (
                        <a 
                          href={`https://github.com/${log.github_full_name}/commit/${log.commit_hash}`}
                          target="_blank"
                          rel="noreferrer"
                          className="flex items-center gap-2 px-3 py-2 rounded-xl bg-white/5 border border-white/10 text-[10px] font-black text-zinc-400 hover:text-white hover:bg-emerald-500/20 hover:border-emerald-500/30 transition-all group shrink-0"
                        >
                          <GitCommit className="w-3 h-3" />
                          {log.commit_hash.substring(0, 7).toUpperCase()}
                          <ExternalLink className="w-3 h-3 group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-transform" />
                        </a>
                      )}
                    </div>
                  </div>
                </motion.div>
              ))
            )}
          </AnimatePresence>
        </div>
      </div>
    </div>
  );
};
