import React, { useState, useEffect } from 'react';
import { api } from '../lib/api';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Shield, Zap, Terminal, AlertTriangle, CheckCircle, 
  Settings, Loader2, Play, Lock as LockIcon, Globe, Database
} from 'lucide-react';

interface ProjectShieldViewProps {
  repoId: string;
}

const ProjectShieldView: React.FC<ProjectShieldViewProps> = ({ repoId }) => {
  const [loading, setLoading] = useState(false);
  const [logs, setLogs] = useState<string[]>([]);
  const [threats, setThreats] = useState<any[]>([]);
  const [hardenStatus, setHardenStatus] = useState<'idle' | 'success' | 'error'>('idle');

  useEffect(() => {
    if (repoId === 'all') return;
    
    const eventSource = new EventSource(`http://localhost:3001/api/ui/stream`);
    eventSource.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.action === 'shield-log' && data.repoId === parseInt(repoId)) {
        setLogs(prev => [...prev, data.message]);
      }
    };
    return () => eventSource.close();
  }, [repoId]);

  const handleHarden = async () => {
    setHardenStatus('idle');
    try {
      await api.post('/api/shield/harden', { repoId });
      setHardenStatus('success');
    } catch (e) {
      setHardenStatus('error');
    }
  };

  const handleSafeInstall = async () => {
    setLoading(true);
    setLogs(['[SENTINEL] Starting Safe Install sequence...']);
    setThreats([]);
    try {
      const { data } = await api.post('/api/shield/safe-install', { repoId });
      setThreats(data.threats || []);
      setLogs(prev => [...prev, `[DONE] Installation and AST Scan complete.`]);
    } catch (e) {
      setLogs(prev => [...prev, `[CRITICAL ERROR] Secure installation aborted.`]);
    } finally {
      setLoading(false);
    }
  };

  if (repoId === 'all') {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-center">
        <Shield className="w-16 h-16 text-zinc-800 mb-6" />
        <h3 className="text-xl font-bold text-white mb-2">Project Shield Command Center</h3>
        <p className="text-sm text-zinc-500 max-w-sm">Select a specific repository from the dropdown above to initialize proactive defense protocols.</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Hardening Toggle */}
        <motion.div 
          className="glass rounded-3xl border border-white/5 p-6 flex flex-col justify-between"
          whileHover={{ borderColor: 'rgba(59, 130, 246, 0.3)' }}
        >
          <div className="flex items-start justify-between mb-4">
            <div className="w-12 h-12 rounded-2xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center">
              <LockIcon className="w-6 h-6 text-blue-400" />
            </div>
            {hardenStatus === 'success' && (
              <div className="px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-[10px] font-black uppercase tracking-widest flex items-center gap-1.5">
                <CheckCircle className="w-3 h-3" />
                Hardened
              </div>
            )}
          </div>
          <div>
            <h3 className="text-lg font-bold text-white mb-1">Environment Hardening</h3>
            <p className="text-xs text-zinc-500 mb-6 leading-relaxed">
              Injects secure `.npmrc` policies (ignore-scripts, save-exact) and validates `package.json` engine requirements.
            </p>
            <button 
              onClick={handleHarden}
              className="w-full py-3 rounded-2xl bg-blue-500 text-white text-sm font-bold hover:bg-blue-400 transition-all flex items-center justify-center gap-2"
            >
              <Zap className="w-4 h-4" />
              Apply Security Policies
            </button>
          </div>
        </motion.div>

        {/* Safe Install */}
        <motion.div 
          className="glass rounded-3xl border border-white/5 p-6 flex flex-col justify-between"
          whileHover={{ borderColor: 'rgba(168, 85, 247, 0.3)' }}
        >
          <div className="flex items-start justify-between mb-4">
            <div className="w-12 h-12 rounded-2xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center">
              <Globe className="w-6 h-6 text-purple-400" />
            </div>
            {loading && (
              <div className="px-3 py-1 rounded-full bg-purple-500/10 border border-purple-500/20 text-purple-400 text-[10px] font-black uppercase tracking-widest flex items-center gap-1.5 animate-pulse">
                <Loader2 className="w-3 h-3 animate-spin" />
                Intercepting
              </div>
            )}
          </div>
          <div>
            <h3 className="text-lg font-bold text-white mb-1">Safe Package Install</h3>
            <p className="text-xs text-zinc-500 mb-6 leading-relaxed">
              Downloads dependencies with scripts disabled and performs a deep AST scan for structural malware after extraction.
            </p>
            <button 
              onClick={handleSafeInstall}
              disabled={loading}
              className="w-full py-3 rounded-2xl bg-white/5 border border-white/10 text-white text-sm font-bold hover:bg-white/10 transition-all flex items-center justify-center gap-2 disabled:opacity-50"
            >
              <Play className="w-4 h-4" />
              Run Secure npm install
            </button>
          </div>
        </motion.div>
      </div>

      {/* Terminal & Results */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Terminal Log */}
        <div className="lg:col-span-2 glass rounded-3xl border border-white/5 overflow-hidden flex flex-col h-[400px]">
          <div className="px-5 py-3 border-b border-white/5 flex items-center gap-2 bg-white/[0.02]">
            <Terminal className="w-4 h-4 text-zinc-500" />
            <span className="text-[11px] font-bold text-zinc-500 uppercase tracking-widest">Secure Installation Console</span>
          </div>
          <div className="flex-1 p-5 overflow-y-auto font-mono text-[11px] space-y-1.5 bg-black/40">
            {logs.length === 0 && <span className="text-zinc-700 italic">Console idle. Awaiting user action...</span>}
            {logs.map((log, i) => (
              <div key={i} className={`${log.includes('CRITICAL') ? 'text-red-400' : log.includes('OK') ? 'text-emerald-400' : 'text-zinc-400'}`}>
                {log}
              </div>
            ))}
          </div>
        </div>

        {/* Scan Results Sidebar */}
        <div className="glass rounded-3xl border border-white/5 flex flex-col h-[400px]">
          <div className="px-5 py-3 border-b border-white/5 bg-white/[0.02]">
            <span className="text-[11px] font-bold text-zinc-500 uppercase tracking-widest">AST Threat Summary</span>
          </div>
          <div className="flex-1 p-4 overflow-y-auto space-y-3">
            {threats.length === 0 && !loading && (
              <div className="h-full flex flex-col items-center justify-center text-center opacity-30">
                <CheckCircle className="w-10 h-10 mb-3" />
                <p className="text-xs font-bold font-mono">NO THREATS DETECTED</p>
              </div>
            )}
            
            <AnimatePresence>
              {threats.map((threat, i) => (
                <motion.div 
                  key={i}
                  initial={{ opacity: 0, x: 20 }}
                  animate={{ opacity: 1, x: 0 }}
                  className="p-3 rounded-xl bg-red-500/5 border border-red-500/10"
                >
                  <div className="flex items-center gap-2 mb-1">
                    <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
                    <span className="text-[10px] font-black text-red-400 uppercase tracking-tighter">{threat.type}</span>
                  </div>
                  <p className="text-[11px] text-white font-bold leading-tight">{threat.message}</p>
                  <p className="text-[9px] text-zinc-600 mt-2 font-mono truncate">{threat.file}</p>
                </motion.div>
              ))}
            </AnimatePresence>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ProjectShieldView;
