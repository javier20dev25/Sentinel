import React, { useState, useEffect, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  ShieldAlert, ShieldCheck, GitBranch, BrainCircuit, 
  Loader2, Bot, Play, X, Check, Star, RefreshCcw, 
  AlertTriangle, Filter, FileCode2
} from 'lucide-react';
import { api } from '../lib/api';
import { LiveScannerTerminal } from './LiveScannerTerminal';
import { useSentinelStream } from '../hooks/useSentinelStream';

interface ThreatLogProps {
  repos: any[];
}

export const ThreatLog: React.FC<ThreatLogProps> = ({ repos }) => {
  const [selectedRepo, setSelectedRepo] = useState<string>('all');
  const [showPinned, setShowPinned] = useState<boolean>(false);
  const [logs, setLogs] = useState<any[]>([]);
  const [loadingLogs, setLoadingLogs] = useState<boolean>(true);
  const [scanningId, setScanningId] = useState<string | null>(null);
  const [selectedLogId, setSelectedLogId] = useState<number | null>(null);

  // SSE Hook for Live Terminal
  const { logs: terminalLogs, confidence, isScanning, clearLogs } = useSentinelStream();

  const [analyzingId, setAnalyzingId] = useState<number | null>(null);
  const [aiResponses, setAiResponses] = useState<Record<number, any>>({});
  const [fixState, setFixState] = useState<{ logId: number, cmd: string } | null>(null);
  const [fixingId, setFixingId] = useState<number | null>(null);
  const [fixResult, setFixResult] = useState<{ success: boolean, message: string } | null>(null);

  const fetchLogs = async () => {
    setLoadingLogs(true);
    try {
      const { data } = await api.get(`/api/repositories/${selectedRepo}/logs?pinned=${showPinned}`);
      const mappedLogs = data.map((log: any) => {
        const r = repos.find(r => r.id === log.repo_id);
        const evidence = log.evidence_metadata ? JSON.parse(log.evidence_metadata) : [];
        return { ...log, repoName: r ? r.github_full_name : 'Unknown Repo', evidence };
      });
      mappedLogs.sort((a: any, b: any) => (b.pinned ? 1 : 0) - (a.pinned ? 1 : 0));
      setLogs(mappedLogs);
    } catch (e) {
      console.error("Failed to fetch logs", e);
    } finally {
      setLoadingLogs(false);
    }
  };

  useEffect(() => {
    if (repos.length > 0) fetchLogs();
  }, [selectedRepo, showPinned, repos]);

  const handleRescan = async () => {
    if (selectedRepo === 'all') return;
    clearLogs();
    setScanningId(selectedRepo);
    try {
      await api.post(`/api/repositories/${selectedRepo}/scan`);
      setTimeout(fetchLogs, 1000); // Small delay to ensure DB is updated
    } catch (e) {
      console.error("Scan failed", e);
    } finally {
      setScanningId(null);
    }
  };

  const handleTogglePin = async (logId: number, currentPinned: boolean) => {
    try {
      await api.put(`/api/logs/${logId}/pin`, { pinned: !currentPinned });
      setLogs(prev => prev.map(l => l.id === logId ? { ...l, pinned: !currentPinned } : l));
    } catch (e) {
      console.error("Failed to pin log", e);
    }
  };

  const analyzeThreat = async (log: any) => {
    setAnalyzingId(log.id);
    try {
      const { data } = await api.post('/api/ai/explain', {
         logId: log.id,
         description: log.description,
         evidence: log.evidence?.[0]?.evidence || ''
      });
      setAiResponses(prev => ({ ...prev, [log.id]: data }));
    } catch (e: any) {
      setAiResponses(prev => ({ ...prev, [log.id]: { error: true, message: "AI Analysis failed. Check API configuration." } }));
    } finally {
      setAnalyzingId(null);
    }
  };

  const handleApplyFix = async () => {
    if (!fixState) return;
    setFixingId(fixState.logId);
    try {
      const { data } = await api.post('/api/action/fix', { command: fixState.cmd });
      setFixResult({ success: true, message: data.message });
      setAiResponses(prev => ({ ...prev, [fixState.logId]: { ...prev[fixState.logId], _fixed: true } }));
    } catch (e: any) {
      setFixResult({ success: false, message: e.response?.data?.error || e.message });
    } finally {
      setFixingId(null);
      setTimeout(() => { setFixState(null); setFixResult(null); }, 3000);
    }
  };

  const activeRepoName = useMemo(() => {
      const r = repos.find(r => r.id === parseInt(selectedRepo));
      return r ? r.github_full_name : 'All Entities';
  }, [selectedRepo, repos]);

  return (
    <div className="flex flex-col h-full gap-6 p-6">
      {/* Upper Control Bar */}
      <div className="flex items-center justify-between bg-white/[0.03] border border-white/[0.06] rounded-3xl p-4 backdrop-blur-md">
        <div className="flex items-center gap-4">
          <div className="relative group">
             <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500 group-focus-within:text-blue-400 transition-colors" />
             <select 
               className="bg-white/[0.05] border border-white/[0.1] rounded-xl pl-10 pr-4 py-2.5 text-sm text-white focus:outline-none focus:ring-2 focus:ring-blue-500/30 outline-none appearance-none min-w-[220px]"
               value={selectedRepo}
               onChange={(e) => setSelectedRepo(e.target.value)}
             >
               <option value="all">All Ecosystems</option>
               {repos.map(r => (
                 <option key={r.id} value={r.id}>{r.github_full_name}</option>
               ))}
             </select>
          </div>
          
          <button 
            onClick={() => setShowPinned(!showPinned)}
            className={`px-5 py-2.5 rounded-xl text-xs font-black flex items-center justify-center gap-2 transition-all border uppercase tracking-widest ${
              showPinned 
                ? 'bg-amber-500/20 text-amber-500 border-amber-500/30' 
                : 'bg-white/5 text-zinc-500 border-white/10 hover:bg-white/10'
            }`}
          >
            <Star className={`w-3.5 h-3.5 ${showPinned ? 'fill-amber-500' : ''}`} />
            {showPinned ? `Investigating (${logs.length})` : 'Pinned Only'}
          </button>
        </div>

        {selectedRepo !== 'all' && (
          <button
            onClick={handleRescan}
            disabled={!!scanningId || isScanning}
            className="px-6 py-2.5 rounded-xl text-xs font-black bg-blue-500 hover:bg-blue-400 text-white transition-all flex items-center justify-center gap-2 shadow-lg shadow-blue-500/20 disabled:opacity-50 uppercase tracking-widest"
          >
            {scanningId || isScanning ? <Loader2 className="w-4 h-4 animate-spin" /> : <RefreshCcw className="w-4 h-4" />}
            {scanningId || isScanning ? 'Synchronizing...' : 'Full System Scan'}
          </button>
        )}
      </div>

      <div className="flex-1 grid grid-cols-1 lg:grid-cols-12 gap-6 min-h-0">
        {/* Left Side: Logs & Forensic Panel (8 cols) */}
        <div className="lg:col-span-8 flex flex-col gap-6 min-h-0">
          
          {/* Main Content Area */}
          <div className="flex-1 overflow-y-auto custom-scrollbar pr-2 space-y-4">
             {loadingLogs ? (
               <div className="h-full flex items-center justify-center"><Loader2 className="w-8 h-8 animate-spin text-blue-500/40" /></div>
             ) : logs.length === 0 ? (
                <div className="h-[400px] flex flex-col items-center justify-center border border-dashed border-white/10 rounded-[32px] opacity-40">
                   <ShieldCheck className="w-12 h-12 mb-4 text-emerald-500" />
                   <p className="text-sm font-bold uppercase tracking-widest">Ecosystem Protected</p>
                </div>
             ) : (
                logs.map((log) => {
                  const isCritical = log.risk_level >= 8;
                  const isSelected = selectedLogId === log.id;
                  return (
                    <motion.div
                      key={log.id}
                      onClick={() => setSelectedLogId(log.id)}
                      layoutId={`log-${log.id}`}
                      className={`group cursor-pointer bg-white/[0.02] border rounded-[24px] p-5 transition-all hover:bg-white/[0.04] ${
                        isSelected ? 'border-blue-500/40 ring-1 ring-blue-500/20' : isCritical ? 'border-red-500/20' : 'border-white/[0.06]'
                      }`}
                    >
                      <div className="flex items-start gap-4">
                        <div className={`w-10 h-10 rounded-2xl flex items-center justify-center shrink-0 ${
                          isCritical ? 'bg-red-500/10 text-red-500' : 'bg-amber-500/10 text-amber-500'
                        }`}>
                          <ShieldAlert className="w-5 h-5" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center justify-between mb-1">
                             <div className="flex items-center gap-2">
                               <span className={`text-[10px] font-black uppercase px-2 py-0.5 rounded-lg border ${
                                 isCritical ? 'text-red-400 border-red-500/20 bg-red-500/5' : 'text-amber-400 border-amber-500/20 bg-amber-500/5'
                               }`}>Risk {log.risk_level}</span>
                               <span className="text-[10px] text-zinc-500 font-bold uppercase tracking-widest">{log.event_type}</span>
                             </div>
                             <span className="text-[10px] text-zinc-600 font-mono">{new Date(log.created_at).toLocaleTimeString()}</span>
                          </div>
                          <h4 className="text-sm text-zinc-200 font-bold mb-1 truncate">{log.description}</h4>
                          <p className="text-[10px] text-zinc-500 flex items-center gap-1.5">
                            <GitBranch className="w-3 h-3" /> {log.repoName}
                          </p>
                        </div>
                        
                        <button 
                          onClick={(e) => { e.stopPropagation(); handleTogglePin(log.id, !!log.pinned); }}
                          className={`p-2 transition-colors rounded-xl ${log.pinned ? 'text-amber-500' : 'text-zinc-700 hover:text-white'}`}
                        >
                          <Star className={`w-4 h-4 ${log.pinned ? 'fill-amber-500' : ''}`} />
                        </button>
                      </div>

                      {/* Expanded View in-list */}
                      <AnimatePresence>
                        {isSelected && (
                          <motion.div 
                            initial={{ opacity: 0, height: 0 }}
                            animate={{ opacity: 1, height: 'auto' }}
                            exit={{ opacity: 0, height: 0 }}
                            className="mt-5 pt-5 border-t border-white/[0.06] space-y-4"
                          >
                             {/* Evidence Snippet */}
                             {log.evidence && log.evidence.length > 0 && log.evidence[0].evidence && (
                               <div className="space-y-2">
                                 <div className="flex items-center gap-2 text-[10px] text-zinc-500 font-black uppercase tracking-widest">
                                   <FileCode2 className="w-3.5 h-3.5" /> Raw Evidence
                                 </div>
                                 <div className="bg-black/60 rounded-xl p-4 border border-white/5 font-mono text-[11px] text-zinc-400 leading-relaxed overflow-x-auto whitespace-pre">
                                   {log.evidence[0].evidence}
                                 </div>
                               </div>
                             )}

                             {/* AI Analysis View */}
                             {aiResponses[log.id] ? (
                               <div className="bg-indigo-500/10 border border-indigo-500/20 rounded-2xl p-4 space-y-3">
                                  <div className="flex items-center justify-between">
                                    <div className="flex items-center gap-2">
                                      <Bot className="w-4 h-4 text-indigo-400" />
                                      <span className="text-xs text-white font-bold">{aiResponses[log.id].threat_type || 'Analysis Result'}</span>
                                    </div>
                                    <div className="text-[10px] font-black uppercase bg-indigo-500/20 text-indigo-400 px-2 py-0.5 rounded-md">
                                      Action: {aiResponses[log.id].recommended_action}
                                    </div>
                                  </div>
                                  <p className="text-xs text-indigo-200/70 leading-relaxed">{aiResponses[log.id].detailed_analysis}</p>
                                  
                                  {aiResponses[log.id].remediation_suggestion && (
                                    <div className="flex items-center justify-between gap-3 bg-black/40 p-2.5 rounded-xl border border-white/5">
                                      <code className="text-[10px] text-emerald-400 truncate">{aiResponses[log.id].remediation_suggestion}</code>
                                      <button 
                                        onClick={(e) => { e.stopPropagation(); setFixState({ logId: log.id, cmd: aiResponses[log.id].remediation_suggestion }); }}
                                        disabled={aiResponses[log.id]._fixed}
                                        className="shrink-0 bg-emerald-500 hover:bg-emerald-400 text-white text-[10px] font-black px-3 py-1.5 rounded-lg transition-colors flex items-center gap-1.5"
                                      >
                                        {aiResponses[log.id]._fixed ? <Check className="w-3 h-3" /> : <Play className="w-3 h-3" />}
                                        {aiResponses[log.id]._fixed ? 'APPLIED' : 'APPLY FIX'}
                                      </button>
                                    </div>
                                  )}
                               </div>
                             ) : (
                               <button 
                                 onClick={(e) => { e.stopPropagation(); analyzeThreat(log); }}
                                 disabled={analyzingId === log.id}
                                 className="w-full flex items-center justify-center gap-2 py-3 rounded-xl bg-white/[0.05] border border-white/10 text-xs font-bold text-zinc-300 hover:bg-white/[0.08] transition-all"
                               >
                                 {analyzingId === log.id ? <Loader2 className="w-4 h-4 animate-spin" /> : <BrainCircuit className="w-4 h-4" />}
                                 {analyzingId === log.id ? 'Analyzing with Sentinel AI...' : 'Analyze Threat with AI Core'}
                               </button>
                             )}
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </motion.div>
                  );
                })
             )}
          </div>
        </div>

        {/* Right Side: Live Terminal (4 cols) */}
        <div className="lg:col-span-4 flex flex-col gap-6 min-h-0">
           <div className="flex-1 min-h-0">
              <LiveScannerTerminal 
                logs={terminalLogs}
                confidenceScore={confidence}
                isScanning={isScanning}
                repoName={activeRepoName}
              />
           </div>

           {/* Quick Stats / Confidence Tracker */}
           <div className="bg-white/[0.02] border border-white/[0.06] rounded-[24px] p-5">
              <div className="flex items-center justify-between mb-4">
                 <h5 className="text-[10px] font-black text-zinc-500 uppercase tracking-widest">System Health</h5>
                 <AlertTriangle className={`w-4 h-4 ${confidence && confidence < 70 ? 'text-red-500' : 'text-zinc-700'}`} />
              </div>
              <div className="space-y-4">
                 <div>
                    <div className="flex items-center justify-between text-[11px] mb-2 font-bold">
                       <span className="text-zinc-400 uppercase tracking-tighter">Confidence Index</span>
                       <span className={confidence && confidence < 70 ? 'text-red-400' : 'text-emerald-400'}>{confidence || 100}%</span>
                    </div>
                    <div className="h-1.5 w-full bg-white/5 rounded-full overflow-hidden">
                       <motion.div 
                         initial={{ width: 0 }}
                         animate={{ width: `${confidence || 100}%` }}
                         className={`h-full ${confidence && confidence < 70 ? 'bg-red-500 shadow-[0_0_10px_rgba(239,68,68,0.5)]' : 'bg-emerald-500 shadow-[0_0_10px_rgba(16,185,129,0.5)]'}`}
                       />
                    </div>
                 </div>
                 
                 <div className="grid grid-cols-2 gap-4">
                    <div className="bg-black/20 p-3 rounded-2xl border border-white/5">
                       <p className="text-[9px] text-zinc-500 uppercase font-black mb-1">Total Threats</p>
                       <p className="text-lg font-black text-white">{logs.filter(l => l.risk_level >= 8).length}</p>
                    </div>
                    <div className="bg-black/20 p-3 rounded-2xl border border-white/5">
                       <p className="text-[9px] text-zinc-500 uppercase font-black mb-1">Alerts</p>
                       <p className="text-lg font-black text-white">{logs.length}</p>
                    </div>
                 </div>
              </div>
           </div>
        </div>
      </div>

      {/* Reused Fix Modal */}
      <AnimatePresence>
        {fixState && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md">
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 20 }}
              className="max-w-md w-full bg-[#0a0a0c] border border-red-500/20 rounded-[32px] p-8 shadow-2xl relative overflow-hidden"
            >
              <div className="absolute top-0 right-0 w-64 h-64 bg-red-500/10 blur-[80px] pointer-events-none" />
              
              <div className="flex justify-between items-center mb-6">
                <div className="w-12 h-12 rounded-2xl bg-red-500/10 border border-red-500/20 flex items-center justify-center">
                  <ShieldAlert className="w-6 h-6 text-red-400" />
                </div>
                {!fixingId && !fixResult && (
                  <button onClick={() => setFixState(null)} className="p-2 text-zinc-500 hover:text-white transition-colors">
                    <X className="w-6 h-6" />
                  </button>
                )}
              </div>

              <h3 className="text-2xl font-black text-white mb-3">Authorize Execution</h3>
              <p className="text-sm text-zinc-400 mb-6 leading-relaxed font-medium">
                Sentinel is requesting privileged access to run the following remediation command on your workspace.
              </p>

              <div className="bg-black/60 border border-white/10 rounded-2xl p-5 mb-8 font-mono text-xs text-amber-500 break-all leading-relaxed shadow-inner">
                {fixState.cmd}
              </div>

              {fixResult ? (
                <div className={`p-5 rounded-2xl text-sm font-bold flex items-start gap-4 ${
                  fixResult.success ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-red-500/10 text-red-400 border border-red-500/20'
                }`}>
                  {fixResult.success ? <Check className="w-6 h-6 shrink-0" /> : <X className="w-6 h-6 shrink-0" />}
                  <span className="leading-relaxed">{fixResult.message}</span>
                </div>
              ) : (
                <div className="flex gap-4">
                  <button
                    onClick={() => setFixState(null)}
                    className="flex-1 py-4 px-6 rounded-2xl font-black text-xs uppercase tracking-widest bg-white/5 hover:bg-white/10 text-white transition-all border border-white/10"
                  >
                    Abort
                  </button>
                  <button
                    onClick={handleApplyFix}
                    disabled={fixingId !== null}
                    className="flex-1 py-4 px-6 rounded-2xl font-black text-xs uppercase tracking-widest bg-red-600 hover:bg-red-500 text-white transition-all shadow-lg shadow-red-600/30 flex items-center justify-center gap-2"
                  >
                    {fixingId ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
                    {fixingId ? 'Executing...' : 'Authorize'}
                  </button>
                </div>
              )}
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
};
