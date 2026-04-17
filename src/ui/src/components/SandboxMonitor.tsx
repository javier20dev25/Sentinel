import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  Play, History, ExternalLink, AlertTriangle, 
  CheckCircle2, Loader2, Copy, Code, Terminal,
  Network, Lock, FileCode
} from 'lucide-react';
import { sandboxApi } from '../lib/api';

interface SandboxMonitorProps {
  repos: any[];
}

interface SandboxThreat {
  type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  message: string;
  evidence: string;
  recommendation: string;
}

interface SandboxRun {
  runId: number;
  status: 'queued' | 'in_progress' | 'completed';
  conclusion: 'success' | 'failure' | 'cancelled' | null;
  url: string;
  threats?: SandboxThreat[];
  riskScore?: number;
  summary?: string;
  ownerRepo: string;
}

export const SandboxMonitor: React.FC<SandboxMonitorProps> = ({ repos }) => {
  const [selectedRepo, setSelectedRepo] = useState<string>('');
  const [branch, setBranch] = useState('main');
  const [isLoading, setIsLoading] = useState(false);
  const [currentRun, setCurrentRun] = useState<SandboxRun | null>(null);
  const [isInstalled, setIsInstalled] = useState<boolean | null>(null);
  const [installationSteps, setInstallationSteps] = useState<string[]>([]);
  const [workflowTemplate, setWorkflowTemplate] = useState('');
  const [pollingActive, setPollingActive] = useState(false);

  // Check if sandbox is installed when repo selection changes
  useEffect(() => {
    if (!selectedRepo) return;
    const [owner, repo] = selectedRepo.split('/');
    sandboxApi.checkStatus(owner, repo).then(res => {
      setIsInstalled(res.data.installed);
    });
  }, [selectedRepo]);

  // Polling for run status
  useEffect(() => {
    if (!pollingActive || !currentRun || !selectedRepo) return;

    const [owner, repo] = selectedRepo.split('/');
    const interval = setInterval(async () => {
      try {
        const { data: status } = await sandboxApi.getRunStatus(owner, repo, currentRun.runId);
        setCurrentRun(prev => prev ? { ...prev, ...status } : null);

        if (status.status === 'completed') {
          setPollingActive(false);
          // Auto analyze on success
          if (status.conclusion === 'success') {
            handleAnalyze(currentRun.runId);
          }
        }
      } catch (e) {
        console.error("Polling error", e);
      }
    }, 10000);

    return () => clearInterval(interval);
  }, [pollingActive, currentRun, selectedRepo]);

  const handleFetchTemplate = async () => {
    const { data } = await sandboxApi.getTemplate();
    setWorkflowTemplate(data.workflowContent);
    setInstallationSteps(data.instructions);
  };

  const handleTrigger = async () => {
    if (!selectedRepo) return;
    setIsLoading(true);
    try {
      const { data } = await sandboxApi.trigger(selectedRepo, branch);
      setCurrentRun(data);
      setPollingActive(true);
    } catch (e) {
      console.error(e);
    } finally {
      setIsLoading(false);
    }
  };

  const handleAnalyze = async (runId: number) => {
    setIsLoading(true);
    try {
      const { data } = await sandboxApi.analyze(selectedRepo, runId);
      setCurrentRun(data);
    } catch (e) {
      console.error(e);
    } finally {
      setIsLoading(false);
    }
  };

  const copyTemplate = () => {
    navigator.clipboard.writeText(workflowTemplate);
  };

  // Helper colors
  const getSeverityColor = (sev: string) => {
    switch (sev) {
      case 'CRITICAL': return 'text-red-500 bg-red-500/10 border-red-500/20';
      case 'HIGH': return 'text-orange-500 bg-orange-500/10 border-orange-500/20';
      case 'MEDIUM': return 'text-yellow-500 bg-yellow-500/10 border-yellow-500/20';
      default: return 'text-blue-500 bg-blue-500/10 border-blue-500/20';
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-black text-white">Dynamic Sandbox Monitor</h1>
          <p className="text-sm text-zinc-500">Isolate and analyze package behavior in GitHub Actions runners.</p>
        </div>
        <div className="flex gap-3">
          <input 
            type="text" 
            value={branch}
            onChange={(e) => setBranch(e.target.value)}
            placeholder="branch (e.g. main)"
            className="bg-white/5 border border-white/10 rounded-xl px-4 py-2 text-sm font-bold outline-none w-32"
          />
          <select 
            value={selectedRepo}
            onChange={(e) => setSelectedRepo(e.target.value)}
            className="bg-white/5 border border-white/10 rounded-xl px-4 py-2 text-sm font-bold outline-none"
          >
            <option value="" className="bg-zinc-900">Select Project...</option>
            {repos.map(r => (
              <option key={r.id} value={r.github_full_name} className="bg-zinc-900">{r.github_full_name}</option>
            ))}
          </select>
          <button 
            disabled={!selectedRepo || !isInstalled || isLoading || pollingActive}
            onClick={handleTrigger}
            className="flex items-center gap-2 px-6 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-bold transition-all shadow-lg shadow-blue-600/20"
          >
            {isLoading || pollingActive ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
            {pollingActive ? 'Analysis Running...' : 'Launch Sandbox'}
          </button>
        </div>
      </div>

      {/* Installation Banner */}
      {selectedRepo && isInstalled === false && (
        <motion.div 
          initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
          className="p-6 rounded-[24px] border border-amber-500/30 bg-amber-500/5 relative overflow-hidden"
        >
          <div className="flex gap-4 relative z-10">
            <div className="w-12 h-12 rounded-2xl bg-amber-500/20 flex items-center justify-center shrink-0">
              <AlertTriangle className="w-6 h-6 text-amber-500" />
            </div>
            <div className="flex-1">
              <h3 className="text-lg font-bold text-white mb-1">Sandbox Template Required</h3>
              <p className="text-sm text-zinc-400 mb-4">
                This repository does not have the Sentinel Sandbox workflow installed. 
                You must add the workflow file manually to enable dynamic analysis.
              </p>
              <button 
                onClick={handleFetchTemplate}
                className="px-5 py-2 rounded-xl bg-amber-500 text-black font-black text-xs hover:bg-amber-400 transition-colors"
              >
                Generate Setup Instructions
              </button>
            </div>
          </div>
        </motion.div>
      )}

      {/* Setup Instructions Modal-like Panel */}
      {workflowTemplate && (
        <motion.div 
          initial={{ opacity: 0, scale: 0.98 }} animate={{ opacity: 1, scale: 1 }}
          className="grid grid-cols-1 lg:grid-cols-2 gap-6"
        >
          <div className="glass rounded-[32px] p-8 border border-white/10">
            <div className="flex items-center gap-3 mb-6">
              <History className="w-5 h-5 text-blue-400" />
              <h3 className="text-lg font-bold text-white">1. Follow Instructions</h3>
            </div>
            <div className="space-y-4">
              {installationSteps.map((step, i) => (
                <div key={i} className="flex gap-3 text-sm text-zinc-400">
                  <span className="text-blue-400 font-bold">{i+1}.</span>
                  <span>{step}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="glass rounded-[32px] p-8 border border-white/10 flex flex-col">
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center gap-3">
                <Code className="w-5 h-5 text-indigo-400" />
                <h3 className="text-lg font-bold text-white">2. Paste into .github/workflows/</h3>
              </div>
              <button 
                onClick={copyTemplate}
                className="p-2 rounded-lg bg-white/5 hover:bg-white/10 text-zinc-400 hover:text-white transition-all"
              >
                <Copy className="w-4 h-4" />
              </button>
            </div>
            <div className="flex-1 bg-black/40 rounded-2xl p-4 border border-white/5 font-mono text-[10px] text-zinc-500 overflow-y-auto max-h-[300px]">
              <pre>{workflowTemplate}</pre>
            </div>
          </div>
        </motion.div>
      )}

      {/* Run Status Display */}
      {currentRun && (
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
          {/* Status Card */}
          <div className="glass rounded-[32px] p-6 border border-white/10 space-y-6">
            <div className="flex items-center justify-between">
              <span className="text-xs font-black uppercase tracking-widest text-zinc-500">Run ID: #{currentRun.runId}</span>
              <a href={currentRun.url} target="_blank" rel="noreferrer" className="text-blue-400 hover:text-blue-300 transition-colors">
                <ExternalLink className="w-4 h-4" />
              </a>
            </div>

            <div className={`p-4 rounded-2xl border flex items-center gap-4 ${
              currentRun.conclusion === 'success' ? 'bg-emerald-500/10 border-emerald-500/20' : 
              currentRun.conclusion === 'failure' ? 'bg-red-500/10 border-red-500/20' : 
              'bg-blue-500/10 border-blue-500/20'
            }`}>
              {currentRun.status === 'completed' ? (
                currentRun.conclusion === 'success' ? <CheckCircle2 className="w-6 h-6 text-emerald-500" /> : <AlertTriangle className="w-6 h-6 text-red-500" />
              ) : (
                <Loader2 className="w-6 h-6 text-blue-500 animate-spin" />
              )}
              <div>
                <p className="text-sm font-black text-white uppercase">{currentRun.status === 'completed' ? currentRun.conclusion : currentRun.status}</p>
                <p className="text-[10px] text-zinc-500">Simulation running on Ubuntu-Latest</p>
              </div>
            </div>

            {currentRun.riskScore !== undefined && (
              <div className="text-center p-6 rounded-3xl bg-white/5 border border-white/10">
                <p className="text-[10px] font-black uppercase tracking-widest text-zinc-500 mb-2">Simulation Risk Score</p>
                <div className="text-5xl font-black text-white">{currentRun.riskScore.toFixed(1)}</div>
                <p className={`text-[10px] mt-2 font-bold ${currentRun.riskScore > 7 ? 'text-red-400' : currentRun.riskScore > 3 ? 'text-amber-400' : 'text-emerald-400'}`}>
                  {currentRun.summary}
                </p>
              </div>
            )}
          </div>

          {/* Threats List */}
          <div className="xl:col-span-2 glass rounded-[32px] p-8 border border-white/10">
            <div className="flex items-center justify-between mb-8">
              <h3 className="text-lg font-black text-white flex items-center gap-3">
                <Terminal className="w-5 h-5 text-blue-400" />
                Telemetry Analysis Results
              </h3>
              <div className="flex gap-2">
                <div className="px-3 py-1 rounded-full bg-white/5 border border-white/10 text-[10px] font-bold text-zinc-400">
                  {currentRun.threats?.length || 0} Findings
                </div>
              </div>
            </div>

            <div className="space-y-4">
              {currentRun.threats && currentRun.threats.length > 0 ? (
                currentRun.threats.map((threat, idx) => (
                  <motion.div 
                    initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: idx * 0.1 }}
                    key={idx} className="p-5 rounded-3xl bg-white/[0.03] border border-white/5 hover:border-white/10 transition-all"
                  >
                    <div className="flex items-start justify-between mb-3">
                      <div className="flex items-center gap-3">
                        <div className={`px-2 py-0.5 rounded-lg border text-[8px] font-black uppercase ${getSeverityColor(threat.severity)}`}>
                          {threat.severity}
                        </div>
                        <h4 className="text-sm font-bold text-white">{threat.type}</h4>
                      </div>
                      {threat.type.includes('NETWORK') && <Network className="w-4 h-4 text-blue-400" />}
                      {threat.type.includes('WASM') && <FileCode className="w-4 h-4 text-indigo-400" />}
                      {threat.type.includes('LOCKFILE') && <Lock className="w-4 h-4 text-emerald-400" />}
                    </div>
                    <p className="text-xs text-zinc-400 mb-4 leading-relaxed">{threat.message}</p>
                    <div className="bg-black/40 rounded-xl p-3 border border-white/5">
                      <p className="text-[9px] font-black uppercase text-zinc-600 mb-1">Evidence</p>
                      <pre className="text-[10px] text-zinc-500 overflow-x-auto">{threat.evidence}</pre>
                    </div>
                  </motion.div>
                ))
              ) : (
                <div className="h-64 flex flex-col items-center justify-center text-center">
                  {currentRun.status === 'completed' ? (
                     <>
                      <div className="w-16 h-16 rounded-full bg-emerald-500/10 flex items-center justify-center mb-4">
                        <CheckCircle2 className="w-8 h-8 text-emerald-500" />
                      </div>
                      <p className="text-sm font-bold text-white">No Threats Detected</p>
                      <p className="text-xs text-zinc-500">All telemetry data matched baseline security profile.</p>
                     </>
                  ) : (
                    <>
                      <Loader2 className="w-8 h-8 text-blue-500 animate-spin mb-4" />
                      <p className="text-sm font-bold text-zinc-500">Awaiting Simulation Data...</p>
                    </>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
