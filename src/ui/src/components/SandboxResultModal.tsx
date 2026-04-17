import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, GitCommit, Upload, CheckCircle, AlertTriangle, ShieldAlert } from 'lucide-react';
import axios from 'axios';
import { ProcessGraph } from './ProcessGraph';
import { SentinelTerminal } from './SentinelTerminal';

type StepStatus = 'idle' | 'running' | 'success' | 'error';

interface Alert {
  ruleName?: string;
  riskLevel?: number;
  description?: string;
}

interface SandboxResultModalProps {
  isOpen: boolean;
  onClose: () => void;
  repoId: number;
  repoName: string;
}

const GRAPH_STEPS = ['Local Diff', 'Sentinel Scan', 'Sandbox Check', 'Result'];

export const SandboxResultModal: React.FC<SandboxResultModalProps> = ({
  isOpen, onClose, repoId, repoName
}) => {
  const [stepStatuses, setStepStatuses] = useState<StepStatus[]>(['idle', 'idle', 'idle', 'idle']);
  const [phase, setPhase] = useState<'scanning' | 'result' | 'commit'>('scanning');
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [pushBlocked, setPushBlocked] = useState(false);
  const [message, setMessage] = useState('');
  const [commitMsg, setCommitMsg] = useState('');
  const [signoff, setSignoff] = useState(false);
  const [commitLoading, setCommitLoading] = useState(false);
  const [commitDone, setCommitDone] = useState<{ success: boolean; pushed: boolean } | null>(null);
  const [termOpen, setTermOpen] = useState(false);
  const setStep = (i: number, s: StepStatus) =>
    setStepStatuses(prev => prev.map((v, idx) => idx === i ? s : v));

  useEffect(() => {
    if (!isOpen) {
      setStepStatuses(['idle', 'idle', 'idle', 'idle']);
      setPhase('scanning');
      setAlerts([]);
      setPushBlocked(false);
      setMessage('');
      setCommitMsg('');
      setCommitDone(null);
      return;
    }

    const run = async () => {
      // Step 0: Local Diff
      setStep(0, 'running');
      await delay(600);
      setStep(0, 'success');

      // Step 1: Sentinel Scan
      setStep(1, 'running');
      try {
        const { data } = await axios.post(`http://localhost:3001/api/repositories/${repoId}/analyze-local`);
        setAlerts(data.alerts || []);
        setPushBlocked(data.pushBlocked || false);
        setMessage(data.message || '');
        setStep(1, data.pushBlocked ? 'error' : 'success');
      } catch (err: any) {
        setMessage(err.response?.data?.error || err.message);
        setStep(1, 'error');
        setStep(2, 'idle');
        setStep(3, 'error');
        setPhase('result');
        return;
      }

      // Step 2: Sandbox (fetch last run status)
      setStep(2, 'running');
      await delay(800);
      try {
        const { data: sbData } = await axios.get(`http://localhost:3001/api/repositories/${repoId}/sandbox/status`);
        setStep(2, sbData.run?.conclusion === 'success' ? 'success' : sbData.run ? 'error' : 'idle');
      } catch {
        setStep(2, 'idle');
      }

      // Step 3: Result
      await delay(300);
      setStep(3, pushBlocked ? 'error' : 'success');
      setPhase('result');
    };

    run();
  }, [isOpen, repoId]);

  const handleCommit = async () => {
    if (!commitMsg.trim()) return;
    setCommitLoading(true);
    try {
      const { data } = await axios.post(`http://localhost:3001/api/repositories/${repoId}/commit`, {
        message: commitMsg.trim(),
        push: true,
        signoff
      });
      setCommitDone({ success: true, pushed: data.pushed });
    } catch (err: any) {
      setCommitDone({ success: false, pushed: false });
    } finally {
      setCommitLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-50 flex items-center justify-center p-6 bg-black/70 backdrop-blur-md">
        <motion.div
          initial={{ opacity: 0, scale: 0.95, y: 20 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 20 }}
          className="w-full max-w-2xl bg-[#0d0d0f] border border-[#2a2a30] rounded-2xl shadow-2xl shadow-emerald-500/5 overflow-hidden"
        >
          {/* Header */}
          <div className="flex items-center justify-between px-5 py-4 border-b border-[#2a2a30] bg-[#111114]">
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span className="text-[11px] font-mono font-bold tracking-widest uppercase text-emerald-400">
                Sentinel — Analyze Local Changes
              </span>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setTermOpen(true)}
                className="px-2 py-1 rounded-lg text-[10px] text-zinc-400 hover:text-white border border-white/10 hover:bg-white/5 transition-colors"
              >
                Terminal View
              </button>
              <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-white/5 text-zinc-500 hover:text-white transition-colors">
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>

          {/* Process Graph */}
          <div className="px-5 pt-4 border-b border-white/5">
            <ProcessGraph
              steps={GRAPH_STEPS.map((label, i) => ({ label, status: stepStatuses[i] }))}
            />
          </div>

          {/* Result Body */}
          <div className="p-5 space-y-4">
            {phase === 'scanning' && (
              <p className="text-sm text-zinc-400 text-center animate-pulse">Analyzing your local changes…</p>
            )}

            {phase === 'result' && (
              <>
                {/* Status Banner */}
                <div className={`rounded-xl px-4 py-3 border flex items-start gap-3 ${
                  pushBlocked
                    ? 'bg-red-500/10 border-red-500/20 text-red-300'
                    : alerts.length > 0
                      ? 'bg-amber-500/10 border-amber-500/20 text-amber-300'
                      : 'bg-emerald-500/10 border-emerald-500/20 text-emerald-300'
                }`}>
                  {pushBlocked ? <ShieldAlert className="w-4 h-4 mt-0.5 shrink-0" /> :
                    alerts.length > 0 ? <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" /> :
                    <CheckCircle className="w-4 h-4 mt-0.5 shrink-0" />}
                  <p className="text-[12px] font-medium leading-relaxed">{message || 'Scan complete.'}</p>
                </div>

                {/* Alert List */}
                {alerts.length > 0 && (
                  <div className="space-y-1.5 max-h-36 overflow-y-auto pr-1">
                    {alerts.map((alert, i) => (
                      <div key={i} className="text-[11px] text-red-300/80 px-3 py-2 rounded-xl bg-red-500/5 border border-red-500/10 leading-relaxed">
                        <span className="font-bold text-red-400">[{alert.ruleName || 'ALERT'}]</span>{' '}
                        {alert.description || 'Potential threat detected.'}
                      </div>
                    ))}
                  </div>
                )}

                {/* Commit Section */}
                {!pushBlocked && !commitDone && (
                  <div className="space-y-3 pt-2 border-t border-white/5">
                    <p className="text-[11px] text-zinc-500 font-medium">Optional: Commit & Push</p>
                    <input
                      type="text"
                      placeholder="Commit message…"
                      value={commitMsg}
                      onChange={e => setCommitMsg(e.target.value)}
                      className="w-full bg-white/5 border border-white/10 rounded-xl px-3 py-2 text-[12px] text-white placeholder-zinc-600 outline-none focus:border-emerald-500/50 transition-colors font-mono"
                    />
                    <div className="flex items-center justify-between">
                      <label className="flex items-center gap-2 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={signoff}
                          onChange={e => setSignoff(e.target.checked)}
                          className="accent-emerald-500"
                        />
                        <span className="text-[11px] text-zinc-400">Add <code className="text-emerald-400">--signoff</code></span>
                      </label>
                      <div className="flex items-center gap-2">
                        <button
                          onClick={onClose}
                          className="px-3 py-1.5 rounded-xl text-[11px] text-zinc-400 hover:text-white border border-white/10 hover:bg-white/5 transition-colors"
                        >
                          Close
                        </button>
                        <motion.button
                          whileTap={{ scale: 0.97 }}
                          onClick={handleCommit}
                          disabled={commitLoading || !commitMsg.trim()}
                          className="flex items-center gap-1.5 px-4 py-1.5 rounded-xl bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-500/30 text-emerald-400 text-[11px] font-bold transition-all disabled:opacity-40 disabled:cursor-not-allowed"
                        >
                          <Upload className="w-3.5 h-3.5" />
                          {commitLoading ? 'Committing…' : 'Commit & Push'}
                        </motion.button>
                      </div>
                    </div>
                  </div>
                )}

                {/* Commit Done */}
                {commitDone && (
                  <div className={`rounded-xl px-4 py-3 border flex items-center gap-3 ${
                    commitDone.success ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-300' : 'bg-red-500/10 border-red-500/20 text-red-300'
                  }`}>
                    {commitDone.success ? <GitCommit className="w-4 h-4 shrink-0" /> : <ShieldAlert className="w-4 h-4 shrink-0" />}
                    <p className="text-[12px] font-medium">
                      {commitDone.success
                        ? commitDone.pushed ? '✅ Committed and pushed successfully.' : '✅ Committed locally (not pushed).'
                        : '❌ Commit failed. Check the terminal for details.'}
                    </p>
                  </div>
                )}

                {/* Push Blocked — only close/fix */}
                {pushBlocked && (
                  <div className="flex justify-end">
                    <button
                      onClick={onClose}
                      className="px-4 py-1.5 rounded-xl text-[11px] font-bold text-zinc-400 hover:text-white border border-white/10 hover:bg-white/5 transition-colors"
                    >
                      Go fix the issues →
                    </button>
                  </div>
                )}
              </>
            )}
          </div>
        </motion.div>
      </div>

      {/* Reuse existing SentinelTerminal for terminal view */}
      <SentinelTerminal
        isOpen={termOpen}
        onClose={() => setTermOpen(false)}
        command="sentinel analyze --local"
        repoName={repoName}
      />
    </AnimatePresence>
  );
};

function delay(ms: number) { return new Promise(r => setTimeout(r, ms)); }
