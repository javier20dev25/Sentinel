import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  ShieldCheck, ShieldAlert, AlertTriangle, 
  Trash2, EyeOff, Send, RefreshCcw, 
  Check, Loader2, GitPullRequest
} from 'lucide-react';
import { api } from '../lib/api';

interface StagedFile {
  path: string;
  riskLevel: number;
  alerts: any[];
  hasContent: boolean;
}

export function SafeStagingView({ repoId }: { repoId: string }) {
  const [files, setFiles] = useState<StagedFile[]>([]);
  const [loading, setLoading] = useState(true);
  const [pushing, setPushing] = useState(false);
  const [pushStatus, setPushStatus] = useState<null | 'success' | 'error'>(null);
  
  const [showOverrideModal, setShowOverrideModal] = useState(false);
  const [password, setPassword] = useState('');
  const [violatingFiles, setViolatingFiles] = useState<string[]>([]);
  const [authError, setAuthError] = useState('');

  const fetchStagedFiles = async () => {
    if (!repoId || repoId === 'all') return;
    setLoading(true);
    try {
      const { data } = await api.get(`/api/git/staged?repoId=${repoId}`);
      setFiles(data.files || []);
    } catch (e) {
      console.error("Failed to fetch staged files", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStagedFiles();
  }, [repoId]);

  const handleUnstage = async (filePath: string) => {
    try {
      await api.post('/api/git/unstage', { repoId, filePath });
      setFiles(prev => prev.filter(f => f.path !== filePath));
    } catch (e) {
      alert("Failed to unstage");
    }
  };

  const handleIgnore = async (filePath: string) => {
    try {
      await api.post('/api/git/ignore', { repoId, filePath });
      setFiles(prev => prev.filter(f => f.path !== filePath));
    } catch (e) {
      alert("Failed to ignore");
    }
  };

  const handlePush = async (isOverride: boolean = false) => {
    setPushing(true);
    setPushStatus(null);
    setAuthError('');
    try {
      await api.post('/api/git/push', { 
        repoId, 
        override: isOverride, 
        password: isOverride ? password : undefined 
      });
      setPushStatus('success');
      setShowOverrideModal(false);
      setFiles([]);
    } catch (e: any) {
      if (e.response?.data?.error === 'PROHIBITED_ASSETS_DETECTED') {
          setViolatingFiles(e.response.data.files);
          setShowOverrideModal(true);
      } else if (e.response?.status === 401) {
          setAuthError('Incorrect master password.');
      } else {
          setPushStatus('error');
      }
    } finally {
      setPushing(false);
    }
  };

  const highRiskFiles = files.filter(f => f.riskLevel >= 7);

  if (!repoId || repoId === 'all') {
    return (
      <div className="flex flex-col items-center justify-center p-12 text-center border-2 border-dashed border-white/10 rounded-2xl bg-white/5">
        <GitPullRequest className="w-16 h-16 text-blue-400 mb-4 opacity-50" />
        <h3 className="text-xl font-bold text-white">Select a Specific Repository</h3>
        <p className="text-slate-400 mt-2 max-w-sm">Safe Staging requires a single active repository context to inspect Git assets.</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header Info */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-black flex items-center gap-3 text-white">
            <ShieldCheck className="text-blue-400" />
            Safe Staging & Push Control
          </h2>
          <p className="text-slate-400">Inspect assets in the Git index before they reach the remote repository.</p>
        </div>
        <button 
          onClick={fetchStagedFiles}
          className="p-2 hover:bg-white/10 rounded-lg transition-colors text-zinc-500"
          title="Refresh Staging Status"
        >
          <RefreshCcw className={`w-5 h-5 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {loading ? (
        <div className="flex flex-col items-center justify-center py-20">
          <Loader2 className="w-10 h-10 text-blue-400 animate-spin mb-4" />
          <p className="text-slate-500 font-medium">Scanning Git Index...</p>
        </div>
      ) : files.length === 0 ? (
        <div className="p-12 text-center border-2 border-dashed border-white/10 rounded-2xl bg-white/5">
          <Check className="w-12 h-12 text-green-400 mx-auto mb-4" />
          <h3 className="text-lg font-bold text-white">Git Index is Clean</h3>
          <p className="text-slate-400 mt-1">No staged changes detected. Ready for your next features.</p>
        </div>
      ) : (
        <div className="grid gap-4">
          <AnimatePresence>
            {files.map((file) => (
              <motion.div
                key={file.path}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, x: -20 }}
                className={`p-4 rounded-xl border flex items-center justify-between bg-black/40 backdrop-blur-sm transition-all
                  ${file.riskLevel >= 7 ? 'border-red-500/50 shadow-lg shadow-red-500/10' : 'border-white/10'}`}
              >
                <div className="flex items-center gap-4">
                  <div className={`p-2 rounded-lg 
                    ${file.riskLevel >= 7 ? 'bg-red-500/20 text-red-400' : 
                      file.riskLevel > 0 ? 'bg-amber-500/20 text-amber-400' : 'bg-slate-500/20 text-slate-400'}`}
                  >
                    {file.riskLevel >= 7 ? <ShieldAlert className="w-5 h-5" /> : 
                     file.riskLevel > 0 ? <AlertTriangle className="w-5 h-5" /> : <ShieldCheck className="w-5 h-5" />}
                  </div>
                  <div>
                    <div className="font-mono text-sm font-bold flex items-center gap-2 text-white">
                       {file.path}
                       {file.riskLevel >= 7 && <span className="text-[10px] bg-red-500 text-white px-2 py-0.5 rounded uppercase">Critical Stop</span>}
                    </div>
                    {file.alerts.length > 0 && (
                      <div className="text-xs text-slate-500 mt-1">
                        Detected: {file.alerts[0].description.substring(0, 60)}...
                      </div>
                    )}
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <button 
                    onClick={() => handleUnstage(file.path)}
                    className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-xs font-bold transition-all border border-white/10 text-white"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    Unstage
                  </button>
                  <button 
                    onClick={() => handleIgnore(file.path)}
                    className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-red-500/10 hover:bg-red-500/20 text-red-400 text-xs font-bold transition-all border border-red-500/20"
                  >
                    <EyeOff className="w-3.5 h-3.5" />
                    Auto-Ignore
                  </button>
                </div>
              </motion.div>
            ))}
          </AnimatePresence>

          {/* Action Bar */}
          <div className="mt-8 p-6 rounded-2xl bg-gradient-to-br from-blue-500/10 to-indigo-500/5 border border-blue-500/20 flex items-center justify-between">
            <div>
              <h4 className="font-bold flex items-center gap-2">
                {highRiskFiles.length > 0 ? (
                  <span className="text-red-400 flex items-center gap-2">
                    <ShieldAlert className="w-5 h-5" /> Security Block Enabled
                  </span>
                ) : (
                  <span className="text-green-400 flex items-center gap-2">
                    <ShieldCheck className="w-5 h-5" /> Staging Verified
                  </span>
                )}
              </h4>
              <p className="text-sm text-slate-400 mt-1">
                {highRiskFiles.length > 0 ? 
                  `Push blocked. Resolve ${highRiskFiles.length} critical security vulnerabilities first.` : 
                  `All ${files.length} staged files passed the security scan.`}
              </p>
            </div>

            <button
               onClick={() => handlePush(false)}
               disabled={highRiskFiles.length > 0 || pushing}
               className={`flex items-center gap-3 px-8 py-3 rounded-xl font-black transition-all transform active:scale-95
                 ${highRiskFiles.length > 0 ? 'bg-slate-800 text-slate-500 cursor-not-allowed grayscale' : 
                   'bg-blue-600 hover:bg-blue-500 shadow-lg shadow-blue-600/20 text-white'}`}
            >
              {pushing ? (
                <>
                  <Loader2 className="w-5 h-5 animate-spin" />
                  Pushing...
                </>
              ) : pushStatus === 'success' ? (
                <>
                  <Check className="w-5 h-5 text-green-300" />
                  Pushed Successfully!
                </>
              ) : (
                <>
                  <Send className="w-5 h-5" />
                  Secure Push to GitHub
                </>
              )}
            </button>
          </div>
        </div>
      )}

      {/* Override Modal */}
      <AnimatePresence>
        {showOverrideModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-6 bg-black/80 backdrop-blur-md">
            <motion.div 
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              className="max-w-lg w-full bg-zinc-900 border border-red-500/30 rounded-[32px] p-8 shadow-2xl shadow-red-500/10"
            >
              <div className="flex items-center gap-4 mb-6">
                <div className="w-14 h-14 rounded-2xl bg-red-500/10 border border-red-500/20 flex items-center justify-center">
                  <ShieldAlert className="w-8 h-8 text-red-500" />
                </div>
                <div>
                  <h3 className="text-xl font-black text-white">SECURITY INTERCEPTION</h3>
                  <p className="text-xs text-red-400 font-bold uppercase tracking-widest">Prohibited Assets Detected</p>
                </div>
              </div>

              <div className="bg-black/40 rounded-2xl p-4 border border-white/5 mb-6">
                <p className="text-xs text-zinc-400 mb-3">Sentinel has blocked the upload of the following protected files:</p>
                <div className="space-y-1">
                  {violatingFiles.map(f => (
                    <div key={f} className="text-[11px] font-mono text-red-400 flex items-center gap-2">
                       <AlertTriangle className="w-3 h-3" /> {f}
                    </div>
                  ))}
                </div>
              </div>

              <div className="space-y-4">
                <div>
                  <label className="block text-[10px] font-black text-zinc-500 uppercase tracking-widest mb-2">Master Password</label>
                  <input 
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Enter Sentinel Master Password"
                    className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-sm text-white outline-none focus:border-red-500/50 transition-colors"
                  />
                  {authError && <p className="text-[10px] text-red-500 mt-2 font-bold">{authError}</p>}
                </div>

                <div className="flex gap-3">
                  <button 
                    onClick={() => setShowOverrideModal(false)}
                    className="flex-1 px-6 py-3 rounded-xl bg-white/5 text-white text-sm font-bold hover:bg-white/10 transition-all"
                  >
                    Cancel
                  </button>
                  <button 
                    onClick={() => handlePush(true)}
                    disabled={!password || pushing}
                    className="flex-1 px-6 py-3 rounded-xl bg-red-500 text-white text-sm font-bold hover:bg-red-600 transition-all flex items-center justify-center gap-2"
                  >
                    {pushing ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
                    Confirm & Force Push
                  </button>
                </div>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}
