import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  GitBranch, ShieldCheck, ShieldAlert, Clock, Scan, MoreVertical,
  Terminal as TermIcon, Shield, BugOff, Zap, ExternalLink,
  ToggleLeft, ToggleRight, Copy, Check, ChevronRight, FolderLock, PackageMinus
} from 'lucide-react';
import axios from 'axios';
import { SentinelTerminal } from './SentinelTerminal';
import { SandboxResultModal } from './SandboxResultModal';
import { PackLoaderModal } from './PackLoaderModal';
import { ProtectedFilesModal } from './ProtectedFilesModal';
import { ScoreRing } from './ScoreRing';
import { DependencyAudit } from './DependencyAudit';

interface RepoCardProps { repo: any; }

type SandboxStatus = 'NOT_CONFIGURED' | 'ACTIVE_SAFE' | 'ACTIVE_THREAT' | 'ACTIVE_RUNNING' | 'LOADING';

const RepoCard: React.FC<RepoCardProps> = ({ repo }) => {
  const isSafe = repo.status === 'SAFE';
  const [showMenu, setShowMenu] = useState(false);

  // Terminal State
  const [termOpen, setTermOpen] = useState(false);
  const [termCmd, setTermCmd] = useState('');

  // Analyze Local Modal
  const [analyzeOpen, setAnalyzeOpen] = useState(false);

  // Pack Loader Modal
  const [packModalOpen, setPackModalOpen] = useState(false);

  // Protected Files Modal
  const [protectedOpen, setProtectedOpen] = useState(false);

  // Sandbox State
  const [sandboxStatus, setSandboxStatus] = useState<SandboxStatus>('LOADING');
  const [sandboxRun, setSandboxRun] = useState<any>(null);
  const [showGuardianModal, setShowGuardianModal] = useState(false);
  const [guardianStep, setGuardianStep] = useState<'info' | 'manual' | 'auto_confirm' | 'auto_done'>('info');
  const [templateContent, setTemplateContent] = useState('');
  const [templatePath, setTemplatePath] = useState('');
  const [copied, setCopied] = useState(false);
  const [sandboxEnabled, setSandboxEnabled] = useState(true); // toggle state
  const [showDisableConfirm, setShowDisableConfirm] = useState(false);

  const latestAlerts = (repo.logs || []).filter((l: any) => l.risk_level >= 6).slice(0, 2);
  const repoName = repo.github_full_name?.includes('/')
    ? repo.github_full_name.split('/')[1]
    : repo.github_full_name || 'Unknown Repo';

  // Fetch sandbox status
  useEffect(() => {
    const fetchSandbox = async () => {
      try {
        const { data } = await axios.get(`http://localhost:3001/api/repositories/${repo.id}/sandbox/status`);
        setSandboxRun(data.run);
        if (!data.installed) {
          setSandboxStatus('NOT_CONFIGURED');
        } else if (!data.run) {
          setSandboxStatus('ACTIVE_SAFE');
        } else if (data.run.status === 'in_progress' || data.run.status === 'queued') {
          setSandboxStatus('ACTIVE_RUNNING');
        } else if (data.run.conclusion === 'success') {
          setSandboxStatus('ACTIVE_SAFE');
        } else if (data.run.conclusion === 'failure') {
          setSandboxStatus('ACTIVE_THREAT');
        } else {
          setSandboxStatus('ACTIVE_SAFE');
        }
      } catch {
        setSandboxStatus('NOT_CONFIGURED');
      }
    };
    fetchSandbox();
    const interval = setInterval(fetchSandbox, 60000); // Poll every minute
    return () => clearInterval(interval);
  }, [repo.id]);

  const handleScan = async (e: React.MouseEvent) => {
    e.stopPropagation(); setScanning(true);
    try { await axios.post(`http://localhost:3001/api/repositories/${repo.id}/scan`); }
    catch (err) { } finally { setScanning(false); }
  };

  const launchTerm = (cmd: string, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    setTermCmd(cmd);
    setTermOpen(true);
    setShowMenu(false);
  };

  const openGuardianManual = async () => {
    try {
      const { data } = await axios.post(`http://localhost:3001/api/repositories/${repo.id}/sandbox/sync`, { mode: 'manual' });
      setTemplateContent(data.content);
      setTemplatePath(data.path);
      setGuardianStep('manual');
    } catch (e) {
      console.error(e);
    }
  };

  const installGuardianAuto = async () => {
    try {
      await axios.post(`http://localhost:3001/api/repositories/${repo.id}/sandbox/sync`, { mode: 'auto', consented: true });
      setSandboxStatus('ACTIVE_SAFE');
      setGuardianStep('auto_done');
    } catch (e) {
      console.error(e);
    }
  };

  const copyTemplate = () => {
    navigator.clipboard.writeText(templateContent);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const sandboxBadge = {
    NOT_CONFIGURED: { color: 'bg-amber-500/10 text-amber-400 border-amber-500/20', dot: 'bg-amber-400', label: 'Sandbox: Not Set Up' },
    ACTIVE_SAFE:    { color: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20', dot: 'bg-emerald-400', label: 'Sandbox: ✓ Clean' },
    ACTIVE_THREAT:  { color: 'bg-red-500/10 text-red-400 border-red-500/20', dot: 'bg-red-400 animate-pulse', label: 'Sandbox: ⚠ Threat' },
    ACTIVE_RUNNING: { color: 'bg-blue-500/10 text-blue-400 border-blue-500/20', dot: 'bg-blue-400 animate-pulse', label: 'Sandbox: Scanning…' },
    LOADING:        { color: 'bg-zinc-500/10 text-zinc-500 border-zinc-500/10', dot: 'bg-zinc-600', label: 'Sandbox: Loading…' },
  }[sandboxStatus];

  return (
    <>
      <motion.div whileHover={{ y: -3 }} className={`glass rounded-[28px] border p-6 relative cursor-pointer transition-colors ${isSafe ? 'border-white/5 hover:border-emerald-500/20' : 'border-red-500/20 bg-red-500/[0.03]'}`}>
        <div className={`absolute -top-12 -right-12 w-40 h-40 blur-[80px] opacity-20 rounded-full ${isSafe ? 'bg-emerald-500' : 'bg-red-500'}`} />

        <div className="relative z-10">
          {/* Header Row */}
          <div className="flex items-start justify-between mb-5">
            <div className="w-12 h-12 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-center">
              <GitBranch className="w-5 h-5 text-zinc-500" />
            </div>

            <div className="flex items-center gap-2">
              <div className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[9px] font-black uppercase tracking-widest border ${isSafe ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' : 'bg-red-500/10 text-red-400 border-red-500/20'}`}>
                {isSafe ? <ShieldCheck className="w-3 h-3" /> : <ShieldAlert className="w-3 h-3" />}
                {repo.status}
              </div>

              {repo.activePacks > 0 && (
                <div 
                  onClick={(e) => { e.stopPropagation(); setPackModalOpen(true); }}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[9px] font-black tracking-widest border bg-[#18181b] text-zinc-400 border-[#2a2a30] hover:text-white cursor-pointer transition-colors uppercase"
                  title="Gestionar Packs Instalados"
                >
                  {repo.activePacks} Packs
                </div>
              )}

              {/* 3-dot menu */}
              <div className="relative">
                <button onClick={(e) => { e.stopPropagation(); setShowMenu(!showMenu); }} className="p-1.5 rounded-full hover:bg-white/10 text-zinc-400 transition-colors">
                  <MoreVertical className="w-4 h-4" />
                </button>
                <AnimatePresence>
                  {showMenu && (
                    <motion.div initial={{ opacity: 0, scale: 0.9, y: 5 }} animate={{ opacity: 1, scale: 1, y: 0 }} exit={{ opacity: 0, scale: 0.9, y: 5 }} className="absolute right-0 mt-2 w-52 bg-[#18181b] border border-[#2a2a30] rounded-xl shadow-2xl py-1 z-50">
                      <button onClick={(e) => launchTerm('sentinel scan', e)} className="w-full flex items-center gap-2 px-3 py-2 text-[11px] text-zinc-300 hover:bg-white/5 hover:text-white transition-colors">
                        <Scan className="w-3.5 h-3.5" /> Full Scope Scan
                      </button>
                      <button onClick={(e) => launchTerm('sentinel quarantine --pr', e)} className="w-full flex items-center gap-2 px-3 py-2 text-[11px] text-zinc-300 hover:bg-white/5 hover:text-white transition-colors">
                        <Shield className="w-3.5 h-3.5 text-amber-500" /> Quarantine Last PR
                      </button>
                      <button onClick={(e) => launchTerm('sentinel block --deps', e)} className="w-full flex items-center gap-2 px-3 py-2 text-[11px] text-zinc-300 hover:bg-white/5 hover:text-white transition-colors">
                        <BugOff className="w-3.5 h-3.5 text-red-500" /> Detect Typosquatting
                      </button>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setShowDisableConfirm(true);
                          setShowMenu(false);
                        }}
                        className="w-full flex items-center justify-between gap-2 px-3 py-2 text-[11px] text-zinc-300 hover:bg-white/5 hover:text-white transition-colors border-t border-white/5 mt-1"
                      >
                        <span className="flex items-center gap-2">
                          {sandboxEnabled ? <ToggleRight className="w-3.5 h-3.5 text-emerald-400" /> : <ToggleLeft className="w-3.5 h-3.5 text-zinc-500" />}
                          Sandbox {sandboxEnabled ? 'Enabled' : 'Disabled'}
                        </span>
                      </button>
                      <button onClick={(e) => { e.stopPropagation(); setProtectedOpen(true); setShowMenu(false); }} className="w-full flex items-center gap-2 px-3 py-2 text-[11px] text-zinc-300 hover:bg-white/5 hover:text-white transition-colors">
                        <FolderLock className="w-3.5 h-3.5 text-amber-500" /> Gestionar Archivos Protegidos
                      </button>
                      <button onClick={async (e) => {
                          e.stopPropagation();
                          if (confirm('Restaurar la configuración eliminará todos los packs. ¿Continuar?')) {
                            try {
                              await axios.delete(`http://localhost:3001/api/repositories/${repo.id}/packs`);
                              window.location.reload();
                            } catch(e) {}
                          }
                      }} className="w-full flex items-center gap-2 px-3 py-2 text-[11px] text-zinc-300 hover:bg-red-500/10 hover:text-red-400 transition-colors border-t border-white/5 mt-1">
                        <PackageMinus className="w-3.5 h-3.5" /> Restaurar Configuración
                      </button>
                      <button onClick={async (e) => {
                        e.stopPropagation();
                        if (confirm(`Are you sure you want to forget this repository? Local logs will be erased.`)) {
                          try {
                            await api.delete(`/api/repositories/${repo.id}`);
                            window.location.reload();
                          } catch (err) { }
                        }
                      }} className="w-full flex items-center gap-2 px-3 py-2 text-[11px] text-zinc-300 hover:bg-red-500/10 hover:text-red-400 transition-colors border-t border-white/5">
                        <ShieldAlert className="w-3.5 h-3.5" /> Forget Repository
                      </button>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            </div>
          </div>

          {/* Repo Name + Score */}
          <div className="mb-4 flex items-center justify-between">
            <div>
              <h3 className="text-base font-bold text-white truncate">{repoName}</h3>
              <p className="text-[11px] text-zinc-600 font-medium truncate mt-0.5">{repo.github_full_name}</p>
            </div>
            {repo.score !== undefined && <ScoreRing score={repo.score} />}
          </div>

          {/* Sandbox Status Bar */}
          <div className="mb-4">
            <div className={`flex items-center justify-between px-3 py-2 rounded-xl border text-[10px] font-bold ${sandboxBadge.color}`}>
              <div className="flex items-center gap-2">
                <span className={`w-1.5 h-1.5 rounded-full ${sandboxBadge.dot}`} />
                {sandboxBadge.label}
              </div>
              <div className="flex items-center gap-2">
                {sandboxStatus === 'NOT_CONFIGURED' && (
                  <button
                    onClick={(e) => { e.stopPropagation(); setShowGuardianModal(true); setGuardianStep('info'); }}
                    className="text-[9px] uppercase tracking-widest hover:text-white transition-colors"
                  >
                    Install →
                  </button>
                )}
                {sandboxStatus === 'ACTIVE_THREAT' && sandboxRun?.html_url && (
                  <a
                    href={sandboxRun.html_url}
                    target="_blank"
                    rel="noreferrer"
                    onClick={(e) => e.stopPropagation()}
                    className="flex items-center gap-1 hover:text-white transition-colors"
                  >
                    See Details <ExternalLink className="w-2.5 h-2.5" />
                  </a>
                )}
                {(sandboxStatus === 'ACTIVE_SAFE' || sandboxStatus === 'ACTIVE_THREAT') && sandboxRun?.created_at && (
                  <span className="text-[9px] opacity-60">
                    {new Date(sandboxRun.created_at).toLocaleDateString()}
                  </span>
                )}
              </div>
            </div>
          </div>

          {/* Alert preview */}
          {latestAlerts.length > 0 && !isSafe && (
            <div className="space-y-2 mb-4">
              {latestAlerts.map((log: any) => (
                <div key={log.id} className="text-[11px] text-red-300/70 leading-relaxed px-3 py-2 rounded-xl bg-red-500/5 border border-red-500/10 truncate">
                  {log.description}
                </div>
              ))}
            </div>
            
            {latestCommit && (
              <div className="flex gap-2.5">
                <div className="w-[1px] bg-blue-500/20 translate-x-1.5 mt-2 mb-2" />
                <div className="space-y-1">
                  <p className="text-[9px] font-black text-zinc-500 uppercase">Recent Activity</p>
                  <p className="text-[10px] text-zinc-300 font-bold leading-tight line-clamp-1">
                    {latestCommit.commit.message}
                  </p>
                  <p className="text-[8px] text-zinc-600 font-medium">
                    by {latestCommit.commit.author.name} • {new Date(latestCommit.commit.author.date).toLocaleDateString()}
                  </p>
                </div>
              </div>
            )}

            <DependencyAudit repoId={repo.id} />
          </div>

          {/* Footer actions */}
          <div className="flex items-center justify-between pt-4 border-t border-white/[0.04] gap-2">
            <div className="flex items-center gap-1.5 text-[10px] text-zinc-600 font-bold">
              <Clock className="w-3 h-3" />
              {repo.last_scan_at ? new Date(repo.last_scan_at).toLocaleString() : 'Never scanned'}
            </div>
            <div className="flex items-center gap-2">
              {/* Analyze Local Changes */}
              <motion.button
                whileTap={{ scale: 0.97 }}
                onClick={(e) => { e.stopPropagation(); setAnalyzeOpen(true); }}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/20 text-[10px] font-bold text-emerald-400 transition-all"
              >
                <Zap className="w-3.5 h-3.5" /> Analyze Changes
              </motion.button>
              {/* Cargador de Packs */}
              <motion.button
                whileTap={{ scale: 0.97 }}
                onClick={(e) => { e.stopPropagation(); setPackModalOpen(true); }}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-violet-500/10 hover:bg-violet-500/20 border border-violet-500/20 text-[10px] font-bold text-violet-400 transition-all"
              >
                Cargar Pack de Configuración
              </motion.button>
              {/* Fast Scan */}
              <motion.button
                onClick={(e) => launchTerm('sentinel fast-scan', e)}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-blue-500/10 hover:bg-blue-500/20 border border-blue-500/20 text-[10px] font-bold text-blue-400 transition-all"
              >
                <TermIcon className="w-3.5 h-3.5" /> Fast Scan
              </motion.button>
            </div>
          </div>
        </div>
      </motion.div>

      {/* Terminals & Modals */}
      <SentinelTerminal isOpen={termOpen} onClose={() => setTermOpen(false)} command={termCmd} repoName={repo.github_full_name} />
      <SandboxResultModal isOpen={analyzeOpen} onClose={() => setAnalyzeOpen(false)} repoId={repo.id} repoName={repo.github_full_name} />
      <PackLoaderModal isOpen={packModalOpen} onClose={() => setPackModalOpen(false)} repoId={repo.id} onUpdated={() => window.location.reload()} />
      <ProtectedFilesModal isOpen={protectedOpen} onClose={() => setProtectedOpen(false)} repoId={repo.id} />

      {/* Install Guardian Modal */}
      <AnimatePresence>
        {showGuardianModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-6 bg-black/70 backdrop-blur-md">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0, scale: 0.95 }}
              className="w-full max-w-xl bg-[#0d0d0f] border border-[#2a2a30] rounded-2xl shadow-2xl overflow-hidden"
            >
              <div className="px-5 py-4 border-b border-[#2a2a30] bg-[#111114] flex items-center justify-between">
                <span className="text-[11px] font-mono font-bold tracking-widest uppercase text-amber-400">Install Sandbox Guardian</span>
                <button onClick={() => setShowGuardianModal(false)} className="p-1.5 rounded hover:bg-white/5 text-zinc-500 hover:text-white transition-colors">✕</button>
              </div>

              <div className="p-5 space-y-4">
                {guardianStep === 'info' && (
                  <>
                    <p className="text-[12px] text-zinc-300 leading-relaxed">
                      Installing the <span className="text-amber-300 font-bold">Sentinel Sandbox</span> will add a GitHub Actions workflow to <span className="font-mono text-emerald-400">{repo.github_full_name}</span> that automatically analyzes every Pull Request in an isolated Docker container.
                    </p>
                    <div className="bg-amber-500/5 border border-amber-500/20 rounded-xl p-4 space-y-2">
                      <p className="text-[11px] text-amber-300 font-bold uppercase tracking-wider">What this will do:</p>
                      <ul className="space-y-1.5 text-[11px] text-zinc-400">
                        {[
                          'Run on every Pull Request (trigger: pull_request)',
                          'Use minimal Docker image (node:22-slim)',
                          'Drop ALL Linux capabilities (--cap-drop=ALL)',
                          'Only read access (permissions: contents: read)',
                          'Scan for secrets, supply chain attacks, binary injection',
                          'Post a summary to the PR automatically',
                        ].map((item, i) => (
                          <li key={i} className="flex items-start gap-2"><ChevronRight className="w-3 h-3 mt-0.5 text-amber-500 shrink-0" />{item}</li>
                        ))}
                      </ul>
                    </div>
                    <div className="flex items-center justify-between gap-3 pt-2">
                      <button onClick={openGuardianManual} className="flex-1 py-2 rounded-xl border border-white/10 text-[11px] text-zinc-300 hover:bg-white/5 hover:text-white transition-colors font-bold">
                        Copy Template (Manual)
                      </button>
                      <button
                        onClick={() => setGuardianStep('auto_confirm')}
                        className="flex-1 py-2 rounded-xl bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/30 text-amber-400 text-[11px] font-bold transition-all"
                      >
                        Auto-Install (Advanced)
                      </button>
                    </div>
                  </>
                )}

                {guardianStep === 'manual' && (
                  <>
                    <p className="text-[12px] text-zinc-400 leading-relaxed">
                      Copy the contents below and create the file at: <code className="text-emerald-400 text-[11px]">{templatePath}</code> in your repository.
                    </p>
                    <div className="relative bg-black/50 rounded-xl border border-white/10 max-h-52 overflow-y-auto">
                      <pre className="p-3 text-[10px] font-mono text-zinc-400 leading-relaxed whitespace-pre-wrap">{templateContent}</pre>
                    </div>
                    <button onClick={copyTemplate} className="w-full flex items-center justify-center gap-2 py-2 rounded-xl border border-white/10 text-[11px] text-zinc-300 hover:bg-white/5 transition-colors font-bold">
                      {copied ? <><Check className="w-3.5 h-3.5 text-emerald-400" /> Copied!</> : <><Copy className="w-3.5 h-3.5" /> Copy Template</>}
                    </button>
                    <p className="text-[10px] text-zinc-600 text-center">After creating the file, commit and push it. Sentinel will detect it automatically.</p>
                  </>
                )}

                {guardianStep === 'auto_confirm' && (
                  <>
                    <div className="bg-red-500/5 border border-red-500/20 rounded-xl p-4 space-y-2">
                      <p className="text-[11px] text-red-300 font-bold uppercase tracking-wider">⚠️ Auto-Install Requires:</p>
                      <ul className="space-y-1.5 text-[11px] text-zinc-400">
                        <li className="flex items-start gap-2"><ChevronRight className="w-3 h-3 mt-0.5 text-red-400 shrink-0" />gh CLI with <code className="text-amber-300">contents: write</code> access</li>
                        <li className="flex items-start gap-2"><ChevronRight className="w-3 h-3 mt-0.5 text-red-400 shrink-0" />Git push access to the repository</li>
                        <li className="flex items-start gap-2"><ChevronRight className="w-3 h-3 mt-0.5 text-red-400 shrink-0" />A local path linked to this repository</li>
                      </ul>
                    </div>
                    <p className="text-[12px] text-zinc-400">
                      Sentinel will create <code className="text-emerald-400">.github/workflows/sentinel-sandbox.yml</code>, commit it, and push to your remote. <span className="text-white font-bold">No other files will be modified.</span>
                    </p>
                    <div className="flex gap-3 pt-2">
                      <button onClick={() => setGuardianStep('info')} className="flex-1 py-2 rounded-xl border border-white/10 text-[11px] text-zinc-400 hover:bg-white/5 transition-colors">← Back</button>
                      <button onClick={installGuardianAuto} className="flex-1 py-2 rounded-xl bg-red-500/20 hover:bg-red-500/30 border border-red-500/30 text-red-300 text-[11px] font-bold transition-all">
                        I Understand — Auto-Install
                      </button>
                    </div>
                  </>
                )}

                {guardianStep === 'auto_done' && (
                  <div className="text-center py-6 space-y-3">
                    <div className="w-12 h-12 rounded-full bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center mx-auto">
                      <ShieldCheck className="w-6 h-6 text-emerald-400" />
                    </div>
                    <p className="text-sm font-bold text-emerald-400">Sandbox Guardian Installed!</p>
                    <p className="text-[11px] text-zinc-500">The workflow has been committed and pushed. It will activate on the next Pull Request.</p>
                    <button onClick={() => setShowGuardianModal(false)} className="px-4 py-2 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-[11px] font-bold hover:bg-emerald-500/20 transition-all">Done</button>
                  </div>
                )}
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* Sandbox Toggle Confirmation */}
      <AnimatePresence>
        {showDisableConfirm && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-6 bg-black/70 backdrop-blur-md">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0, scale: 0.95 }}
              className="w-full max-w-sm bg-[#0d0d0f] border border-[#2a2a30] rounded-2xl shadow-2xl p-5 space-y-4"
            >
              <p className="text-sm font-bold text-white">
                {sandboxEnabled ? 'Disable Sandbox Guardian?' : 'Enable Sandbox Guardian?'}
              </p>
              <p className="text-[12px] text-zinc-400 leading-relaxed">
                {sandboxEnabled
                  ? 'This will pause automated sandbox scanning for this repository. You can re-enable it anytime.'
                  : 'This will re-activate the Sentinel Sandbox workflow for this repository.'}
              </p>
              <div className="flex gap-3">
                <button onClick={() => setShowDisableConfirm(false)} className="flex-1 py-2 rounded-xl border border-white/10 text-[11px] text-zinc-400 hover:bg-white/5 transition-colors">Cancel</button>
                <button
                  onClick={() => { setSandboxEnabled(!sandboxEnabled); setShowDisableConfirm(false); }}
                  className={`flex-1 py-2 rounded-xl text-[11px] font-bold transition-all border ${sandboxEnabled
                    ? 'bg-red-500/20 border-red-500/30 text-red-300 hover:bg-red-500/30'
                    : 'bg-emerald-500/20 border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/30'}`}
                >
                  {sandboxEnabled ? 'Yes, Disable' : 'Yes, Enable'}
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </>
  );
};

export default RepoCard;