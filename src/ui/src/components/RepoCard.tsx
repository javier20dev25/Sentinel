import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { GitBranch, ShieldCheck, ShieldAlert, Clock, Scan, MoreVertical, Terminal as TermIcon, Shield, BugOff, Activity } from 'lucide-react';
import { api } from '../lib/api';
import { SentinelTerminal } from './SentinelTerminal';
import { ScoreRing } from './ScoreRing';
import { DependencyAudit } from './DependencyAudit';

interface RepoCardProps { repo: any; }

const RepoCard: React.FC<RepoCardProps> = ({ repo }) => {
  const isSafe = repo.status === 'SAFE';
  const [showMenu, setShowMenu] = useState(false);
  
  // Terminal State
  const [termOpen, setTermOpen] = useState(false);
  const [termCmd, setTermCmd] = useState('');

  const [commits, setCommits] = useState<any[]>([]);

  useEffect(() => {
    const fetchCommits = async () => {
      try {
        const res = await api.get(`/api/repositories/${repo.id}/commits`);
        setCommits(res.data.commits || []);
      } catch (err) {}
    };
    fetchCommits();
  }, [repo.id]);

  const latestCommit = commits[0];

  const launchTerm = (cmd: string, e?: React.MouseEvent) => {
    if(e) e.stopPropagation();
    setTermCmd(cmd);
    setTermOpen(true);
    setShowMenu(false);
  };

  const repoName = repo.github_full_name?.includes('/') ? repo.github_full_name.split('/')[1] : repo.github_full_name || 'Unknown Repo';

  return (
    <>
      <motion.div whileHover={{ y: -3 }} className={`glass rounded-[28px] border p-6 relative cursor-pointer transition-colors ${isSafe ? 'border-white/5 hover:border-emerald-500/20' : 'border-red-500/20 bg-red-500/[0.03]'}`}>
        <div className={`absolute -top-12 -right-12 w-40 h-40 blur-[80px] opacity-20 rounded-full ${isSafe ? 'bg-emerald-500' : 'bg-red-500'}`} />

        <div className="relative z-10">
          <div className="flex items-start justify-between mb-5">
            <div className="w-12 h-12 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-center">
              <GitBranch className="w-5 h-5 text-zinc-500" />
            </div>
            
            <div className="flex items-center gap-2">
              <div className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[9px] font-black uppercase tracking-widest border ${isSafe ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' : 'bg-red-500/10 text-red-400 border-red-500/20'}`}>
                {isSafe ? <ShieldCheck className="w-3 h-3" /> : <ShieldAlert className="w-3 h-3" />}
                {repo.status}
              </div>
              
              <div className="relative">
                <button onClick={(e) => { e.stopPropagation(); setShowMenu(!showMenu); }} className="p-1.5 rounded-full hover:bg-white/10 text-zinc-400 transition-colors">
                  <MoreVertical className="w-4 h-4" />
                </button>
                <AnimatePresence>
                  {showMenu && (
                    <motion.div initial={{ opacity: 0, scale: 0.9, y: 5 }} animate={{ opacity: 1, scale: 1, y: 0 }} exit={{ opacity: 0, scale: 0.9, y: 5 }} className="absolute right-0 mt-2 w-48 bg-[#18181b] border border-[#2a2a30] rounded-xl shadow-2xl py-1 z-50">
                      <button onClick={(e) => launchTerm('sentinel scan', e)} className="w-full flex items-center gap-2 px-3 py-2 text-[11px] text-zinc-300 hover:bg-white/5 hover:text-white transition-colors">
                        <Scan className="w-3.5 h-3.5" /> Full Scope Scan
                      </button>
                      <button onClick={(e) => launchTerm('sentinel quarantine --pr', e)} className="w-full flex items-center gap-2 px-3 py-2 text-[11px] text-zinc-300 hover:bg-white/5 hover:text-white transition-colors">
                        <Shield className="w-3.5 h-3.5 text-amber-500" /> Quarantine Last PR
                      </button>
                      <button onClick={(e) => launchTerm('sentinel block --deps', e)} className="w-full flex items-center gap-2 px-3 py-2 text-[11px] text-zinc-300 hover:bg-white/5 hover:text-white transition-colors">
                        <BugOff className="w-3.5 h-3.5 text-red-500" /> Detect Typosquatting
                      </button>
                      <button onClick={async (e) => {
                        e.stopPropagation();
                        if (confirm(`Are you sure you want to forget this repository? Local logs will be erased.`)) {
                          try {
                            await api.delete(`/api/repositories/${repo.id}`);
                            window.location.reload();
                          } catch (err) {}
                        }
                      }} className="w-full flex items-center gap-2 px-3 py-2 text-[11px] text-zinc-300 hover:bg-red-500/10 hover:text-red-400 transition-colors border-t border-white/5 mt-1">
                        <ShieldAlert className="w-3.5 h-3.5" /> Forget Repository
                      </button>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            </div>
          </div>

          <div className="mb-5 flex items-center justify-between">
            <div>
              <h3 className="text-base font-bold text-white truncate">{repoName}</h3>
              <p className="text-[11px] text-zinc-600 font-medium truncate mt-0.5">{repo.github_full_name}</p>
            </div>
            {repo.score !== undefined && (
              <ScoreRing score={repo.score} />
            )}
          </div>

          {/* Aura Monitor Insights */}
          <div className="mb-5 space-y-3">
            <div className="flex items-center justify-between p-2.5 rounded-2xl bg-blue-500/5 border border-blue-500/10 hover:bg-blue-500/10 transition-colors cursor-help">
              <div className="flex items-center gap-2">
                <Activity className="w-3.5 h-3.5 text-blue-400" />
                <p className="text-[10px] font-black text-white uppercase tracking-widest">Aura Monitor</p>
              </div>
              <p className="text-[9px] font-bold text-blue-300/60 uppercase">Live</p>
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

          <div className="flex items-center justify-between pt-4 border-t border-white/[0.04]">
            <div className="flex items-center gap-1.5 text-[10px] text-zinc-600 font-bold">
              <Clock className="w-3 h-3" />
              {repo.last_scan_at ? new Date(repo.last_scan_at).toLocaleString() : 'Never scanned'}
            </div>
            <motion.button onClick={(e) => launchTerm('sentinel fast-scan', e)} className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-blue-500/10 hover:bg-blue-500/20 border border-blue-500/20 text-[10px] font-bold text-blue-400 transition-all">
              <TermIcon className="w-3.5 h-3.5" /> Fast Scan
            </motion.button>
          </div>
        </div>
      </motion.div>
      <SentinelTerminal isOpen={termOpen} onClose={() => setTermOpen(false)} command={termCmd} repoName={repo.github_full_name} />
    </>
  );
};

export default RepoCard;