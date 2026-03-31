import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { motion } from 'framer-motion';
import { ShieldAlert, ShieldCheck, GitBranch, Plus, LayoutDashboard, Loader2 } from 'lucide-react';
import RepoCard from './RepoCard';

interface DashboardProps {
  repos: any[];
  loading: boolean;
  onAddProject: () => void;
}

const Dashboard: React.FC<DashboardProps> = ({ repos, loading, onAddProject }) => {
  const [globalScanning, setGlobalScanning] = useState(false);
  const safeCount = repos.filter(r => r.status === 'SAFE').length;
  const infectedCount = repos.filter(r => r.status !== 'SAFE').length;

  useEffect(() => {
    const handleIntent = async (e: any) => {
      const intent = e.detail;
      if (intent.action === 'scan-all') {
        if (repos.length === 0) return;
        setGlobalScanning(true);
        try {
          // Trigger scan for all repos in parallel
          await Promise.all(
            repos.map(repo => 
              axios.post(`http://localhost:3001/api/repositories/${repo.id}/scan`)
            )
          );
          new Notification("Sentinel: Global Scan Complete", {
            body: `Successfully scanned ${repos.length} repositories.`,
            icon: 'info'
          });
        } catch (err) {
          console.error("Failed global scan", err);
        } finally {
          setGlobalScanning(false);
        }
      }
    };

    window.addEventListener('sentinel-intent', handleIntent);
    return () => window.removeEventListener('sentinel-intent', handleIntent);
  }, [repos]);

  return (
    <div className="space-y-8">
      {/* Stats Row */}
      <div className="grid grid-cols-3 gap-4">
        {[
          {
            label: 'Total Repos',
            value: repos.length,
            icon: GitBranch,
            color: 'text-blue-400',
            bg: 'bg-blue-500/10 border-blue-500/20',
          },
          {
            label: 'Protected',
            value: safeCount,
            icon: ShieldCheck,
            color: 'text-emerald-400',
            bg: 'bg-emerald-500/10 border-emerald-500/20',
          },
          {
            label: 'Threats Found',
            value: infectedCount,
            icon: ShieldAlert,
            color: 'text-red-400',
            bg: 'bg-red-500/10 border-red-500/20',
          },
        ].map((stat, i) => (
          <motion.div
            key={stat.label}
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.07 }}
            className={`stat-card border ${stat.bg} flex items-center gap-4`}
          >
            <div className={`w-12 h-12 rounded-2xl ${stat.bg} border flex items-center justify-center shrink-0`}>
              <stat.icon className={`w-5 h-5 ${stat.color}`} />
            </div>
            <div>
              <p className="text-3xl font-black text-white leading-none">{stat.value}</p>
              <p className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest mt-1">{stat.label}</p>
            </div>
          </motion.div>
        ))}
      </div>

      {/* Repo Section Header */}
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-3">
            <h2 className="text-lg font-bold text-white">Monitored Repositories</h2>
            {globalScanning && (
              <div className="flex items-center gap-1.5 px-3 py-1 bg-blue-500/10 border border-blue-500/20 text-blue-400 rounded-full text-xs font-bold animate-pulse">
                <Loader2 className="w-3 h-3 animate-spin" />
                Global Scan Active
              </div>
            )}
          </div>
          <p className="text-xs text-zinc-600 mt-0.5">
            {loading ? 'Loading...' : repos.length === 0 ? 'No repositories linked yet' : `Last updated ${new Date().toLocaleTimeString()}`}
          </p>
        </div>
        <motion.button
          onClick={onAddProject}
          whileHover={{ scale: 1.03 }}
          whileTap={{ scale: 0.97 }}
          className="flex items-center gap-2 px-5 py-2.5 rounded-2xl bg-blue-500/10 border border-blue-500/20 text-blue-400 text-sm font-bold hover:bg-blue-500/20 transition-colors"
        >
          <Plus className="w-4 h-4" />
          Add Repository
        </motion.button>
      </div>

      {/* Skeletons */}
      {loading && repos.length === 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-5">
          {[1, 2, 3].map(i => (
            <div key={i} className="h-52 glass rounded-[28px] border border-white/5 animate-pulse" />
          ))}
        </div>
      )}

      {/* Empty State */}
      {!loading && repos.length === 0 && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex flex-col items-center justify-center py-24 glass rounded-[32px] border border-dashed border-white/10"
        >
          <div className="w-20 h-20 rounded-3xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center mb-6">
            <LayoutDashboard className="w-9 h-9 text-blue-400/50" />
          </div>
          <h3 className="text-xl font-bold text-white mb-2">No Repositories Active</h3>
          <p className="text-sm text-zinc-500 text-center max-w-xs leading-relaxed mb-6">
            Link a local folder to begin real-time threat detection, secret scanning, and supply-chain analysis.
          </p>
          <motion.button
            onClick={onAddProject}
            whileHover={{ scale: 1.04 }}
            whileTap={{ scale: 0.97 }}
            className="flex items-center gap-2 px-6 py-3 rounded-2xl bg-blue-500 hover:bg-blue-400 text-white text-sm font-bold shadow-lg shadow-blue-500/20 transition-colors"
          >
            <Plus className="w-4 h-4" />
            Link First Repository
          </motion.button>
        </motion.div>
      )}

      {/* Repo Grid */}
      {repos.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-5">
          {repos.map((repo, idx) => (
            <motion.div
              key={repo.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: idx * 0.07 }}
            >
              <RepoCard repo={repo} />
            </motion.div>
          ))}
        </div>
      )}
    </div>
  );
};

export default Dashboard;
