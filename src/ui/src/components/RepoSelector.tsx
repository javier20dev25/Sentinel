import React, { useState, useEffect, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Search, GitBranch, Lock, Globe, Check, Loader2, Shield, ChevronRight } from 'lucide-react';
import axios from 'axios';

const API = 'http://localhost:3001';

interface GHRepo {
  name: string;
  fullName: string;
  description: string;
  visibility: string;
  updatedAt: string;
}

interface RepoSelectorProps {
  username: string;
  onComplete: () => void;
}

const RepoSelector: React.FC<RepoSelectorProps> = ({ username, onComplete }) => {
  const [repos, setRepos] = useState<GHRepo[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [search, setSearch] = useState('');
  const [linking, setLinking] = useState(false);

  useEffect(() => {
    fetchRepos();
  }, []);

  const fetchRepos = async () => {
    setLoading(true);
    try {
      const { data } = await axios.get(`${API}/api/github/repos`);
      setRepos(data);
    } catch (e) {
      console.error('Failed to fetch repos:', e);
    } finally {
      setLoading(false);
    }
  };

  const filtered = useMemo(() => {
    if (!search.trim()) return repos;
    const q = search.toLowerCase();
    return repos.filter(r =>
      r.name.toLowerCase().includes(q) ||
      r.fullName.toLowerCase().includes(q) ||
      r.description?.toLowerCase().includes(q)
    );
  }, [repos, search]);

  const toggle = (fullName: string) => {
    setSelected(prev => {
      const next = new Set(prev);
      if (next.has(fullName)) next.delete(fullName);
      else next.add(fullName);
      return next;
    });
  };

  const selectAll = () => {
    if (selected.size === filtered.length) {
      setSelected(new Set());
    } else {
      setSelected(new Set(filtered.map(r => r.fullName)));
    }
  };

  const handleLink = async () => {
    if (selected.size === 0) return;
    setLinking(true);
    try {
      await axios.post(`${API}/api/repositories/bulk`, { repos: Array.from(selected) });
      onComplete();
    } catch (e) {
      console.error('Failed to link repos:', e);
    } finally {
      setLinking(false);
    }
  };

  return (
    <div className="h-screen flex flex-col relative overflow-hidden" style={{ backgroundColor: 'var(--color-background)' }}>
      {/* Background */}
      <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-blue-500/5 blur-[150px] rounded-full" />

      {/* Header */}
      <header className="shrink-0 px-8 py-6 border-b border-white/[0.06]">
        <div className="flex items-center gap-3 mb-1">
          <div className="w-8 h-8 rounded-xl bg-gradient-to-br from-blue-500 to-indigo-600 flex items-center justify-center">
            <Shield className="w-4 h-4 text-white" />
          </div>
          <h1 className="text-lg font-black tracking-tight text-white">SENTINEL</h1>
        </div>
        <p className="text-xs text-zinc-500 ml-11">
          Welcome, <span className="text-white font-semibold">{username}</span>. Select the repositories you want to protect.
        </p>
      </header>

      {/* Search & Controls */}
      <div className="shrink-0 px-8 py-4 flex items-center gap-4 border-b border-white/[0.04]">
        <div className="flex-1 relative">
          <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-600" />
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search repositories..."
            className="w-full bg-white/[0.04] border border-white/[0.08] rounded-2xl pl-11 pr-5 py-3 text-sm text-white placeholder-zinc-600 focus:outline-none focus:ring-2 focus:ring-blue-500/30 focus:border-blue-500/30 transition-all"
          />
        </div>
        <button
          onClick={selectAll}
          className="px-4 py-3 rounded-2xl border border-white/10 text-xs font-bold text-zinc-400 hover:text-white hover:bg-white/5 transition-colors whitespace-nowrap"
        >
          {selected.size === filtered.length && filtered.length > 0 ? 'Deselect All' : 'Select All'}
        </button>
      </div>

      {/* Repo List */}
      <div className="flex-1 overflow-y-auto px-8 py-4">
        {loading ? (
          <div className="flex flex-col items-center justify-center py-20">
            <Loader2 className="w-8 h-8 text-blue-400 animate-spin mb-4" />
            <p className="text-sm text-zinc-500">Loading your repositories...</p>
          </div>
        ) : filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20">
            <GitBranch className="w-10 h-10 text-zinc-700 mb-4" />
            <p className="text-sm text-zinc-500">{search ? 'No matches found' : 'No repositories found in your account'}</p>
          </div>
        ) : (
          <div className="space-y-2">
            {filtered.map((repo, i) => {
              const isSelected = selected.has(repo.fullName);
              return (
                <motion.button
                  key={repo.fullName}
                  onClick={() => toggle(repo.fullName)}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: i * 0.02 }}
                  className={`w-full flex items-center gap-4 p-4 rounded-2xl border text-left transition-all ${
                    isSelected
                      ? 'border-blue-500/30 bg-blue-500/10'
                      : 'border-white/[0.06] bg-white/[0.02] hover:bg-white/[0.05] hover:border-white/10'
                  }`}
                >
                  {/* Checkbox */}
                  <div className={`w-5 h-5 rounded-lg border-2 flex items-center justify-center shrink-0 transition-all ${
                    isSelected
                      ? 'bg-blue-500 border-blue-500'
                      : 'border-zinc-600'
                  }`}>
                    {isSelected && <Check className="w-3 h-3 text-white" />}
                  </div>

                  {/* Info */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <p className="text-sm font-semibold text-white truncate">{repo.name}</p>
                      {repo.visibility === 'PRIVATE' ? (
                        <Lock className="w-3 h-3 text-amber-500/60 shrink-0" />
                      ) : (
                        <Globe className="w-3 h-3 text-zinc-600 shrink-0" />
                      )}
                    </div>
                    {repo.description && (
                      <p className="text-[11px] text-zinc-500 truncate mt-0.5">{repo.description}</p>
                    )}
                  </div>

                  {/* Updated */}
                  <span className="text-[10px] text-zinc-600 shrink-0 font-medium">
                    {new Date(repo.updatedAt).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}
                  </span>
                </motion.button>
              );
            })}
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="shrink-0 px-8 py-5 border-t border-white/[0.06] backdrop-blur-xl flex items-center justify-between" style={{ backgroundColor: 'rgba(10, 10, 12, 0.8)' }}>
        <p className="text-xs text-zinc-500">
          <span className="text-white font-bold">{selected.size}</span> of {repos.length} repositories selected
        </p>
        <motion.button
          onClick={handleLink}
          disabled={selected.size === 0 || linking}
          whileHover={{ scale: 1.02 }}
          whileTap={{ scale: 0.97 }}
          className="flex items-center gap-2 px-7 py-3.5 rounded-2xl bg-blue-500 hover:bg-blue-400 disabled:opacity-40 disabled:cursor-not-allowed text-white text-sm font-bold shadow-lg shadow-blue-500/20 transition-colors"
        >
          {linking ? (
            <><Loader2 className="w-4 h-4 animate-spin" /> Linking...</>
          ) : (
            <><Shield className="w-4 h-4" /> Start Monitoring <ChevronRight className="w-4 h-4" /></>
          )}
        </motion.button>
      </div>
    </div>
  );
};

export default RepoSelector;
