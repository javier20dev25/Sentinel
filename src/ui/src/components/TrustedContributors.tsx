import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { motion, AnimatePresence } from 'framer-motion';
import { Users, Plus, Trash2, Loader2, GitBranch as Github, ShieldCheck } from 'lucide-react';

const API = 'http://localhost:3001';

export const TrustedContributors: React.FC = () => {
  const [trusted, setTrusted] = useState<any[]>([]);
  const [suggestions, setSuggestions] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadingSuggestions, setLoadingSuggestions] = useState(false);
  const [newUser, setNewUser] = useState('');
  const [adding, setAdding] = useState(false);

  const fetchTrusted = async () => {
    try {
      const { data } = await axios.get(`${API}/api/trusted`);
      setTrusted(data || []);
    } catch (e) {} finally { setLoading(false); }
  };

  const fetchSuggestions = async () => {
    setLoadingSuggestions(true);
    try {
      const { data } = await axios.get(`${API}/api/github/collaborators`);
      setSuggestions(data || []);
    } catch (e) {} finally { setLoadingSuggestions(false); }
  };

  useEffect(() => {
    fetchTrusted();
  }, []);

  const handleAdd = async (username: string) => {
    if (!username.trim()) return;
    setAdding(true);
    try {
      await axios.post(`${API}/api/trusted`, { username: username.trim() });
      await fetchTrusted();
      setNewUser('');
    } catch (e) {} finally { setAdding(false); }
  };

  const handleRemove = async (username: string) => {
    try {
      await axios.delete(`${API}/api/trusted/${username}`);
      await fetchTrusted();
    } catch (e) {}
  };

  return (
    <div className="glass rounded-[28px] border border-emerald-500/10 p-7 space-y-5 relative overflow-hidden">
      <div className="absolute -top-10 -right-10 w-40 h-40 bg-emerald-500/10 blur-[50px] rounded-full pointer-events-none" />

      <div className="flex items-center gap-3 relative z-10 mb-2">
        <div className="w-10 h-10 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
          <Users className="w-5 h-5 text-emerald-400" />
        </div>
        <div className="flex-1">
          <h3 className="text-base font-bold text-white">Trusted Contributors</h3>
          <p className="text-xs text-zinc-500">Exempt these users from strict malware blocking (lowers severity)</p>
        </div>
        <button 
          onClick={fetchSuggestions}
          disabled={loadingSuggestions}
          className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-white/5 hover:bg-white/10 text-xs font-bold text-white transition-colors border border-white/10"
        >
          {loadingSuggestions ? <Loader2 className="w-3 h-3 animate-spin" /> : <Github className="w-3 h-3" />}
          Import
        </button>
      </div>

      <div className="flex gap-2 relative z-10">
        <input
          type="text"
          value={newUser}
          onChange={e => setNewUser(e.target.value)}
          placeholder="GitHub username"
          onKeyDown={e => e.key === 'Enter' && handleAdd(newUser)}
          className="flex-1 bg-white/[0.05] border border-white/10 rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none focus:ring-2 focus:ring-emerald-500/40 focus:border-emerald-500/40 transition-all font-mono"
        />
        <button
          onClick={() => handleAdd(newUser)}
          disabled={adding || !newUser.trim()}
          className="px-4 py-2.5 rounded-xl font-bold text-sm bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-400 transition-colors border border-emerald-500/20 disabled:opacity-50 flex items-center gap-2"
        >
          {adding ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
          Add
        </button>
      </div>

      {suggestions.length > 0 && (
        <div className="relative z-10 flex flex-wrap gap-2 pt-2">
          <span className="text-[10px] uppercase font-bold text-zinc-600 mt-1">Suggestions:</span>
          {suggestions.filter(s => !trusted.find(t => t.username === s)).slice(0, 5).map(s => (
            <button
              key={s}
              onClick={() => handleAdd(s)}
              className="px-2 py-0.5 rounded-lg bg-teal-500/10 hover:bg-teal-500/20 text-teal-300 text-xs border border-teal-500/20 transition-colors"
            >
              + {s}
            </button>
          ))}
        </div>
      )}

      <div className="relative z-10 space-y-2 mt-4">
        {loading ? (
          <div className="flex justify-center p-4"><Loader2 className="w-5 h-5 text-emerald-500 animate-spin" /></div>
        ) : trusted.length === 0 ? (
          <p className="text-xs text-zinc-500 text-center py-4 italic">No trusted contributors yet</p>
        ) : (
          <AnimatePresence>
            {trusted.map((t) => (
              <motion.div
                key={t.username}
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                className="flex items-center justify-between p-3 rounded-xl bg-white/[0.02] border border-white/5"
              >
                <div className="flex items-center gap-3">
                  <img src={`https://github.com/${t.username}.png?size=40`} className="w-8 h-8 rounded-full border border-emerald-500/30" alt="" />
                  <span className="text-sm font-semibold text-white">{t.username}</span>
                  <ShieldCheck className="w-4 h-4 text-emerald-500 ml-2" />
                </div>
                <button
                  onClick={() => handleRemove(t.username)}
                  className="p-2 text-zinc-500 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition-all"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </motion.div>
            ))}
          </AnimatePresence>
        )}
      </div>
    </div>
  );
};
