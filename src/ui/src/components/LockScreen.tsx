import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { motion } from 'framer-motion';
import { Shield, Lock, ArrowRight, Loader2, Key } from 'lucide-react';

const API = 'http://localhost:3001';

interface LockScreenProps {
  onUnlocked: (token: string) => void;
}

export const LockScreen: React.FC<LockScreenProps> = ({ onUnlocked }) => {
  const [phase, setPhase] = useState<'checking' | 'setup' | 'login'>('checking');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    checkStatus();
  }, []);

  const checkStatus = async () => {
    try {
      const { data } = await axios.get(`${API}/api/auth/local/status`);
      setPhase(data.setupRequired ? 'setup' : 'login');
    } catch (e: any) {
      setError('Cannot connect to Sentinel Core (Backend dead?)');
      setPhase('login');
    }
  };

  const handleSetup = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    
    if (password.length < 4) {
      setError('Password must be at least 4 characters');
      return;
    }
    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    setLoading(true);
    try {
      const { data } = await axios.post(`${API}/api/auth/local/setup`, { password });
      if (data.token) {
        onUnlocked(data.token);
      }
    } catch (e: any) {
      setError(e.response?.data?.error || 'Setup failed');
    } finally {
      setLoading(false);
    }
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    
    try {
      const { data } = await axios.post(`${API}/api/auth/local/login`, { password });
      if (data.token) {
        onUnlocked(data.token);
      }
    } catch (e: any) {
      setError(e.response?.data?.error || 'Invalid Identity');
    } finally {
      setLoading(false);
    }
  };

  if (phase === 'checking') {
    return (
      <div className="h-screen flex items-center justify-center bg-black">
        <Loader2 className="w-8 h-8 text-blue-500 animate-spin" />
      </div>
    );
  }

  return (
    <div className="h-screen flex items-center justify-center bg-[#09090b] relative overflow-hidden font-sans">
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[500px] h-[500px] bg-blue-500/10 blur-[120px] rounded-full pointer-events-none" />

      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        className="w-full max-w-sm glass border border-white/10 rounded-3xl p-8 relative z-10 mx-4"
      >
        <div className="text-center mb-8">
          <div className="w-16 h-16 mx-auto rounded-2xl bg-gradient-to-br from-blue-500 to-indigo-600 flex items-center justify-center shadow-lg shadow-blue-500/20 mb-6">
            <Shield className="w-8 h-8 text-white" />
          </div>
          <h2 className="text-2xl font-black text-white tracking-tight">Sentinel Core</h2>
          <p className="text-xs text-zinc-500 font-bold uppercase tracking-widest mt-2">
            {phase === 'setup' ? 'Set Master Password' : 'Encrypted Access'}
          </p>
        </div>

        <form onSubmit={phase === 'setup' ? handleSetup : handleLogin} className="space-y-4">
          <div className="relative">
            <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
              <Key className="w-4 h-4 text-zinc-500" />
            </div>
            <div suppressHydrationWarning>
              <input
                type="password"
                placeholder={phase === 'setup' ? 'Create a master password' : 'Enter master password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full bg-black/50 border border-white/10 rounded-xl py-3 pl-10 pr-4 text-white text-sm focus:outline-none focus:border-blue-500/50 transition-colors"
                autoFocus
                autoComplete="off"
                data-lpignore="true"
                data-1p-ignore
              />
            </div>
          </div>

          {phase === 'setup' && (
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                <Lock className="w-4 h-4 text-zinc-500" />
              </div>
              <div suppressHydrationWarning>
                <input
                  type="password"
                  placeholder="Confirm master password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  className="w-full bg-black/50 border border-white/10 rounded-xl py-3 pl-10 pr-4 text-white text-sm focus:outline-none focus:border-blue-500/50 transition-colors"
                  autoComplete="off"
                  data-lpignore="true"
                  data-1p-ignore
                />
              </div>
            </div>
          )}

          {error && (
            <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-xs text-center font-semibold">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading || !password}
            className="w-full py-3 rounded-xl bg-blue-500 hover:bg-blue-600 text-white font-bold text-sm transition-colors flex items-center justify-center gap-2 group disabled:opacity-50"
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : (
              <>
                {phase === 'setup' ? 'Initialize Sentinel' : 'Unlock Framework'}
                <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
              </>
            )}
          </button>
        </form>
      </motion.div>
    </div>
  );
};
