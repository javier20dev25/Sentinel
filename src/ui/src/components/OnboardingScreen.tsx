import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, GitBranch as Github, Download, CheckCircle2, AlertTriangle, Loader2, Terminal, ExternalLink } from 'lucide-react';
import axios from 'axios';

const API = 'http://localhost:3001';

interface SystemStatus {
  git: { installed: boolean; version: string | null };
  gh: { installed: boolean; version: string | null };
}

interface OnboardingProps {
  onAuthComplete: (username: string) => void;
}

const OnboardingScreen: React.FC<OnboardingProps> = ({ onAuthComplete }) => {
  const [step, setStep] = useState<'checking' | 'deps' | 'auth' | 'logging-in'>('checking');
  const [system, setSystem] = useState<SystemStatus | null>(null);
  const [installing, setInstalling] = useState(false);
  const [installResult, setInstallResult] = useState<{ success: boolean; message: string } | null>(null);
  const [authError, setAuthError] = useState('');

  React.useEffect(() => {
    checkSystem();
  }, []);

  const checkSystem = async () => {
    setStep('checking');
    try {
      const { data } = await axios.get(`${API}/api/system/check`);
      setSystem(data);
      if (!data.git.installed || !data.gh.installed) {
        setStep('deps');
      } else {
        // All deps ok, check auth
        const { data: auth } = await axios.get(`${API}/api/auth/status`);
        if (auth.authenticated) {
          onAuthComplete(auth.username);
        } else {
          setStep('auth');
        }
      }
    } catch {
      setStep('deps');
    }
  };

  const handleInstallGH = async () => {
    setInstalling(true);
    setInstallResult(null);
    try {
      const { data } = await axios.post(`${API}/api/system/install-gh`);
      setInstallResult(data);
      if (data.success) {
        setTimeout(checkSystem, 2000);
      }
    } catch {
      setInstallResult({ success: false, message: 'Error connecting to Sentinel backend.' });
    } finally {
      setInstalling(false);
    }
  };

  const handleLogin = async () => {
    setStep('logging-in');
    setAuthError('');
    try {
      const { data } = await axios.post(`${API}/api/auth/login`);
      if (data.success) {
        onAuthComplete(data.username);
      } else {
        setAuthError(data.message || 'Login failed.');
        setStep('auth');
      }
    } catch {
      setAuthError('Could not connect to Sentinel backend.');
      setStep('auth');
    }
  };

  return (
    <div className="h-screen flex items-center justify-center relative overflow-hidden" style={{ backgroundColor: 'var(--color-background)' }}>
      {/* Background effects */}
      <div className="absolute inset-0">
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-[600px] h-[600px] bg-blue-500/5 blur-[150px] rounded-full" />
        <div className="absolute bottom-0 right-0 w-[400px] h-[400px] bg-indigo-500/5 blur-[120px] rounded-full" />
      </div>

      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        className="relative z-10 w-full max-w-md mx-auto text-center"
      >
        {/* Shield Logo */}
        <motion.div
          className="w-20 h-20 mx-auto mb-8 rounded-[28px] bg-gradient-to-br from-blue-500 to-indigo-600 flex items-center justify-center shadow-2xl shadow-blue-500/30"
          initial={{ y: -20 }}
          animate={{ y: 0 }}
          transition={{ type: 'spring', damping: 12 }}
        >
          <Shield className="w-10 h-10 text-white" />
        </motion.div>

        <h1 className="text-4xl font-black tracking-tight text-white mb-2">SENTINEL</h1>
        <p className="text-sm text-zinc-500 mb-10">Security Guardian for your GitHub Repositories</p>

        <AnimatePresence mode="wait">
          {/* Checking System */}
          {step === 'checking' && (
            <motion.div
              key="checking"
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -16 }}
              className="space-y-4"
            >
              <Loader2 className="w-8 h-8 mx-auto text-blue-400 animate-spin" />
              <p className="text-sm text-zinc-400">Checking system requirements...</p>
            </motion.div>
          )}

          {/* Missing Dependencies */}
          {step === 'deps' && system && (
            <motion.div
              key="deps"
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -16 }}
              className="glass rounded-[32px] border border-white/10 p-8 text-left space-y-5"
            >
              <div className="text-center mb-2">
                <h2 className="text-lg font-bold text-white">System Requirements</h2>
                <p className="text-xs text-zinc-500 mt-1">Sentinel needs these tools to protect your repos</p>
              </div>

              {/* Git Status */}
              <div className={`flex items-center gap-4 p-4 rounded-2xl border ${
                system.git.installed
                  ? 'border-emerald-500/20 bg-emerald-500/5'
                  : 'border-red-500/20 bg-red-500/5'
              }`}>
                <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${
                  system.git.installed ? 'bg-emerald-500/15' : 'bg-red-500/15'
                }`}>
                  {system.git.installed
                    ? <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                    : <AlertTriangle className="w-5 h-5 text-red-400" />}
                </div>
                <div className="flex-1">
                  <p className="text-sm font-bold text-white">Git</p>
                  <p className="text-[10px] text-zinc-500">
                    {system.git.installed ? `v${system.git.version} — Installed` : 'Not found — Please install from git-scm.com'}
                  </p>
                </div>
              </div>

              {/* GH CLI Status */}
              <div className={`flex items-center gap-4 p-4 rounded-2xl border ${
                system.gh.installed
                  ? 'border-emerald-500/20 bg-emerald-500/5'
                  : 'border-amber-500/20 bg-amber-500/5'
              }`}>
                <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${
                  system.gh.installed ? 'bg-emerald-500/15' : 'bg-amber-500/15'
                }`}>
                  {system.gh.installed
                    ? <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                    : <Terminal className="w-5 h-5 text-amber-400" />}
                </div>
                <div className="flex-1">
                  <p className="text-sm font-bold text-white">GitHub CLI (gh)</p>
                  <p className="text-[10px] text-zinc-500">
                    {system.gh.installed ? `v${system.gh.version} — Installed` : 'Required for repository access'}
                  </p>
                </div>
                {!system.gh.installed && (
                  <motion.button
                    onClick={handleInstallGH}
                    disabled={installing}
                    whileTap={{ scale: 0.95 }}
                    className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-blue-500 hover:bg-blue-400 text-white text-xs font-bold disabled:opacity-50 transition-colors"
                  >
                    {installing
                      ? <><Loader2 className="w-3 h-3 animate-spin" /> Installing...</>
                      : <><Download className="w-3 h-3" /> Install</>}
                  </motion.button>
                )}
              </div>

              {installResult && (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className={`p-4 rounded-2xl text-xs leading-relaxed border ${
                    installResult.success
                      ? 'bg-emerald-500/5 border-emerald-500/20 text-emerald-300/80'
                      : 'bg-red-500/5 border-red-500/20 text-red-300/80'
                  }`}
                >
                  {installResult.message}
                  {!installResult.success && (
                    <a
                      href="https://cli.github.com"
                      target="_blank"
                      rel="noopener"
                      className="flex items-center gap-1 mt-2 text-blue-400 hover:underline"
                    >
                      <ExternalLink className="w-3 h-3" /> Download GitHub CLI manually
                    </a>
                  )}
                </motion.div>
              )}

              {system.git.installed && system.gh.installed && (
                <motion.button
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  onClick={checkSystem}
                  className="w-full py-3.5 rounded-2xl bg-blue-500 hover:bg-blue-400 text-white text-sm font-bold shadow-lg shadow-blue-500/20 transition-colors"
                >
                  Continue →
                </motion.button>
              )}

              {(!system.git.installed || !system.gh.installed) && (
                <button
                  onClick={checkSystem}
                  className="w-full py-3 rounded-2xl border border-white/10 text-zinc-500 hover:text-white hover:bg-white/5 text-sm font-medium transition-colors"
                >
                  Re-check Requirements
                </button>
              )}
            </motion.div>
          )}

          {/* Login */}
          {step === 'auth' && (
            <motion.div
              key="auth"
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -16 }}
              className="glass rounded-[32px] border border-white/10 p-8 space-y-6"
            >
              <div className="w-16 h-16 mx-auto rounded-2xl bg-zinc-800 border border-white/10 flex items-center justify-center">
                <Github className="w-8 h-8 text-white" />
              </div>
              <div>
                <h2 className="text-lg font-bold text-white">Connect to GitHub</h2>
                <p className="text-xs text-zinc-500 mt-1">
                  Sentinel needs access to your GitHub account to monitor your repositories for threats.
                </p>
              </div>

              {authError && (
                <div className="p-3 rounded-xl bg-red-500/10 border border-red-500/20 text-xs text-red-300/80">
                  {authError}
                </div>
              )}

              <motion.button
                onClick={handleLogin}
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.97 }}
                className="w-full flex items-center justify-center gap-3 py-4 rounded-2xl bg-white text-black font-bold shadow-xl shadow-white/10 hover:bg-zinc-100 transition-colors"
              >
                <Github className="w-5 h-5" />
                Sign in with GitHub
              </motion.button>
              <p className="text-[10px] text-zinc-600 leading-relaxed">
                This will open your browser to authenticate via GitHub CLI. Your credentials are stored locally and never sent to third parties.
              </p>
            </motion.div>
          )}

          {/* Logging In */}
          {step === 'logging-in' && (
            <motion.div
              key="logging"
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -16 }}
              className="space-y-4"
            >
              <Loader2 className="w-8 h-8 mx-auto text-blue-400 animate-spin" />
              <p className="text-sm text-zinc-400">Waiting for GitHub authentication...</p>
              <p className="text-xs text-zinc-600">Complete the login in your browser window.</p>
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>
    </div>
  );
};

export default OnboardingScreen;
