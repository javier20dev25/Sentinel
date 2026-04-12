import React, { useState, useEffect } from 'react';
import { api } from '../lib/api';
import { motion, AnimatePresence } from 'framer-motion';
import { ShieldAlert, GitMerge, Loader2, X, Check } from 'lucide-react';

export const SecurityHardener: React.FC = () => {
  const [switches, setSwitches] = useState({ npmIgnoreScripts: false, globalGitHooks: false, secretScanning: true });
  const [loading, setLoading] = useState(true);
  const [toggling, setToggling] = useState(false);
  const [modalOpen, setModalOpen] = useState(false);

  const fetchStatus = async () => {
    try {
      const { data } = await api.get('/api/hardener/status');
      setSwitches(data);
    } catch (e) {
      console.error('Failed to fetch hardener status', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  const handleToggle = async (key: string, currentValue: boolean) => {
    if (key === 'globalGitHooks' && !currentValue) {
      setModalOpen(true);
      return;
    }
    await executeToggle(key, !currentValue);
  };

  const executeToggle = async (key: string, enable: boolean) => {
    setToggling(true);
    try {
      const { data } = await api.post('/api/hardener/switch', { key, enable });
      if (data.success) {
        setSwitches(prev => ({ ...prev, [key]: data.enabled }));
        setModalOpen(false);
      }
    } catch (e) {
      console.error('Failed to toggle switch', e);
    } finally {
      setToggling(false);
    }
  };

  return (
    <div className="glass rounded-[28px] border border-red-500/10 p-7 space-y-5 relative overflow-hidden">
      {/* Background glow for security section */}
      <div className="absolute -top-10 -right-10 w-40 h-40 bg-red-500/5 blur-[50px] rounded-full pointer-events-none" />

      <div className="flex items-center gap-3 mb-2 relative z-10">
        <div className="w-10 h-10 rounded-2xl bg-red-500/10 border border-red-500/20 flex items-center justify-center">
          <ShieldAlert className="w-5 h-5 text-red-400" />
        </div>
        <div>
          <h3 className="text-base font-bold text-white">System Security Hardener</h3>
          <p className="text-xs text-zinc-500">Global protective switches (Interruptores)</p>
        </div>
      </div>

      {loading ? (
        <div className="flex items-center gap-3 text-xs text-zinc-500 py-4">
          <Loader2 className="w-4 h-4 animate-spin" />
          Reading global configurations...
        </div>
      ) : (
        <div className="space-y-3 relative z-10">
          
          
          {/* Switch 3: Secret Scanning */}
          <div className="flex items-start justify-between py-1 bg-white/[0.02] border border-white/5 p-4 rounded-2xl">
            <div className="flex-1 pr-6">
              <p className="text-sm font-semibold text-white">Enable Secret Scanning (Pre-Push)</p>
              <p className="text-xs text-zinc-500 mt-1 leading-relaxed">
                Globally block commits/pushes if hardcoded secrets are detected (e.g. AWS Keys, Stripe, GitHub Tokens, .env files).
              </p>
            </div>
            
            <button
              onClick={() => handleToggle('secretScanning', switches.secretScanning)}
              disabled={toggling}
              className={`w-12 h-6 rounded-full relative transition-colors duration-200 shrink-0 mt-1 ${
                switches.secretScanning ? 'bg-amber-500' : 'bg-zinc-700 hover:bg-zinc-600'
              } ${toggling ? 'opacity-50 cursor-not-allowed' : ''}`}
            >
              <motion.div
                layout
                className="absolute top-1 w-4 h-4 bg-white rounded-full shadow"
                animate={{ left: switches.secretScanning ? '26px' : '4px' }}
                transition={{ type: 'spring', damping: 20, stiffness: 300 }}
              />
            </button>
          </div>

          {/* Switch 2: Global Git Hooks */}
          <div className="flex items-start justify-between py-1 bg-white/[0.02] border border-white/5 p-4 rounded-2xl">
            <div className="flex-1 pr-6">
              <p className="text-sm font-semibold text-white">Active Git Firewalls (Git Hooks)</p>
              <p className="text-xs text-zinc-500 mt-1 leading-relaxed">
                Re-routes <code className="text-blue-400 font-mono bg-blue-500/10 px-1 py-0.5 rounded">core.hooksPath</code> to Sentinel. 
                Automatically intercept and scan every <span className="font-bold">git push</span> and <span className="font-bold">git merge</span> on your system.
                Safely delegates to your existing Husky hooks afterward.
              </p>
            </div>
            
            <button
              onClick={() => handleToggle('globalGitHooks', switches.globalGitHooks)}
              disabled={toggling}
              className={`w-12 h-6 rounded-full relative transition-colors duration-200 shrink-0 mt-1 ${
                switches.globalGitHooks ? 'bg-blue-500' : 'bg-zinc-700 hover:bg-zinc-600'
              } ${toggling ? 'opacity-50 cursor-not-allowed' : ''}`}
            >
              <motion.div
                layout
                className="absolute top-1 w-4 h-4 bg-white rounded-full shadow"
                animate={{ left: switches.globalGitHooks ? '26px' : '4px' }}
                transition={{ type: 'spring', damping: 20, stiffness: 300 }}
              />
            </button>
          </div>

          {/* Switch 1: NPM Ignore Scripts */}
          <div className="flex items-start justify-between py-1 bg-white/[0.02] border border-white/5 p-4 rounded-2xl">
            <div className="flex-1 pr-6">
              <p className="text-sm font-semibold text-white">Block NPM Lifecycle Scripts</p>
              <p className="text-xs text-zinc-500 mt-1 leading-relaxed">
                Globally enables <code className="text-red-400 font-mono bg-red-500/10 px-1 py-0.5 rounded">ignore-scripts=true</code>.
                Prevents malicious packages from silently running <i>preinstall</i> or <i>postinstall</i> scripts on your machine.
                <span className="block mt-1 text-amber-500/80 font-medium">Warning: May break valid packages that require native C++ compilation (like swc/esbuild).</span>
              </p>
            </div>
            
            <button
              onClick={() => handleToggle('npmIgnoreScripts', switches.npmIgnoreScripts)}
              disabled={toggling}
              className={`w-12 h-6 rounded-full relative transition-colors duration-200 shrink-0 mt-1 ${
                switches.npmIgnoreScripts ? 'bg-red-500' : 'bg-zinc-700 hover:bg-zinc-600'
              } ${toggling ? 'opacity-50 cursor-not-allowed' : ''}`}
            >
              <motion.div
                layout
                className="absolute top-1 w-4 h-4 bg-white rounded-full shadow"
                animate={{ left: switches.npmIgnoreScripts ? '26px' : '4px' }}
                transition={{ type: 'spring', damping: 20, stiffness: 300 }}
              />
            </button>
          </div>

        </div>
      )}

      {/* Explicit Opt-In Modal for Git Hooks */}
      <AnimatePresence>
        {modalOpen && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm -m-7">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="max-w-md w-full glass rounded-3xl border border-blue-500/30 p-6 overflow-hidden relative shadow-2xl"
            >
              <div className="absolute top-0 right-0 w-64 h-64 bg-blue-500/10 blur-[60px] pointer-events-none" />
              
              <div className="flex justify-between items-start mb-5 relative z-10">
                <div className="w-12 h-12 rounded-2xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center">
                  <GitMerge className="w-6 h-6 text-blue-400" />
                </div>
                {!toggling && (
                  <button onClick={() => setModalOpen(false)} className="p-2 text-zinc-500 hover:text-white transition-colors">
                    <X className="w-5 h-5" />
                  </button>
                )}
              </div>

              <h3 className="text-xl font-bold text-white mb-2 relative z-10">⚠️ Activate Global Git Firewall?</h3>
              <p className="text-sm text-zinc-400 mb-4 relative z-10 leading-relaxed">
                This will install Sentinel hooks in <strong className="text-white">ALL your Git repositories</strong> by modifying 
                <span className="font-mono text-xs bg-white/10 px-1.5 py-0.5 ml-1 rounded">~/.gitconfig</span> globally.
              </p>

              <div className="bg-amber-500/10 border border-amber-500/20 rounded-xl p-3 mb-5 relative z-10">
                <p className="text-xs text-amber-300 leading-relaxed">
                  <strong>What will happen:</strong>
                </p>
                <ul className="text-xs text-amber-300/80 mt-1.5 space-y-1 list-disc list-inside">
                  <li>Every <code className="font-mono bg-amber-500/10 px-1 rounded">git push</code> will be scanned for threats before leaving your machine</li>
                  <li>Every <code className="font-mono bg-amber-500/10 px-1 rounded">git merge / pull</code> will be analyzed for malicious code</li>
                  <li>If malware is detected, the operation will be <strong className="text-amber-200">blocked automatically</strong></li>
                  <li>Your existing hooks (Husky, etc.) will still run normally after Sentinel</li>
                </ul>
              </div>

              <p className="text-[11px] text-zinc-500 mb-4 relative z-10">
                You can disable this at any time from this same panel. No data is sent externally.
              </p>

              <div className="flex gap-3 relative z-10 mt-2">
                <button
                  onClick={() => setModalOpen(false)}
                  disabled={toggling}
                  className="flex-1 py-3 px-4 rounded-xl font-bold text-sm bg-white/5 hover:bg-white/10 text-white transition-colors border border-white/10"
                >
                  No, Skip
                </button>
                <button
                  onClick={() => executeToggle('globalGitHooks', true)}
                  disabled={toggling}
                  className="flex-1 py-3 px-4 rounded-xl font-bold text-sm bg-blue-500 hover:bg-blue-400 text-white transition-colors flex items-center justify-center gap-2"
                >
                  {toggling ? <Loader2 className="w-4 h-4 animate-spin" /> : <Check className="w-4 h-4" />}
                  {toggling ? 'Installing...' : 'Authorize Hooks'}
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
};
