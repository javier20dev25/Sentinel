import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Info, Bell, Clock, Save, CheckCircle2, HardDrive, Trash2, Loader2, Globe, BrainCircuit } from 'lucide-react';
import { useLanguage } from '../contexts/LanguageContext';
import { SecurityHardener } from './SecurityHardener';
import { TrustedContributors } from './TrustedContributors';

// SECURITY: Access Electron APIs via contextBridge (preload.js)
const sentinelBridge = (window as any).sentinel;

export const PreferencesPanel: React.FC = () => {
  const { lang, setLang } = useLanguage();
  const [pollingInterval, setPollingInterval] = useState('20');
  const [notifications, setNotifications] = useState(true);
  
  // AI Keys
  const [aiProvider, setAiProvider] = useState(() => localStorage.getItem('sentinel_ai_provider') || 'openai');
  const [aiKey, setAiKey] = useState(() => localStorage.getItem('sentinel_ai_key') || '');
  const [aiModel, setAiModel] = useState(() => localStorage.getItem('sentinel_ai_model') || 'gpt-4o-mini');

  const [saved, setSaved] = useState(false);
  const [clearing, setClearing] = useState(false);
  const [memoryMessage, setMemoryMessage] = useState('');

  const handleSave = () => {
    // Persist API Keys
    localStorage.setItem('sentinel_ai_provider', aiProvider);
    localStorage.setItem('sentinel_ai_key', aiKey);
    localStorage.setItem('sentinel_ai_model', aiModel);
    
    setSaved(true);
    setTimeout(() => setSaved(false), 3000);
  };

  const handleClearMemory = async () => {
    setClearing(true);
    try {
      const result = await sentinelBridge?.clearMemory();
      setMemoryMessage(result.message || 'Cache cleared');
    } catch (e) {
      setMemoryMessage('Failed to clear memory');
    } finally {
      setTimeout(() => setMemoryMessage(''), 4000);
      setClearing(false);
    }
  };

  return (
    <div className="max-w-2xl space-y-6">
      {/* Section: Scanning */}
      <div className="glass rounded-[28px] border border-white/5 p-7 space-y-5">
        <div className="flex items-center gap-3 mb-2">
          <div className="w-10 h-10 rounded-2xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center">
            <Clock className="w-5 h-5 text-blue-400" />
          </div>
          <div>
            <h3 className="text-base font-bold text-white">Scan Settings</h3>
            <p className="text-xs text-zinc-500">Configure background monitoring behavior</p>
          </div>
        </div>

        <div>
          <label className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest mb-2 block">
            Polling Interval (Minutes)
          </label>
          <input
            type="number"
            min={5}
            max={120}
            value={pollingInterval}
            onChange={e => setPollingInterval(e.target.value)}
            className="w-full bg-white/[0.05] border border-white/10 rounded-2xl px-5 py-3.5 text-sm text-white focus:outline-none focus:ring-2 focus:ring-blue-500/40 focus:border-blue-500/40 transition-all"
          />
          <p className="text-xs text-zinc-600 mt-2">How often Sentinel checks for new pull requests. Minimum: 5 minutes.</p>
        </div>
      </div>

      {/* Section: Language */}
      <div className="glass rounded-[28px] border border-white/5 p-7 space-y-5">
        <div className="flex items-center gap-3 mb-2">
          <div className="w-10 h-10 rounded-2xl bg-teal-500/10 border border-teal-500/20 flex items-center justify-center">
            <Globe className="w-5 h-5 text-teal-400" />
          </div>
          <div>
            <h3 className="text-base font-bold text-white">Language / Idioma</h3>
            <p className="text-xs text-zinc-500">Choose your preferred language</p>
          </div>
        </div>

        <div className="flex gap-3 mt-4">
          <button
            onClick={() => setLang('en')}
            className={`flex-1 py-3 px-4 rounded-xl border transition-all text-sm font-bold ${
              lang === 'en' ? 'bg-teal-500/20 border-teal-500/40 text-teal-400' : 'bg-white/[0.05] border-white/5 text-zinc-400 hover:bg-white/10'
            }`}
          >
            🇬🇧 English
          </button>
          <button
            onClick={() => setLang('es')}
            className={`flex-1 py-3 px-4 rounded-xl border transition-all text-sm font-bold ${
              lang === 'es' ? 'bg-teal-500/20 border-teal-500/40 text-teal-400' : 'bg-white/[0.05] border-white/5 text-zinc-400 hover:bg-white/10'
            }`}
          >
            🇪🇸 Español
          </button>
        </div>
      </div>

      {/* Section: BYOK AI Threat Analysis */}
      <div className="glass rounded-[28px] border border-white/5 p-7 space-y-5">
        <div className="flex items-center gap-3 mb-2">
          <div className="w-10 h-10 rounded-2xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center">
            <BrainCircuit className="w-5 h-5 text-indigo-400" />
          </div>
          <div>
            <h3 className="text-base font-bold text-white">Advanced AI Analysis (BYOK)</h3>
            <p className="text-xs text-zinc-500">Bring your own key to explain and patch malware dynamically</p>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-4">
           <div>
            <label className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest mb-2 block">
              AI Provider
            </label>
            <select
              value={aiProvider}
              onChange={e => setAiProvider(e.target.value)}
              className="w-full bg-white/[0.05] border border-white/10 rounded-2xl px-5 py-3.5 text-sm text-white focus:outline-none focus:ring-2 focus:ring-indigo-500/40"
            >
              <option value="openai">OpenAI</option>
              <option value="anthropic">Anthropic (Claude)</option>
              <option value="gemini">Google Gemini</option>
              <option value="deepseek">DeepSeek</option>
              <option value="ollama">Ollama (Local)</option>
            </select>
          </div>
          <div>
            <label className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest mb-2 block">
              Model Name
            </label>
            <input
              type="text"
              value={aiModel}
              onChange={e => setAiModel(e.target.value)}
              placeholder={
                aiProvider === 'openai' ? 'gpt-4o-mini' :
                aiProvider === 'anthropic' ? 'claude-3-5-sonnet-20241022' :
                aiProvider === 'gemini' ? 'gemini-1.5-pro' :
                aiProvider === 'deepseek' ? 'deepseek-coder' :
                'llama3.2:latest'
              }
              className="w-full bg-white/[0.05] border border-white/10 rounded-2xl px-5 py-3.5 text-sm text-white focus:outline-none focus:ring-2 focus:ring-indigo-500/40 transition-all cursor-text text-left"
            />
          </div>
        </div>
        
        {aiProvider !== 'ollama' && (
          <div>
            <label className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest mb-2 block">
              Secret API Key
            </label>
            <input
              type="password"
              value={aiKey}
              onChange={e => setAiKey(e.target.value)}
              placeholder="sk-proj-..."
              className="w-full bg-white/[0.05] border border-red-500/20 rounded-2xl px-5 py-3.5 text-sm text-white focus:outline-none focus:ring-2 focus:ring-indigo-500/40 transition-all font-mono cursor-text text-left"
            />
            <p className="text-xs text-zinc-500 mt-2">Stored locally in your client. Never sent to our servers.</p>
          </div>
        )}
      </div>

      {/* Section: Notifications */}
      <div className="glass rounded-[28px] border border-white/5 p-7 space-y-5">
        <div className="flex items-center gap-3 mb-2">
          <div className="w-10 h-10 rounded-2xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center">
            <Bell className="w-5 h-5 text-amber-400" />
          </div>
          <div>
            <h3 className="text-base font-bold text-white">Notifications</h3>
            <p className="text-xs text-zinc-500">Desktop alert settings</p>
          </div>
        </div>

        <div className="flex items-center justify-between py-1">
          <div>
            <p className="text-sm font-semibold text-white">Desktop Notifications</p>
            <p className="text-xs text-zinc-500 mt-0.5">Show a system alert when a threat is detected</p>
          </div>
          <button
            onClick={() => setNotifications(!notifications)}
            className={`w-12 h-6 rounded-full relative transition-colors duration-200 ${notifications ? 'bg-blue-500' : 'bg-zinc-700'}`}
          >
            <motion.div
              layout
              className="absolute top-1 w-4 h-4 bg-white rounded-full shadow"
              animate={{ left: notifications ? '26px' : '4px' }}
              transition={{ type: 'spring', damping: 20, stiffness: 300 }}
            />
          </button>
        </div>
      </div>

      {/* Section: Trusted Contributors */}
      <TrustedContributors />

      {/* Section: Security Hardener */}
      <SecurityHardener />

      {/* Section: Memory Management */}
      <div className="glass rounded-[28px] border border-white/5 p-7 space-y-5">
        <div className="flex items-center gap-3 mb-2">
          <div className="w-10 h-10 rounded-2xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center">
            <HardDrive className="w-5 h-5 text-purple-400" />
          </div>
          <div>
            <h3 className="text-base font-bold text-white">Memory Management</h3>
            <p className="text-xs text-zinc-500">Free up system resources and cache</p>
          </div>
        </div>

        <div className="flex items-center justify-between py-1 bg-white/[0.02] border border-white/5 p-4 rounded-2xl">
          <div>
            <p className="text-sm font-semibold text-white">Clear App Cache</p>
            <p className="text-xs text-zinc-500 mt-0.5">Frees up accumulated memory from GitHub API requests and scans.</p>
          </div>
          <div className="flex items-center gap-3">
            {memoryMessage && <span className="text-xs text-emerald-400 font-medium">{memoryMessage}</span>}
            <motion.button
              onClick={handleClearMemory}
              disabled={clearing}
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-purple-500/10 hover:bg-purple-500/20 text-purple-400 border border-purple-500/30 text-xs font-bold transition-colors disabled:opacity-50"
            >
              {clearing ? <Loader2 className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />}
              Clear Memory
            </motion.button>
          </div>
        </div>
      </div>

      {/* Info Banner */}
      <div className="flex items-start gap-3 p-4 rounded-2xl bg-blue-500/5 border border-blue-500/10">
        <Info className="w-4 h-4 text-blue-400 mt-0.5 shrink-0" />
        <p className="text-xs text-blue-300/60 leading-relaxed">
          Sentinel runs entirely locally. No data leaves your machine. All analysis is performed using local heuristics and the GitHub CLI.
        </p>
      </div>

      {/* Save Button */}
      <motion.button
        onClick={handleSave}
        whileHover={{ scale: 1.02 }}
        whileTap={{ scale: 0.97 }}
        className={`flex items-center gap-2 px-7 py-3.5 rounded-2xl text-sm font-bold shadow-lg transition-colors ${
          saved
            ? 'bg-emerald-500/20 border border-emerald-500/30 text-emerald-400'
            : 'bg-blue-500 hover:bg-blue-400 text-white shadow-blue-500/20'
        }`}
      >
        {saved ? <CheckCircle2 className="w-4 h-4" /> : <Save className="w-4 h-4" />}
        {saved ? 'Settings Saved!' : 'Save Changes'}
      </motion.button>
    </div>
  );
};
