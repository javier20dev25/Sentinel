import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { motion, AnimatePresence } from 'framer-motion';
import {
  LayoutDashboard, Shield, Settings, History, RefreshCcw, Activity,
  Bell, LogOut, Loader2, Terminal
} from 'lucide-react';
import OnboardingScreen from './components/OnboardingScreen';
import RepoSelector from './components/RepoSelector';
import Dashboard from './components/Dashboard';
import { ThreatLog } from './components/ThreatLog';
import { StatusBar } from './components/StatusBar';
import { PreferencesPanel } from './components/PreferencesPanel';
import { CLIReference } from './components/CLIReference';
import { SecurityControls } from './components/SecurityControls';
import { useLanguage } from './contexts/LanguageContext';

// SECURITY: Access Electron APIs via contextBridge (preload.js)
// window.sentinel exposes only quit() and clearMemory() — no direct Node access
const sentinelBridge = (window as any).sentinel;

const API = 'http://localhost:3001';

type AppPhase = 'loading' | 'onboarding' | 'repo-select' | 'dashboard' | 'error';

// Standardized API Client
const api = axios.create({
  baseURL: API,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
  }
});

const App: React.FC = () => {
  const { t } = useLanguage();
  const [phase, setPhase] = useState<AppPhase>('loading');
  const [serverError, setServerError] = useState('');
  const [username, setUsername] = useState('');
  const [activeTab, setActiveTab] = useState('dashboard');
  const [repos, setRepos] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [alertCount, setAlertCount] = useState(0);

  const navItems = [
    { id: 'dashboard', icon: LayoutDashboard, label: t('dashboard') },
    { id: 'threats', icon: History, label: t('threat_logs') },
    { id: 'settings', icon: Settings, label: t('settings') },
            { id: 'cli', icon: Terminal, label: t('cli_reference') || 'CLI & Agents' },
            { id: 'controls', icon: Activity, label: t('control_center') || 'Process Manager' },
  ];

  // Initial auth check and SSE connection
  useEffect(() => {
    checkAuthStatus();

    // ─── Remote Navigation Intents (SSE) ───
    const eventSource = new EventSource(`${API}/api/ui/stream`);
    
    eventSource.onmessage = (event) => {
      try {
        const intent = JSON.parse(event.data);
        if (intent.connected) return; // Ignore initial dummy ping

        console.log("📡 Received Navigation Intent:", intent);
        
        // Handle navigation intents sent from CLI
        if (intent.action === 'scan-all') {
          setActiveTab('dashboard');
          window.dispatchEvent(new CustomEvent('sentinel-intent', { detail: intent }));
        } else if (intent.action === 'repo') {
          setActiveTab('threats');
          // Actually, ThreatLog takes a selectedRepoID but we'd need to find it by name.
          // Since we'll need a global way to pass 'target', we can emit a custom event.
          window.dispatchEvent(new CustomEvent('sentinel-intent', { detail: intent }));
        } else if (intent.action === 'pr') {
          setActiveTab('threats');
          window.dispatchEvent(new CustomEvent('sentinel-intent', { detail: intent }));
        }
      } catch (e) {
        console.error("Error parsing intent", e);
      }
    };

    return () => {
      eventSource.close();
    };
  }, []);

  const checkAuthStatus = async (retryCount = 0) => {
    try {
      const { data: auth } = await api.get('/api/auth/status');
      if (auth.authenticated) {
        setUsername(auth.username);
        // Check if user has any repos linked
        const { data: linkedRepos } = await api.get('/api/repositories');
        if (linkedRepos.length > 0) {
          setRepos(linkedRepos);
          setAlertCount(linkedRepos.filter((r: any) => r.status !== 'SAFE').length);
          setPhase('dashboard');
        } else {
          setPhase('repo-select');
        }
      } else {
        console.log("Session lost or not authenticated. Gracefully redirecting to onboarding.");
        setPhase('onboarding');
      }
    } catch (e: any) {
      // Retry if backend is not ready yet (connection refused)
      if (retryCount < 10) {
        console.log(`Backend not ready, retrying... (${retryCount + 1}/10)`);
        await new Promise(r => setTimeout(r, 1000));
        return checkAuthStatus(retryCount + 1);
      }
      console.error(e);
      setServerError(e.message || 'Failed to connect to local backend');
      setPhase('error');
    }
  };

  const fetchRepos = useCallback(async () => {
    setLoading(true);
    try {
      const { data } = await api.get('/api/repositories');
      setRepos(data);
      setAlertCount(data.filter((r: any) => r.status !== 'SAFE').length);
    } catch (e) {
      console.error('Failed to fetch repos:', e);
    } finally {
      setLoading(false);
    }
  }, []);

  // Auto-refresh repos on dashboard
  useEffect(() => {
    if (phase !== 'dashboard') return;
    fetchRepos();
    const interval = setInterval(fetchRepos, 30000);
    return () => clearInterval(interval);
  }, [phase, fetchRepos]);

  const handleAuthComplete = (user: string) => {
    setUsername(user);
    setPhase('repo-select');
  };

  const handleRepoSelectComplete = () => {
    setPhase('dashboard');
  };

  const handleAddMore = () => {
    setPhase('repo-select');
  };

  const tabLabels: Record<string, string> = {
    dashboard: t('dashboard'),
    threats: t('threat_logs'),
    settings: t('settings'),
  };

  // ── Loading ──
  if (phase === 'loading') {
    return (
      <div className="h-screen bg-background flex items-center justify-center">
        <div className="text-center">
          <div className="w-16 h-16 mx-auto mb-6 rounded-[22px] bg-gradient-to-br from-blue-500 to-indigo-600 flex items-center justify-center shadow-2xl shadow-blue-500/30">
            <Shield className="w-8 h-8 text-white" />
          </div>
          <Loader2 className="w-6 h-6 mx-auto text-blue-400 animate-spin" />
        </div>
      </div>
    );
  }

  // ── Onboarding (deps + auth) ──
  if (phase === 'onboarding') {
    return <OnboardingScreen onAuthComplete={handleAuthComplete} />;
  }

  // ── Error View ──
  if (phase === 'error') {
    return (
      <div className="h-screen flex items-center justify-center p-8 relative overflow-hidden" style={{ backgroundColor: 'var(--color-background)' }}>
        {/* Background glow */}
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-red-500/10 blur-[100px] rounded-full point-events-none" />

        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          className="max-w-md w-full glass rounded-[32px] border border-red-500/20 p-10 text-center relative z-10 block"
        >
          <div className="w-20 h-20 mx-auto rounded-[24px] bg-red-500/10 border border-red-500/20 flex items-center justify-center mb-6">
            <Shield className="w-10 h-10 text-red-500" />
          </div>
          <h2 className="text-2xl font-black text-white mb-2">Backend Offline</h2>
          <p className="text-sm text-zinc-400 mb-6 leading-relaxed">
            Sentinel could not connect to its local security node (port 3001). This can happen if the process crashed or port is in use.
          </p>
          <div className="bg-black/30 text-red-400 text-xs font-mono p-3 rounded-xl border border-red-500/10 mb-8 inline-block">
            {serverError}
          </div>
          <div className="flex gap-3">
            <button
              onClick={() => sentinelBridge?.quit()}
              className="flex-1 px-5 py-3 rounded-2xl bg-white/5 border border-white/10 text-white font-bold hover:bg-white/10 transition-colors"
            >
              Quit App
            </button>
            <button
              onClick={() => {
                setPhase('loading');
                setTimeout(checkAuthStatus, 1000);
              }}
              className="flex-1 px-5 py-3 rounded-2xl bg-red-500 text-white font-bold hover:bg-red-600 transition-colors flex items-center justify-center gap-2"
            >
              <RefreshCcw className="w-4 h-4" />
              Retry
            </button>
          </div>
        </motion.div>
      </div>
    );
  }

  // ── Repo Selection ──
  if (phase === 'repo-select') {
    return <RepoSelector username={username} onComplete={handleRepoSelectComplete} />;
  }

  // ── Main Dashboard ──
  return (
    <div className="flex h-screen overflow-hidden text-white select-none" style={{ backgroundColor: 'var(--color-background)' }}>
      {/* Sidebar */}
      <aside className="w-60 glass border-r border-white/[0.06] flex flex-col py-5 px-3 shrink-0">
        {/* Logo */}
        <div className="flex items-center gap-3 px-3 mb-6">
          <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-blue-500 to-indigo-600 flex items-center justify-center shadow-lg shadow-blue-500/25 shrink-0">
            <Shield className="w-4.5 h-4.5 text-white" />
          </div>
          <div>
            <h1 className="text-sm font-black tracking-tight text-white">SENTINEL</h1>
            <p className="text-[8px] text-zinc-600 uppercase tracking-[0.2em] font-bold">{t('security_suite')}</p>
          </div>
        </div>

        {/* Status */}
        <div className="px-3 mb-5">
          <div className={`flex items-center gap-2 px-3 py-2 rounded-xl border ${
            alertCount > 0
              ? 'border-red-500/20 bg-red-500/10'
              : 'border-emerald-500/20 bg-emerald-500/10'
          }`}>
            <span className={`w-1.5 h-1.5 rounded-full animate-pulse ${alertCount > 0 ? 'bg-red-400' : 'bg-emerald-400'}`} />
            <span className={`text-[9px] font-bold uppercase tracking-widest ${alertCount > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
              {alertCount > 0 ? `${alertCount} ${t('threats_found')}` : t('all_clear')}
            </span>
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 space-y-1 px-1">
          {navItems.map((item) => {
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl text-[13px] font-semibold transition-all ${
                  isActive
                    ? 'bg-blue-500/15 text-blue-400 border border-blue-500/20'
                    : 'text-zinc-500 hover:text-zinc-200 hover:bg-white/5 border border-transparent'
                }`}
              >
                <item.icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-blue-400' : ''}`} />
                {item.label}
                {item.id === 'threats' && alertCount > 0 && (
                  <span className="ml-auto text-[8px] font-black bg-red-500/20 text-red-400 border border-red-500/30 px-1.5 py-0.5 rounded-full">
                    {alertCount}
                  </span>
                )}
              </button>
            );
          })}
        </nav>

        {/* User */}
        <div className="px-1 mt-auto space-y-2">
          <div className="flex items-center gap-3 p-3 rounded-xl border border-white/5 bg-white/[0.02]">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-blue-500 to-violet-600 flex items-center justify-center text-[10px] font-black shadow-md shrink-0">
              {username.substring(0, 2).toUpperCase()}
            </div>
            <div className="min-w-0 flex-1">
              <p className="text-xs font-bold text-white truncate">{username}</p>
              <p className="text-[8px] text-zinc-600 uppercase tracking-widest font-bold">GitHub</p>
            </div>
          </div>
          
          <button 
            onClick={() => sentinelBridge?.quit()}
            className="w-full flex items-center justify-center gap-2 p-3 rounded-xl border border-red-500/10 bg-red-500/5 text-red-400 hover:bg-red-500/10 hover:border-red-500/20 transition-all text-xs font-bold"
          >
            <LogOut className="w-3.5 h-3.5" />
            {t('close_sentinel')}
          </button>
        </div>
      </aside>

      {/* Main */}
      <main className="flex-1 flex flex-col overflow-hidden">
        {/* Telemetry StatusBar */}
        <StatusBar />
        
        {/* Header */}
        <header className="h-14 px-7 flex items-center justify-between border-b border-white/[0.06] backdrop-blur-xl shrink-0" style={{ backgroundColor: 'rgba(10, 10, 12, 0.8)' }}>
          <div>
            <h2 className="text-base font-bold text-white">{tabLabels[activeTab]}</h2>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={fetchRepos}
              className="p-2 rounded-lg border border-white/5 bg-white/[0.03] text-zinc-500 hover:text-white hover:bg-white/10 transition-colors"
            >
              <RefreshCcw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-blue-400' : ''}`} />
            </button>
            <button className="relative p-2 rounded-lg border border-white/5 bg-white/[0.03] text-zinc-500 hover:text-amber-400 transition-colors">
              <Bell className="w-3.5 h-3.5" />
              {alertCount > 0 && <span className="absolute top-1.5 right-1.5 w-1.5 h-1.5 bg-red-500 rounded-full" />}
            </button>
          </div>
        </header>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-7">
          <AnimatePresence mode="wait">
            <motion.div
              key={activeTab}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              transition={{ duration: 0.15 }}
            >
              {activeTab === 'dashboard' && (
                <Dashboard repos={repos} loading={loading} onAddProject={handleAddMore} />
              )}
              {activeTab === 'threats' && <ThreatLog repos={repos} />}
              {activeTab === 'settings' && <PreferencesPanel />}
            {activeTab === 'cli' && <CLIReference />}
            {activeTab === 'controls' && <SecurityControls />}
            </motion.div>
          </AnimatePresence>
        </div>
      </main>
    </div>
  );
};

export default App;
