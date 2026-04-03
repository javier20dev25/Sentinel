import React, { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  LayoutDashboard, Shield, Settings, History, RefreshCcw, Activity,
  Bell, LogOut, Loader2, Terminal, GitBranch, Lock as LockIcon
} from 'lucide-react';
import OnboardingScreen from './components/OnboardingScreen';
import RepoSelector from './components/RepoSelector';
import Dashboard from './components/Dashboard';
import { ThreatLog } from './components/ThreatLog';
import { StatusBar } from './components/StatusBar';
import { PreferencesPanel } from './components/PreferencesPanel';
import { CLIReference } from './components/CLIReference';
import { SecurityControls } from './components/SecurityControls';
import { SafeStagingView } from './components/SafeStagingView';
import ProjectShieldView from './components/ProjectShieldView';
import AssetGuardView from './components/AssetGuardView';
import { AuditTrailView } from './components/AuditTrailView';
import { useLanguage } from './contexts/LanguageContext';

// SECURITY: Access Electron APIs via contextBridge (preload.js)
// window.sentinel exposes only quit() and clearMemory() — no direct Node access
const sentinelBridge = (window as any).sentinel;

const API = 'http://localhost:3001';

type AppPhase = 'locked' | 'loading' | 'onboarding' | 'repo-select' | 'dashboard' | 'error';

import { api } from './lib/api';
import { LockScreen } from './components/LockScreen';

const App: React.FC = () => {
  const { t } = useLanguage();
  const [phase, setPhase] = useState<AppPhase>('locked'); // Default to locked
  const [serverError, setServerError] = useState('');
  const [username, setUsername] = useState('');
  const [activeTab, setActiveTab] = useState('dashboard');
  const [selectedRepoId, setSelectedRepoId] = useState<string>('all');
  const [repos, setRepos] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [alertCount, setAlertCount] = useState(0);

  const navItems = [
    { id: 'dashboard', icon: LayoutDashboard, label: t('dashboard') },
    { id: 'audit', icon: History, label: 'Audit Trail' },
    { id: 'threats', icon: History, label: t('threat_logs') },
    { id: 'shield', icon: Shield, label: 'Project Shield' },
    { id: 'assets', icon: LockIcon, label: 'Asset Guard' },
    { id: 'safepush', icon: GitBranch, label: 'Safe Push' },
    { id: 'settings', icon: Settings, label: t('settings') },
    { id: 'cli', icon: Terminal, label: t('cli_reference') || 'CLI & Agents' },
    { id: 'controls', icon: Activity, label: t('control_center') || 'Process Manager' },
  ];

  useEffect(() => {
    // If there is a token, try to bypass lock automatically
    const token = localStorage.getItem('sentinel_jwt');
    if (token) {
       setPhase('loading'); // loading will naturally call checkAuthStatus
    }

    const handleLogout = () => {
      setTokens('');
    };

    window.addEventListener('sentinel-logout', handleLogout);
    return () => window.removeEventListener('sentinel-logout', handleLogout);
  }, []);

  useEffect(() => {
    if (phase !== 'loading') return;
    checkAuthStatus();
    // ─── Remote Navigation Intents (SSE) ───
    const eventSource = new EventSource(`${API}/api/ui/stream`);
    
    eventSource.onmessage = (event) => {
      try {
        const intent = JSON.parse(event.data);
        if (intent.connected) return; // Ignore initial dummy ping
        if (intent.action === 'scan-all') {
          setActiveTab('dashboard');
          window.dispatchEvent(new CustomEvent('sentinel-intent', { detail: intent }));
        } else if (intent.action === 'repo' || intent.action === 'pr') {
          setActiveTab('threats');
          window.dispatchEvent(new CustomEvent('sentinel-intent', { detail: intent }));
        }
      } catch (e) { }
    };
    return () => eventSource.close();
  }, [phase]);

  const checkAuthStatus = async (retryCount = 0) => {
    try {
      const { data: auth } = await api.get('/api/auth/status');
      if (auth.authenticated) {
        setUsername(auth.username);
        const { data: linkedRepos } = await api.get('/api/repositories');
        if (linkedRepos.length > 0) {
          setRepos(linkedRepos);
          setAlertCount(linkedRepos.filter((r: any) => r.status !== 'SAFE').length);
          setPhase('dashboard');
        } else {
          setPhase('repo-select');
        }
      } else {
        setPhase('onboarding');
      }
    } catch (e: any) {
      if (e.response?.status === 401) return; // interceptor pushes to lock
      if (retryCount < 5) {
        setTimeout(() => checkAuthStatus(retryCount + 1), 1000);
        return;
      }
      setServerError(e.message || 'Failed to connect to local backend');
      setPhase('error');
    }
  };

  const setTokens = (token: string) => {
    if (token) {
      localStorage.setItem('sentinel_jwt', token);
      setPhase('loading');
    } else {
      localStorage.removeItem('sentinel_jwt');
      setPhase('locked');
    }
  };

  const fetchRepos = useCallback(async () => {
    setLoading(true);
    try {
      const { data } = await api.get('/api/repositories');
      setRepos(data);
      setAlertCount(data.filter((r: any) => r.status !== 'SAFE').length);
    } catch (e) {} finally { setLoading(false); }
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

  const handleLogoutClick = () => {
     setTokens('');
  };

  const handleShutdownClick = async () => {
    try {
      await api.post('/api/system/shutdown');
      setTokens('');
    } catch (e) {
      setServerError('Sentinel Core is shutting down...');
      setPhase('error');
    }
  };

  const tabLabels: Record<string, string> = {
    dashboard: t('dashboard'),
    audit: 'Audit Trail',
    threats: t('threat_logs'),
    settings: t('settings'),
    cli: t('cli_reference') || 'CLI & Agents',
    controls: t('control_center') || 'Process Manager'
  };

  // ── Lock Screen ──
  if (phase === 'locked') {
    return <LockScreen onUnlocked={setTokens} />;
  }

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
          
          <div className="grid grid-cols-2 gap-2">
            <button 
              onClick={handleLogoutClick}
              title="Cerrar Sesión"
              className="flex items-center justify-center p-3 rounded-xl border border-red-500/10 bg-red-500/5 text-red-400 hover:bg-red-500/10 hover:border-red-500/20 transition-all text-xs font-bold"
            >
              <LogOut className="w-3.5 h-3.5" />
            </button>
            <button 
              onClick={handleShutdownClick}
              title="Cerrar Sesión y Apagar Servidor"
              className="flex items-center justify-center p-3 rounded-xl border border-zinc-500/10 bg-zinc-500/5 text-zinc-400 hover:bg-red-600 hover:text-white transition-all text-xs font-bold"
            >
              <RefreshCcw className="w-3.5 h-3.5" />
            </button>
          </div>
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
              {activeTab === 'audit' && <AuditTrailView repoId={selectedRepoId} />}
              {activeTab === 'threats' && <ThreatLog repos={repos} />}
              {activeTab === 'shield' && (
                <div className="space-y-6">
                  <div className="flex items-center gap-4 mb-8 p-4 bg-white/5 rounded-2xl border border-white/10">
                    <Shield className="w-5 h-5 text-blue-400" />
                    <select 
                      value={selectedRepoId}
                      onChange={(e) => setSelectedRepoId(e.target.value)}
                      className="bg-transparent text-sm font-bold outline-none flex-1 cursor-pointer"
                    >
                      <option value="all" className="bg-zinc-900">Select Project to Protected...</option>
                      {repos.map(r => (
                        <option key={r.id} value={r.id} className="bg-zinc-900">{r.github_full_name}</option>
                      ))}
                    </select>
                  </div>
                  <ProjectShieldView repoId={selectedRepoId} />
                </div>
              )}
              {activeTab === 'assets' && (
                <div className="space-y-6">
                  <div className="flex items-center gap-4 mb-8 p-4 bg-white/5 rounded-2xl border border-white/10">
                    <LockIcon className="w-5 h-5 text-red-400" />
                    <select 
                      value={selectedRepoId}
                      onChange={(e) => setSelectedRepoId(e.target.value)}
                      className="bg-transparent text-sm font-bold outline-none flex-1 cursor-pointer"
                    >
                      <option value="all" className="bg-zinc-900">Select Project to Secure Assets...</option>
                      {repos.map(r => (
                        <option key={r.id} value={r.id} className="bg-zinc-900">{r.github_full_name}</option>
                      ))}
                    </select>
                  </div>
                  <AssetGuardView repoId={selectedRepoId} />
                </div>
              )}
              {activeTab === 'safepush' && (
                <div className="space-y-6">
                  <div className="flex items-center gap-4 mb-8 p-4 bg-white/5 rounded-2xl border border-white/10">
                    <GitBranch className="w-5 h-5 text-emerald-400" />
                    <select 
                      value={selectedRepoId}
                      onChange={(e) => setSelectedRepoId(e.target.value)}
                      className="bg-transparent text-sm font-bold outline-none flex-1 cursor-pointer"
                    >
                      <option value="all" className="bg-zinc-900">Select Repository to Inspect Staging...</option>
                      {repos.map(r => (
                        <option key={r.id} value={r.id} className="bg-zinc-900">{r.github_full_name}</option>
                      ))}
                    </select>
                  </div>
                  <SafeStagingView repoId={selectedRepoId} />
                </div>
              )}
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
