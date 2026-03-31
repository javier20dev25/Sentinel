import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Shield, Clock, Cpu, Server, CheckCircle2, PauseCircle, Activity, Loader2 } from 'lucide-react';
import axios from 'axios';

const API = 'http://localhost:3001';

const processMeta: Record<string, any> = {
  'poller': {
    name: 'Background Poller',
    desc: 'Checks GitHub APIs every X minutes for new PRs or changes.',
    cpu: '0.1%',
    ram: '12 MB',
    type: 'network'
  },
  'pre-push': {
    name: 'Git Pre-Push Hook (Secrets)',
    desc: 'Intercepts git push commands to regex-scan for leaked secrets.',
    cpu: '0.0%',
    ram: '0 MB (Idle)',
    type: 'local'
  },
  'hardener': {
    name: 'Global Security Hardener',
    desc: 'Actively monitors npm installs to block preinstall/postinstall scripts.',
    cpu: '0.5%',
    ram: '18 MB',
    type: 'system'
  }
};

export const SecurityControls: React.FC = () => {
  const [processes, setProcesses] = useState<Record<string, any>>({});
  const [loading, setLoading] = useState(true);
  const [toggling, setToggling] = useState<string | null>(null);

  useEffect(() => {
    fetchProcesses();
  }, []);

  const fetchProcesses = async () => {
    try {
      const { data } = await axios.get(`${API}/api/system/processes`);
      setProcesses(data);
    } catch (e) {
      console.error('Failed to fetch processes:', e);
    } finally {
      setLoading(false);
    }
  };

  const toggleProc = async (id: string, currentState: boolean) => {
    setToggling(id);
    try {
      const { data } = await axios.post(`${API}/api/system/processes`, {
        id,
        active: !currentState
      });
      if (data.success) {
        setProcesses(prev => ({
          ...prev,
          [id]: data.process
        }));
      }
    } catch (e) {
      console.error('Failed to toggle process:', e);
    } finally {
      setToggling(null);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center p-20 glass rounded-3xl border border-white/5">
        <Loader2 className="w-8 h-8 text-teal-400 animate-spin" />
      </div>
    );
  }

  const procKeys = Object.keys(processMeta);

  return (
    <div className="space-y-6 max-w-4xl">
      <div className="flex items-center gap-3">
        <div className="w-12 h-12 rounded-2xl bg-teal-500/10 border border-teal-500/20 flex items-center justify-center">
          <Activity className="w-6 h-6 text-teal-400" />
        </div>
        <div>
          <h2 className="text-xl font-bold text-white">Process Manager</h2>
          <p className="text-sm text-zinc-500">Security Control Center. Audit and control the local daemons and hooks Sentinel runs to keep your system safe.</p>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4">
        {procKeys.map((id, i) => {
          const meta = processMeta[id];
          const procState = processes[id] || { active: false, freq: 'Unknown' };
          const isActive = procState.active;
          const isToggling = toggling === id;

          return (
            <motion.div 
              key={id}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.1 }}
              className={`glass rounded-[24px] border p-5 flex items-center justify-between transition-colors ${
                isActive ? 'border-teal-500/20 bg-teal-500/[0.02]' : 'border-white/5 opacity-60'
              }`}
            >
              <div className="flex items-start gap-4 flex-1">
                <div className={`w-10 h-10 rounded-xl flex items-center justify-center shrink-0 border ${
                  isActive ? 'bg-teal-500/10 border-teal-500/20 text-teal-400' : 'bg-white/5 border-white/10 text-zinc-500'
                }`}>
                  {meta.type === 'network' ? <Server className="w-5 h-5" /> : meta.type === 'local' ? <Shield className="w-5 h-5" /> : <Cpu className="w-5 h-5" />}
                </div>
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-1">
                    <h3 className="text-sm font-bold text-white">{meta.name}</h3>
                    <span className={`text-[9px] px-2 py-0.5 rounded-full font-bold uppercase tracking-wider ${
                      isActive ? 'bg-emerald-500/10 text-emerald-400' : 'bg-red-500/10 text-red-400'
                    }`}>
                      {isActive ? 'Active' : 'Paused'}
                    </span>
                  </div>
                  <p className="text-xs text-zinc-400 mb-3 leading-relaxed">{meta.desc}</p>
                  
                  <div className="flex gap-4">
                    <div className="flex items-center gap-1.5 text-[10px] font-mono text-zinc-500">
                      <Clock className="w-3 h-3" /> Freq: <span className="text-zinc-300">{procState.freq}</span>
                    </div>
                    {procState.lastRun && (
                      <div className="flex items-center gap-1.5 text-[10px] font-mono text-zinc-500">
                        <Activity className="w-3 h-3 text-emerald-500" /> Última ejecución: <span className="text-zinc-300">hace {Math.max(0, Math.floor((Date.now() - procState.lastRun) / 60000))} minutos</span>
                      </div>
                    )}
                    <div className="flex items-center gap-1.5 text-[10px] font-mono text-zinc-500">
                      <Cpu className="w-3 h-3" /> CPU: <span className="text-zinc-300">{isActive ? meta.cpu : '0.0%'}</span>
                    </div>
                  </div>
                </div>
              </div>

              <div className="ml-4 pl-4 border-l border-white/5 flex flex-col items-center justify-center h-full min-w-[60px]">
                <button
                  onClick={() => toggleProc(id, isActive)}
                  disabled={isToggling}
                  className={`w-10 h-10 rounded-xl flex items-center justify-center transition-all ${
                    isToggling ? 'opacity-50 cursor-not-allowed bg-zinc-800 text-zinc-500' :
                    isActive 
                      ? 'bg-red-500/10 text-red-400 hover:bg-red-500/20' 
                      : 'bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20'
                  }`}
                >
                  {isToggling ? <Loader2 className="w-5 h-5 animate-spin" /> : 
                   isActive ? <PauseCircle className="w-5 h-5" /> : <CheckCircle2 className="w-5 h-5" />}
                </button>
                <span className={`text-[9px] font-bold uppercase mt-2 ${isActive ? 'text-red-400/80' : 'text-emerald-400/80'}`}>
                  {isToggling ? 'Working' : isActive ? 'Pause' : 'Start'}
                </span>
              </div>
            </motion.div>
          )
        })}
      </div>
    </div>
  );
};
