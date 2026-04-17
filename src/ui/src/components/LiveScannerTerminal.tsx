import React, { useEffect, useRef } from 'react';
import { Terminal, ShieldAlert, CheckCircle2, Shield, Activity, Network } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

export interface TerminalLog {
  id: string;
  timestamp: string;
  message: string;
  type: 'info' | 'warning' | 'error' | 'success' | 'system';
}

interface LiveScannerTerminalProps {
  logs: TerminalLog[];
  confidenceScore: number | null; // 0 to 100
  isScanning: boolean;
  repoName: string;
}

export const LiveScannerTerminal: React.FC<LiveScannerTerminalProps> = ({ logs, confidenceScore, isScanning, repoName }) => {
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs]);

  const getScoreColor = (score: number | null) => {
    if (score === null) return 'text-zinc-500';
    if (score >= 90) return 'text-emerald-400';
    if (score >= 70) return 'text-amber-400';
    return 'text-red-400';
  };

  const getLogStyle = (type: TerminalLog['type']) => {
    switch(type) {
      case 'info': return 'text-blue-400';
      case 'warning': return 'text-amber-400';
      case 'error': return 'text-red-400 font-bold';
      case 'success': return 'text-emerald-400';
      case 'system': return 'text-zinc-500';
      default: return 'text-zinc-400';
    }
  };

  return (
    <div className="flex flex-col h-full bg-black border border-white/[0.06] rounded-2xl overflow-hidden font-mono relative group">
      {/* Terminal Header */}
      <div className="shrink-0 h-10 bg-white/[0.02] border-b border-white/[0.06] flex items-center justify-between px-4">
        <div className="flex items-center gap-3">
          <Terminal className="w-4 h-4 text-zinc-500" />
          <span className="text-xs text-zinc-400 uppercase tracking-widest font-bold">Sentinel Engine // {repoName || 'Idle'}</span>
        </div>
        
        {/* Confidence Score Display */}
        <div className="flex items-center gap-3">
          {isScanning && (
            <div className="flex items-center gap-2 mr-2">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-blue-500"></span>
              </span>
              <span className="text-[10px] uppercase text-blue-400 font-bold tracking-widest">Scanning</span>
            </div>
          )}
          <div className="flex items-center gap-2 bg-white/[0.05] px-3 py-1 rounded-lg border border-white/[0.05]">
             <Activity className="w-3.5 h-3.5 text-zinc-500" />
             <span className="text-[10px] text-zinc-500 font-bold">CONFIDENCE:</span>
             <span className={`text-xs font-black ${getScoreColor(confidenceScore)}`}>
               {confidenceScore !== null ? `${confidenceScore}%` : '---'}
             </span>
          </div>
        </div>
      </div>

      {/* Terminal Body */}
      <div ref={scrollRef} className="flex-1 overflow-y-auto p-4 space-y-1.5 custom-scrollbar">
        {logs.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center opacity-50">
             <Network className="w-8 h-8 text-zinc-600 mb-3" />
             <p className="text-xs text-zinc-500 uppercase tracking-widest">Waiting for target...</p>
          </div>
        ) : (
          <AnimatePresence initial={false}>
            {logs.map((log) => (
              <motion.div
                key={log.id}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                className="flex items-start gap-3"
              >
                <span className="text-[10px] text-zinc-600 shrink-0 mt-0.5 select-none hover:text-zinc-400 transition-colors">
                  {log.timestamp}
                </span>
                <span className={`text-xs break-all leading-relaxed ${getLogStyle(log.type)}`}>
                  {log.message}
                </span>
              </motion.div>
            ))}
          </AnimatePresence>
        )}
      </div>
    </div>
  );
};
