import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Terminal as TermIcon, X, Copy, Check } from 'lucide-react';
import { api } from '../lib/api';

interface SentinelTerminalProps {
  isOpen: boolean;
  onClose: () => void;
  command: string;
  repoName: string;
}

export const SentinelTerminal: React.FC<SentinelTerminalProps> = ({ isOpen, onClose, command, repoName }) => {
  const [logs, setLogs] = useState<{ id: number, text: string, type: 'info' | 'success' | 'warning' | 'error' | 'cmd', time: string }[]>([]);
  const [copied, setCopied] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (isOpen) {
      setLogs([]);
      let counter = 0;
      const getTime = () => new Date().toTimeString().split(' ')[0];
      
      const sequence = [
        { text: `$ ${command} ${repoName}`, type: 'cmd' as const, delay: 100 },
        { text: 'Initializing AI context and heuristics...', type: 'info' as const, delay: 800 },
        { text: 'Loading pattern-matching signatures...', type: 'info' as const, delay: 600 },
        { text: 'Pre-flight checks completed.', type: 'success' as const, delay: 400 },
        { text: `Target: ${repoName}`, type: 'info' as const, delay: 50 },
      ];

      let currentDelay = 0;
      sequence.forEach((item) => {
        currentDelay += item.delay;
        setTimeout(() => {
          setLogs(prev => [...prev, { id: counter++, text: item.text, type: item.type, time: getTime() }]);
        }, currentDelay);
      });

      // After initial simulation, trigger real scan
      setTimeout(async () => {
        setLogs(prev => [...prev, { id: counter++, text: '🚀 Triggering Deep-Scan API...', type: 'info' as const, time: getTime() }]);
        
        try {
          // Find repo ID from repo list (passed via props or assumed global - let's assume we need repoId)
          // For simplicity, we'll try to find the repo by name or just use a placeholder if we didn't pass ID.
          // Better: pass repoId in props.
          const { data } = await api.post('/api/repositories/scan-by-name', { fullName: repoName });
          
          setLogs(prev => [...prev, 
            { id: counter++, text: `Scan complete: ${data.files_scanned} files, ${data.prs_scanned} PRs checked.`, type: 'success' as const, time: getTime() },
            { id: counter++, text: `Threats found: ${data.threats_found}`, type: data.threats_found > 0 ? 'error' as const : 'success' as const, time: getTime() }
          ]);

          if (data.threats_found > 0) {
            if (data.details && data.details.length > 0) {
              data.details.forEach((desc: string) => {
                setLogs(prev => [...prev, { id: counter++, text: `Threat Detail: ${desc}`, type: 'warning' as const, time: getTime() }]);
              });
            }
            setLogs(prev => [...prev, { id: counter++, text: 'Check the Threat Log for detailed breakdown and history.', type: 'info' as const, time: getTime() }]);
          }
        } catch (err: any) {
          setLogs(prev => [...prev, { id: counter++, text: `Scan failed: ${err.response?.data?.error || err.message}`, type: 'error' as const, time: getTime() }]);
        }
      }, currentDelay + 1000);
    }
  }, [isOpen, command, repoName]);

  const copyOut = () => {
    const text = logs.map(l => `[${l.time}] ${l.text}`).join('\n');
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (!isOpen) return null;

  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-50 flex items-center justify-center p-6 bg-black/60 backdrop-blur-md">
        <motion.div
          initial={{ opacity: 0, scale: 0.95, y: 20 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 20 }}
          className="w-full max-w-3xl h-[500px] flex flex-col bg-[#0d0d0f] border border-[#2a2a30] rounded-2xl shadow-2xl shadow-[#10b981]/5 overflow-hidden ring-1 ring-white/10"
        >
          {/* Header */}
          <div className="flex items-center justify-between px-4 py-3 border-b border-[#2a2a30] bg-[#121215]">
            <div className="flex items-center gap-3">
              <div className="flex gap-1.5">
                <div className="w-3 h-3 rounded-full bg-red-500/80 cursor-pointer hover:bg-red-400" onClick={onClose} />
                <div className="w-3 h-3 rounded-full bg-amber-500/80" />
                <div className="w-3 h-3 rounded-full bg-emerald-500/80" />
              </div>
              <div className="flex items-center gap-2 text-zinc-500 ml-4">
                <TermIcon className="w-4 h-4" />
                <span className="text-[11px] font-mono tracking-widest uppercase font-bold text-[#10b981]">Sentinel Interactive Shell</span>
              </div>
            </div>
            <div className="flex gap-2">
              <button onClick={copyOut} className="px-3 py-1.5 rounded border border-white/10 hover:bg-white/5 text-[10px] font-bold text-zinc-400 tracking-wider flex items-center gap-1.5 transition-colors">
                {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                {copied ? 'Copied!' : 'Copy logs'}
              </button>
              <button onClick={onClose} className="p-1.5 rounded hover:bg-white/5 text-zinc-500 hover:text-white transition-colors">
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>

          {/* Terminal Body */}
          <div ref={scrollRef} className="flex-1 p-5 overflow-y-auto font-mono text-[13px] leading-relaxed tracking-wide shadow-inner">
             {logs.map(log => (
                <div key={log.id} className="mb-2 flex items-start gap-3">
                  <span className="text-zinc-600 shrink-0 select-none">[{log.time}]</span>
                  <span className={`
                    ${log.type === 'cmd' ? 'text-blue-400 font-bold' : ''}
                    ${log.type === 'info' ? 'text-zinc-300' : ''}
                    ${log.type === 'success' ? 'text-[#10b981]' : ''}
                    ${log.type === 'warning' ? 'text-amber-400' : ''}
                    ${log.type === 'error' ? 'text-red-400 font-bold bg-red-500/10 px-1 rounded' : ''}
                  `}>
                    {log.type === 'error' && '🔴 '}
                    {log.type === 'warning' && '⚠️ '}
                    {log.type === 'success' && '✓ '}
                    {log.type === 'cmd' && '❯ '}
                    {log.text}
                  </span>
                </div>
             ))}
             {logs.length > 0 && logs[logs.length-1].type !== 'error' && (
               <div className="w-2 h-4 bg-[#10b981]/70 animate-pulse mt-2" />
             )}
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
};
