import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Terminal, Copy, Check, Zap, BookOpen } from 'lucide-react';

const commands = [
  { name: 'Link Repository', cmd: 'sentinel link <path>', desc: 'Links a local folder as a monitored repository for real-time scanning.', example: 'sentinel link ./' },
  { name: 'Full System Scan', cmd: 'sentinel scan', desc: 'Forces an immediate scan of all linked repositories.' },
  { name: 'Scan Specific PR', cmd: 'sentinel scan --pr <url>', desc: 'Scans a specific pull request for malicious payloads or secrets.' },
  { name: 'Quarantine PR', cmd: 'sentinel quarantine --pr <url>', desc: 'Moves an infected PR into a safe quarantine branch for inspection.' },
  { name: 'Safe Install', cmd: 'sentinel safe-install', desc: 'Runs npm install while temporarily blocking all lifecycle scripts globally.' }
];

export const CLIReference: React.FC = () => {
  const [copied, setCopied] = useState<string | null>(null);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(text);
    setTimeout(() => setCopied(null), 2000);
  };

  return (
    <div className="space-y-6 max-w-5xl pb-10">
      <div className="flex items-center gap-3">
        <div className="w-12 h-12 rounded-2xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center">
          <Terminal className="w-6 h-6 text-indigo-400" />
        </div>
        <div>
          <h2 className="text-xl font-bold text-white">CLI & AI Agents Reference</h2>
          <p className="text-sm text-zinc-500">Global commands available in your terminal (PowerShell, CMD, Bash).</p>
        </div>
      </div>

      {/* QUICK START PARA HUMANOS */}
      <div className="glass rounded-[28px] border border-blue-500/20 p-6 flex flex-col md:flex-row gap-6 relative overflow-hidden">
        <div className="absolute top-0 right-0 w-64 h-64 bg-blue-500/10 blur-[80px] rounded-full pointer-events-none" />
        
        <div className="shrink-0 pt-2 relative z-10 w-full md:w-64">
           <div className="flex items-center gap-2 mb-2">
             <Zap className="w-5 h-5 text-blue-400" />
             <h3 className="text-base font-bold text-white">Quick Start para Humanos</h3>
           </div>
           <p className="text-xs text-blue-300 leading-relaxed mb-4">
             ¿No eres una IA? No te preocupes. Sentinel está diseñado para ser aprendido en 5 minutos.
           </p>
           <div className="flex items-center gap-2 bg-black/40 border border-white/5 px-4 py-2.5 rounded-xl cursor-pointer group hover:bg-black/60 transition-colors" onClick={() => copyToClipboard('npm i -g sentinel-cli')}>
              <code className="text-indigo-300 font-mono text-[11px]">npm i -g sentinel</code>
              {copied === 'npm i -g sentinel-cli' ? <Check className="w-3 h-3 text-emerald-400 ml-auto" /> : <Copy className="w-3 h-3 text-zinc-600 group-hover:text-white transition-colors ml-auto" />}
            </div>
        </div>

        <div className="flex-1 grid grid-cols-1 md:grid-cols-2 gap-3 relative z-10">
          <div className="bg-white/[0.03] border border-white/10 rounded-2xl p-4 hover:border-blue-500/30 transition-colors">
             <h4 className="text-sm font-bold text-white mb-1">1. Vincular Repositorio</h4>
             <p className="text-[10px] text-zinc-400 mb-2 leading-relaxed">Ponte en la carpeta de tu código y dile a Sentinel que la vigile.</p>
             <code className="bg-black/40 px-2 py-1.5 rounded-lg text-[10px] text-blue-300 font-mono border border-white/5 cursor-pointer block text-center hover:bg-white/5" onClick={() => copyToClipboard('sentinel link ./')}>sentinel link ./</code>
          </div>
          <div className="bg-white/[0.03] border border-white/10 rounded-2xl p-4 hover:border-blue-500/30 transition-colors">
             <h4 className="text-sm font-bold text-white mb-1">2. Auditar un PR </h4>
             <p className="text-[10px] text-zinc-400 mb-2 leading-relaxed">Antes de hacer `git pull`, revisa el PR para evitar inyecciones.</p>
             <code className="bg-black/40 px-2 py-1.5 rounded-lg text-[10px] text-blue-300 font-mono border border-white/5 cursor-pointer block text-center hover:bg-white/5" onClick={() => copyToClipboard('sentinel scan --pr <url>')}>sentinel scan --pr &lt;url&gt;</code>
          </div>
          <div className="bg-white/[0.03] border border-white/10 rounded-2xl p-4 hover:border-blue-500/30 transition-colors">
             <h4 className="text-sm font-bold text-white mb-1">3. Instalación Segura</h4>
             <p className="text-[10px] text-zinc-400 mb-2 leading-relaxed">Instala NPM bloqueando todos los scripts post/preinstall.</p>
             <code className="bg-black/40 px-2 py-1.5 rounded-lg text-[10px] text-blue-300 font-mono border border-white/5 cursor-pointer block text-center hover:bg-white/5" onClick={() => copyToClipboard('sentinel safe-install')}>sentinel safe-install</code>
          </div>
          <div className="bg-white/[0.03] border border-white/10 rounded-2xl p-4 hover:border-blue-500/30 transition-colors">
             <h4 className="text-sm font-bold text-white mb-1">4. Aislar Amenaza</h4>
             <p className="text-[10px] text-zinc-400 mb-2 leading-relaxed">Baja un PR infectado a una rama aislada (sandbox).</p>
             <code className="bg-black/40 px-2 py-1.5 rounded-lg text-[10px] text-blue-300 font-mono border border-white/5 cursor-pointer block text-center hover:bg-white/5" onClick={() => copyToClipboard('sentinel quarantine --pr <url>')}>sentinel quarantine --pr &lt;url&gt;</code>
          </div>
        </div>
      </div>

      <div className="flex items-center gap-2 mt-10 mb-5 pl-2">
        <BookOpen className="w-5 h-5 text-indigo-400" />
        <h3 className="text-lg font-bold text-white">Full Command Reference</h3>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {commands.map((c, i) => (
          <motion.div 
            key={c.cmd}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.05 }}
            className="glass rounded-[24px] border border-white/5 p-5 flex flex-col justify-between hover:bg-white/[0.03] hover:border-white/10 transition-colors"
          >
            <div>
              <div className="flex justify-between items-start mb-2">
                <h3 className="text-sm font-bold text-white">{c.name}</h3>
                <button 
                  onClick={() => copyToClipboard(c.cmd)}
                  className="p-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-zinc-400 hover:text-white transition-colors"
                >
                  {copied === c.cmd ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>
              <div className="bg-black/40 border border-white/5 rounded-xl p-3 mb-3">
                <code className="text-indigo-300 font-mono text-[11px] break-all">{c.cmd}</code>
              </div>
              <p className="text-xs text-zinc-500 leading-relaxed mb-1">{c.desc}</p>
            </div>
          </motion.div>
        ))}
      </div>
    </div>
  );
};

export default CLIReference;