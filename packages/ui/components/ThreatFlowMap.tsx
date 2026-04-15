import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { GitCommit, Activity, Server, ArrowRight, Skull, FileCode, Network, Link2 } from 'lucide-react';

interface ThreatFlowMapProps {
  eventType?: string;
}

export const ThreatFlowMap: React.FC<ThreatFlowMapProps> = ({ eventType }) => {
  const [isOpen, setIsOpen] = useState(false);

  // Define simplified attack chains based on event type
  const getFlowSteps = () => {
    switch(eventType) {
      case 'MALICIOUS_HOOK':
      case 'NPM_LIFECYCLE_ATTACK':
        return [
          { label: 'npm install', icon: FileCode, type: 'init' },
          { label: 'postinstall hook', icon: Activity, type: 'action' },
          { label: 'Execution', icon: Skull, type: 'impact' }
        ];
      case 'OBFUSCATION':
      case 'UNICODE_ATTACK':
        return [
          { label: 'Hidden Payload', icon: FileCode, type: 'init' },
          { label: 'De-obfuscation', icon: Activity, type: 'action' },
          { label: 'Execution', icon: Skull, type: 'impact' }
        ];
      case 'DATA_EXFILTRATION':
      case 'SUSPICIOUS_DOMAIN':
        return [
          { label: 'Read Env Vars', icon: FileCode, type: 'init' },
          { label: 'Network Out', icon: Network, type: 'action' },
          { label: 'Evil Server', icon: Server, type: 'impact' }
        ];
      case 'TYPOSQUATTING':
        return [
          { label: 'Install Typosquat', icon: FileCode, type: 'init' },
          { label: 'Run Dependency', icon: Activity, type: 'action' },
          { label: 'System Compromise', icon: Skull, type: 'impact' }
        ];
      default:
        // Generic PR or Supply Chain Attack
        return [
          { label: 'Code Insertion', icon: GitCommit, type: 'init' },
          { label: 'Dependency Injection', icon: Link2, type: 'action' },
          { label: 'Execution', icon: Skull, type: 'impact' }
        ];
    }
  };

  const steps = getFlowSteps();

  const getColor = (type: string) => {
    switch(type) {
      case 'init': return 'text-blue-400 bg-blue-500/10 border-blue-500/20';
      case 'action': return 'text-amber-400 bg-amber-500/10 border-amber-500/20';
      case 'impact': return 'text-red-400 bg-red-500/10 border-red-500/20';
      default: return 'text-zinc-400 bg-zinc-500/10 border-zinc-500/20';
    }
  };

  return (
    <div className="mt-4 pt-3 border-t border-white/5">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="text-[10px] uppercase font-bold tracking-widest text-zinc-500 flex items-center gap-1.5 hover:text-white transition-colors"
      >
        <Activity className="w-3.5 h-3.5" />
        {isOpen ? 'Hide' : 'View'} Attack Chain
      </button>

      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ opacity: 0, height: 0, marginTop: 0 }}
            animate={{ opacity: 1, height: 'auto', marginTop: 16 }}
            exit={{ opacity: 0, height: 0, marginTop: 0 }}
            className="overflow-hidden"
          >
            <div className="p-4 bg-black/40 border border-white/10 rounded-2xl flex items-center justify-between gap-2 overflow-x-auto relative">
               {/* Background connection line */}
               <div className="absolute top-1/2 left-[10%] right-[10%] h-px bg-white/10 z-0 hidden md:block" />

              {steps.map((step, idx) => (
                <React.Fragment key={idx}>
                  <div className={`p-3 relative z-10 rounded-xl border flex flex-col items-center justify-center gap-2 min-w-[100px] shrink-0 ${getColor(step.type)}`}>
                    <step.icon className="w-5 h-5 mb-1 opacity-80" />
                    <span className="text-[10px] font-bold text-center leading-tight">
                      {step.label}
                    </span>
                  </div>
                  
                  {idx < steps.length - 1 && (
                    <div className="relative z-10 flex-1 min-w-[20px] flex items-center justify-center text-zinc-500 md:hidden">
                      <ArrowRight className="w-4 h-4" />
                    </div>
                  )}
                </React.Fragment>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

