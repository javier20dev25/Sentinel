import React from 'react';
import { motion } from 'framer-motion';
import { GitBranch, Shield, Activity, CheckCircle, XCircle, Loader } from 'lucide-react';

type StepStatus = 'idle' | 'running' | 'success' | 'error';

interface ProcessGraphProps {
  steps: { label: string; status: StepStatus }[];
}

const ICONS = [GitBranch, Shield, Activity, CheckCircle];

const statusColor: Record<StepStatus, string> = {
  idle:    'border-white/10 text-zinc-500 bg-zinc-900',
  running: 'border-blue-500/50 text-blue-400 bg-blue-500/10',
  success: 'border-emerald-500/50 text-emerald-400 bg-emerald-500/10',
  error:   'border-red-500/50 text-red-400 bg-red-500/10',
};

const statusDot: Record<StepStatus, string> = {
  idle:    'bg-zinc-700',
  running: 'bg-blue-400 animate-pulse',
  success: 'bg-emerald-400',
  error:   'bg-red-400',
};

export const ProcessGraph: React.FC<ProcessGraphProps> = ({ steps }) => {
  return (
    <div className="w-full flex items-center justify-between gap-2 px-2 py-4">
      {steps.map((step, i) => {
        const Icon = ICONS[i % ICONS.length];
        const isRunning = step.status === 'running';
        return (
          <React.Fragment key={i}>
            {/* Node */}
            <motion.div
              initial={{ opacity: 0, scale: 0.85 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: i * 0.12 }}
              className={`flex flex-col items-center gap-2 flex-1 min-w-0`}
            >
              <div className={`relative w-14 h-14 rounded-2xl border flex items-center justify-center transition-all duration-500 ${statusColor[step.status]}`}>
                {isRunning ? (
                  <motion.div
                    animate={{ rotate: 360 }}
                    transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
                  >
                    <Loader className="w-5 h-5" />
                  </motion.div>
                ) : step.status === 'success' ? (
                  <CheckCircle className="w-5 h-5" />
                ) : step.status === 'error' ? (
                  <XCircle className="w-5 h-5" />
                ) : (
                  <Icon className="w-5 h-5" />
                )}
                {/* Status dot */}
                <span className={`absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full border border-black ${statusDot[step.status]}`} />
              </div>
              <span className="text-[10px] font-bold text-center text-zinc-400 leading-tight truncate w-full px-1">
                {step.label}
              </span>
            </motion.div>

            {/* Connector line */}
            {i < steps.length - 1 && (
              <motion.div
                initial={{ scaleX: 0 }}
                animate={{ scaleX: step.status === 'success' ? 1 : 0.3 }}
                transition={{ duration: 0.5 }}
                className="h-px flex-shrink-0 w-6 origin-left"
                style={{
                  background: step.status === 'success'
                    ? 'linear-gradient(90deg, #10b981, #3b82f6)'
                    : '#27272a'
                }}
              />
            )}
          </React.Fragment>
        );
      })}
    </div>
  );
};
