import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ShieldAlert, Package, ChevronDown, ChevronUp, ExternalLink, Activity, Info } from 'lucide-react';
import { api } from '../lib/api';

interface DependencyAuditProps {
  repoId: number;
}

export const DependencyAudit: React.FC<DependencyAuditProps> = ({ repoId }) => {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState(false);

  useEffect(() => {
    const fetchAudit = async () => {
      try {
        const res = await api.get(`/api/repositories/${repoId}/audit`);
        setData(res.data);
      } catch (err) {
        console.error("Audit failed", err);
      } finally {
        setLoading(false);
      }
    };
    fetchAudit();
  }, [repoId]);

  if (loading) return (
    <div className="flex items-center gap-2 text-[10px] text-zinc-500 font-bold py-2 animate-pulse">
      <Activity className="w-3 h-3 animate-spin" />
      Analyzing Aura Permissions...
    </div>
  );

  if (!data) return null;

  const hasRiskyScripts = data.rootAlerts?.length > 0;

  return (
    <div className="mt-4 border-t border-white/[0.04] pt-4">
      <div 
        onClick={() => setExpanded(!expanded)}
        className="flex items-center justify-between cursor-pointer group"
      >
        <div className="flex items-center gap-2">
          <div className={`p-1.5 rounded-lg ${hasRiskyScripts ? 'bg-red-500/10 text-red-400' : 'bg-blue-500/10 text-blue-400'}`}>
            <Package className="w-3.5 h-3.5" />
          </div>
          <div>
            <p className="text-[10px] font-black text-white uppercase tracking-widest">
              Aura Bundle: {data.dependencies} Dependencies
            </p>
            {hasRiskyScripts && (
              <p className="text-[9px] font-bold text-red-500/80 animate-pulse">
                {data.rootAlerts.length} Sensitive Permissions Detected
              </p>
            )}
          </div>
        </div>
        {expanded ? <ChevronUp className="w-4 h-4 text-zinc-500" /> : <ChevronDown className="w-4 h-4 text-zinc-500" />}
      </div>

      <AnimatePresence>
        {expanded && (
          <motion.div 
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden"
          >
            <div className="pt-4 space-y-3">
              {data.rootAlerts?.length > 0 && (
                <div className="space-y-2">
                  <p className="text-[9px] font-black text-red-400 uppercase tracking-tighter">Found Vulnerabilities</p>
                  {data.rootAlerts.map((alert: any, i: number) => (
                    <div key={i} className="flex gap-2 p-2.5 rounded-xl bg-red-500/5 border border-red-500/10">
                      <ShieldAlert className="w-3 h-3 text-red-400 shrink-0 mt-0.5" />
                      <div>
                        <p className="text-[10px] font-black text-white leading-tight">{alert.type}</p>
                        <p className="text-[9px] text-red-300/60 font-medium mt-0.5">{alert.message}</p>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              <div className="space-y-2">
                <p className="text-[9px] font-black text-zinc-500 uppercase tracking-tighter">Direct Dependencies</p>
                <div className="flex flex-wrap gap-1.5">
                  {data.list?.slice(0, 15).map((dep: string) => (
                    <span key={dep} className="px-2 py-1 rounded-md bg-white/5 border border-white/5 text-[9px] text-zinc-400 font-bold hover:bg-white/10 transition-colors cursor-default">
                      {dep}
                    </span>
                  ))}
                  {data.list?.length > 15 && (
                    <span className="text-[9px] text-zinc-600 font-bold ml-1">+{data.list.length - 15} more</span>
                  )}
                </div>
              </div>

              <div className="flex items-center justify-between p-2.5 rounded-xl bg-blue-500/[0.03] border border-blue-500/10 mt-2">
                <div className="flex items-center gap-2">
                  <Info className="w-3 h-3 text-blue-400" />
                  <p className="text-[9px] font-bold text-blue-300/70">Scan powered by Sentinel Aura</p>
                </div>
                <ExternalLink className="w-3 h-3 text-zinc-600" />
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};
