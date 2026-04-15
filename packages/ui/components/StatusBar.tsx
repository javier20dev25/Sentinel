import React, { useEffect, useState } from 'react';
import { api } from '../lib/api';
import { Activity, Cpu, HardDrive } from 'lucide-react';

interface SystemStats {
  os: {
    totalMem: number;
    freeMem: number;
    usedMem: number;
    memPercentage: number;
    loadAvg: number;
    cpus: number;
  };
  process: {
    rss: number;
    heapTotal: number;
    heapUsed: number;
  };
  uptime: number;
}

const formatBytes = (bytes: number) => {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
};

export const StatusBar: React.FC = () => {
  const [stats, setStats] = useState<SystemStats | null>(null);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const { data } = await api.get('/api/system/stats');
        setStats(data);
      } catch (e) {
        // Silent fail to not spam console
      }
    };

    fetchStats();
    const interval = setInterval(fetchStats, 3000); // Update every 3 seconds
    return () => clearInterval(interval);
  }, []);

  if (!stats) return null;

  return (
    <div className="h-6 w-full bg-[#050505] border-b border-white/[0.05] flex items-center justify-between px-4 text-[10px] font-mono text-zinc-500 tracking-wider">
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-1.5">
          <Activity className="w-3 h-3 text-emerald-500" />
          <span className="text-zinc-400">SENTINEL-CORE OK</span>
        </div>
        <div className="w-[1px] h-3 bg-white/10" />
        <div className="flex items-center gap-1.5" title="System CPU Load Average (1m)">
          <Cpu className="w-3 h-3" />
          <span>LOAD {(stats.os.loadAvg).toFixed(2)}</span>
        </div>
      </div>

      <div className="flex items-center gap-4">
         <div className="flex items-center gap-1.5" title="Sentinel Background Process RAM">
          <HardDrive className="w-3 h-3 text-blue-400" />
          <span>V8 HEAP: {formatBytes(stats.process.heapUsed)}</span>
        </div>
      </div>
    </div>
  );
};
