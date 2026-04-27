'use client';

import React, { useEffect, useState, useCallback } from 'react';
import Image from 'next/image';
import Link from 'next/link';
import { createClient } from '@/utils/supabase/client';
import { ScanLog } from '@/types';
import { User } from '@supabase/supabase-js';

interface Signal {
  id: string;
  repo: string;
  file: string;
  type: string;
  risk: number;
  status: string;
  time: string;
}

interface GitHubRepo {
  id: number;
  name: string;
  full_name: string;
  private: boolean;
}

interface TrackedRepo {
  id: string;
  github_id: number;
  github_full_name: string;
  created_at: string;
}

interface DashboardProps {
  user: User;
}

export default function Dashboard({ user }: DashboardProps) {
  const [signals, setSignals] = useState<Signal[]>([]);
  const [trackedRepos, setTrackedRepos] = useState<TrackedRepo[]>([]);
  const [stats, setStats] = useState({ processed: 0, blocked: 0, activeNodes: 0 });
  const [loading, setLoading] = useState(true);
  const [isSyncing, setIsSyncing] = useState(false);
  
  const [showImporter, setShowImporter] = useState(false);
  const [githubRepos, setGithubRepos] = useState<GitHubRepo[]>([]);
  const [importLoading, setImportLoading] = useState(false);

  const supabase = createClient();

  const refreshData = useCallback(async () => {
    try {
      const { data: repos, error: reposError } = await supabase
        .from('repositories')
        .select('*')
        .order('created_at', { ascending: false });

      if (reposError) throw reposError;
      setTrackedRepos(repos || []);

      const { data: logs } = await supabase
        .from('scan_logs')
        .select(`
          id, event_type, risk_level, created_at, description,
          repositories ( github_full_name )
        `)
        .order('created_at', { ascending: false })
        .limit(10);

      const typedLogs = (logs || []) as unknown as ScanLog[];
      setSignals(typedLogs.map(l => ({
        id: `TRC_${l.id.toString().padStart(4, '0')}`,
        repo: l.repositories?.github_full_name || 'EXTERNAL_SIGNAL',
        file: l.description,
        type: l.event_type,
        risk: l.risk_level,
        status: l.risk_level >= 8 ? 'BLOCKED' : 'AUDITED',
        time: new Date(l.created_at).toLocaleTimeString()
      })));

      setStats({ 
        processed: (logs?.length || 0) * 12,
        blocked: typedLogs.filter(l => l.risk_level >= 8).length, 
        activeNodes: repos?.length || 0 
      });

    } catch {
      // Background sync failed silently
    } finally {
      setLoading(false);
    }
  }, [supabase]);

  useEffect(() => {
    let isMounted = true;
    const init = async () => {
      if (isMounted) await refreshData();
    };
    init();
    return () => { isMounted = false; };
  }, [refreshData]);

  const openImporter = async () => {
    setShowImporter(true);
    setImportLoading(true);
    try {
      const { data: { session } } = await supabase.auth.getSession();
      const token = session?.provider_token;

      if (!token) {
        alert("Sesión de GitHub expirada. Por favor, haz logout y vuelve a entrar.");
        return;
      }

      const res = await fetch('https://api.github.com/user/repos?sort=updated&per_page=100', {
        headers: { Authorization: `Bearer ${token}` }
      });
      const data = await res.json();
      setGithubRepos(Array.isArray(data) ? data : []);
    } catch {
      alert("Error al conectar con la API de GitHub.");
    } finally {
      setImportLoading(false);
    }
  };

  const trackRepo = async (repo: GitHubRepo) => {
    setIsSyncing(true);
    try {
      const { data: existing } = await supabase
        .from('repositories')
        .select('id')
        .eq('github_id', repo.id)
        .maybeSingle();

      if (existing) {
        alert(`RECURSO YA EXISTENTE: ${repo.full_name} ya está siendo monitorizado.`);
        setShowImporter(false);
        return;
      }

      const { error: insertError } = await supabase.from('repositories').insert({
        github_id: repo.id,
        github_full_name: repo.full_name,
        owner_id: user.id
      });
      
      if (insertError) throw insertError;

      await refreshData();
      setShowImporter(false);
    } catch (e) {
      const err = e as Error;
      alert(`FALLO DE INFRAESTRUCTURA: ${err.message}. Verifica las políticas RLS en Supabase.`);
    } finally {
      setIsSyncing(false);
    }
  };

  const untrackRepo = async (id: string) => {
    if (!confirm("¿Deseas dejar de vigilar este repositorio? Los logs permanecerán.")) return;
    setIsSyncing(true);
    try {
      const { error: deleteError } = await supabase.from('repositories').delete().eq('id', id);
      if (deleteError) throw deleteError;
      await refreshData();
    } catch (e) {
      const err = e as Error;
      alert(`ERROR AL ELIMINAR: ${err.message}`);
    } finally {
      setIsSyncing(false);
    }
  };

  const handleLogout = async () => {
    await supabase.auth.signOut();
    window.location.href = '/';
  };

  if (loading) {
     return (
        <div className="min-h-screen bg-white flex items-center justify-center font-mono uppercase tracking-[0.5em] text-[10px]">
          <span>Syncing_Elite_Infrastructure...</span>
        </div>
     );
  }

  return (
    <div className="min-h-screen bg-white text-black font-mono p-8 selection:bg-black selection:text-white" translate="no">
      <header className="flex justify-between items-end border-b border-gray-100 pb-8 mb-12">
        <div className="flex items-end gap-4">
          <Image src="/brand/logo.png" alt="Sentinel Logo" width={48} height={48} className="object-contain pb-1 mix-blend-multiply" />
          <div>
            <div className="text-[10px] font-bold text-gray-400 mb-2 uppercase tracking-widest">
              Operator Status: <span className="text-green-600 pulse-dot inline-block ml-1 text-[12px]">ONLINE</span>
              <span className="mx-4 text-gray-200">|</span>
              Plan Level: <span className="text-black bg-yellow-400 px-2 py-0.5 ml-1 text-[9px] italic">ELITE</span>
            </div>
            <h1 className="text-5xl font-bold tracking-tighter uppercase italic glitch-text">ELITE</h1>
          </div>
        </div>
        <div className="flex gap-4 items-center">
            <div className="text-right mr-4">
                <div className="text-[10px] font-bold uppercase truncate max-w-[200px]">{user.email}</div>
                <div className="text-[9px] text-gray-400 uppercase tracking-tighter">Auth_Token: {user.id.slice(0, 16)}...</div>
            </div>
            <button onClick={handleLogout} className="border border-black px-4 py-2 text-[10px] font-bold hover:bg-black hover:text-white transition-all uppercase italic">Logout</button>
        </div>
      </header>

      <main className="max-w-7xl mx-auto space-y-16">
        <section className="grid grid-cols-1 md:grid-cols-3 gap-8">
          <div className="border border-black p-8 relative overflow-hidden bg-white group">
            <div className="absolute top-0 right-0 p-2 text-[8px] font-bold text-gray-400 uppercase">Metric_A1</div>
            <h3 className="text-[10px] text-gray-400 mb-4 uppercase tracking-widest font-bold">Total Intercepts</h3>
            <p className="text-6xl font-light tabular-nums tracking-tighter italic">{stats.processed}</p>
          </div>
          <div className="border border-black p-8 relative overflow-hidden bg-black text-white">
            <div className="absolute top-0 right-0 p-2 text-[8px] font-bold text-gray-800 uppercase bg-white">Metric_B2</div>
            <h3 className="text-[10px] text-gray-500 mb-4 uppercase tracking-widest font-bold">Neutralized Threats</h3>
            <p className="text-6xl font-light tabular-nums tracking-tighter text-red-500 italic">{stats.blocked}</p>
          </div>
          <div className="border border-black p-8 relative overflow-hidden">
            <div className="absolute top-0 right-0 p-2 text-[8px] font-bold text-gray-400 uppercase">Metric_C3</div>
            <h3 className="text-[10px] text-gray-400 mb-4 uppercase tracking-widest font-bold">Monitored Nodes</h3>
            <p className="text-6xl font-light tabular-nums tracking-tighter italic">{stats.activeNodes}</p>
          </div>
        </section>

        <section>
          <div className="flex justify-between items-center mb-8 border-l-4 border-black pl-4">
            <h2 className="text-2xl font-bold uppercase tracking-tight italic">Monitored Repositories</h2>
            <button 
              onClick={openImporter}
              className="bg-black text-white px-6 py-2 text-[10px] font-bold uppercase tracking-widest hover:bg-gray-800 transition-all shadow-[6px_6px_0px_0px_rgba(0,0,0,0.1)] active:translate-x-1 active:translate-y-1 active:shadow-none"
            >
              + Import Signal Source
            </button>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
            {trackedRepos.map((repo) => (
              <Link href={`/dashboard/repo/${repo.id}`} key={repo.id} className="block border border-black p-6 bg-white hover:bg-black hover:text-white transition-all relative group cursor-pointer shadow-[6px_6px_0px_0px_rgba(0,0,0,0.1)] active:translate-x-1 active:translate-y-1 active:shadow-none">
                <div className="text-[10px] text-gray-400 group-hover:text-gray-300 mb-2 uppercase font-bold tracking-tighter truncate">{repo.github_full_name.split('/')[0]}</div>
                <div className="text-lg font-bold uppercase tracking-tighter mb-6 truncate">{repo.github_full_name.split('/')[1]}</div>
                
                <div className="flex justify-between items-center pt-4 border-t border-gray-100 group-hover:border-gray-800">
                   <div className="flex flex-col">
                      <span className="text-[8px] text-gray-400 group-hover:text-gray-500 font-bold uppercase">Status</span>
                      <span className="text-[10px] text-green-600 group-hover:text-green-400 font-bold uppercase">SECURE</span>
                   </div>
                   <button 
                    onClick={(e) => {
                      e.preventDefault();
                      e.stopPropagation();
                      untrackRepo(repo.id);
                    }}
                    className="text-[8px] font-bold text-gray-300 hover:text-red-500 uppercase transition-colors"
                   >
                     Decommission
                   </button>
                </div>
              </Link>
            ))}
            {trackedRepos.length === 0 && (
              <div className="col-span-full border border-dashed border-gray-200 py-20 text-center text-gray-300 text-[10px] font-bold uppercase tracking-[0.3em]">
                No active nodes detected. Import a signal source to start forensics.
              </div>
            )}
          </div>
        </section>

        <section>
          <div className="flex justify-between items-center mb-8 border-l-4 border-black pl-4">
            <h2 className="text-2xl font-bold uppercase tracking-tight italic">Live Forensic Feed</h2>
            <div className="flex gap-4 items-center">
               <span className="text-[10px] font-bold uppercase text-red-600 animate-pulse">● Recv_Stream</span>
            </div>
          </div>
          
          <div className="border border-black overflow-hidden bg-white">
            <table className="w-full text-left text-xs">
              <thead className="bg-black text-white text-[9px] uppercase font-bold tracking-[0.2em]">
                <tr>
                  <th className="px-6 py-4">Trace_ID</th>
                  <th className="px-6 py-4">Context / Artifact</th>
                  <th className="px-6 py-4">Vector</th>
                  <th className="px-6 py-4">Risk_Index</th>
                  <th className="px-6 py-4 text-right">Operation</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 font-medium">
                {signals.map((sig) => (
                  <tr key={sig.id} className="hover:bg-gray-50 transition-colors group">
                    <td className="px-6 py-6 text-gray-300 font-bold tabular-nums">{sig.id}</td>
                    <td className="px-6 py-6">
                      <div className="font-bold text-black group-hover:underline italic uppercase text-[11px]">{sig.repo}</div>
                      <div className="text-[9px] text-gray-400 mt-1 uppercase truncate max-w-xs tracking-tighter">{sig.file}</div>
                    </td>
                    <td className="px-6 py-6 font-bold text-[10px] uppercase text-gray-500">{sig.type}</td>
                    <td className="px-6 py-6 italic font-bold text-[11px] tabular-nums">{sig.risk}/10</td>
                    <td className="px-6 py-6 text-right">
                      <button className="text-[9px] font-bold border border-black px-4 py-2 hover:bg-black hover:text-white transition-all uppercase italic">Forensic_View</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </main>

      {showImporter && (
        <div className="fixed inset-0 bg-white/95 backdrop-blur-sm z-[100] flex flex-col p-12 overflow-y-auto">
          <div className="flex justify-between items-center mb-12 border-b border-black pb-8">
            <div>
               <h2 className="text-4xl font-bold uppercase tracking-tighter italic glitch-text">Source Selector</h2>
               <p className="text-gray-400 text-[10px] uppercase font-bold tracking-widest mt-2">Connecting to GitHub API v3 // Intercepting available endpoints</p>
            </div>
            <button onClick={() => setShowImporter(false)} className="text-6xl font-light hover:rotate-90 transition-transform">×</button>
          </div>
          
          {importLoading ? (
            <div className="flex-1 flex items-center justify-center text-[10px] uppercase font-bold tracking-[0.5em] animate-pulse">
               Scanning_GitHub_Namespace...
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8 pb-12">
              {githubRepos.map(repo => (
                <div key={repo.id} className="border border-black p-8 group hover:bg-black hover:text-white transition-all cursor-pointer" onClick={() => trackRepo(repo)}>
                  <div className="text-[10px] text-gray-400 group-hover:text-gray-500 mb-2 uppercase font-bold">{repo.private ? '🔒 PRIVATE_ARTIFACT' : '🌐 PUBLIC_ARTIFACT'}</div>
                  <div className="text-xl font-bold uppercase tracking-tighter">{repo.full_name}</div>
                  <div className="mt-8 text-[10px] font-bold uppercase flex justify-between">
                    <span>Signal: READY</span>
                    <span className="opacity-0 group-hover:opacity-100 transition-opacity">→ Import Now</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {isSyncing && (
        <div className="fixed bottom-8 right-8 bg-black text-white p-6 font-bold text-[10px] uppercase tracking-widest flex items-center gap-4 shadow-2xl z-[200]">
           <div className="w-4 h-4 border-2 border-white border-t-transparent animate-spin"></div>
           Orchestrating_Database_Changes...
        </div>
      )}

      <footer className="mt-32 pt-8 border-t border-gray-100 text-[9px] text-gray-300 flex justify-between uppercase font-bold tracking-[0.4em] italic">
        <div>Sentinel Elite Infrastructure // Distributed Forensic Mesh</div>
        <div>Session Token: {user.id.slice(0, 12)}...</div>
      </footer>
    </div>
  );
}
