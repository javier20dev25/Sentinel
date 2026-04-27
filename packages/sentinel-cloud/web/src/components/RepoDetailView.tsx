'use client';

import React, { useEffect, useState, useCallback } from 'react';
import Image from 'next/image';
import Link from 'next/link';
import { createClient } from '@/utils/supabase/client';
import { User } from '@supabase/supabase-js';

interface RepoDetailViewProps {
  user: User;
  repoId: string;
}

interface TrackedRepo {
  id: string;
  github_id: number;
  github_full_name: string;
  created_at: string;
}

interface PR {
  id: number;
  number: number;
  title: string;
  user: { login: string };
  state: string;
  updated_at: string;
  html_url: string;
}

// eslint-disable-next-line @typescript-eslint/no-unused-vars
export default function RepoDetailView({ user, repoId }: RepoDetailViewProps) {
  const [repo, setRepo] = useState<TrackedRepo | null>(null);
  const [prs, setPrs] = useState<PR[]>([]);
  const [loading, setLoading] = useState(true);
  const supabase = createClient();

  // Sandbox State
  const [showSandboxModal, setShowSandboxModal] = useState(false);
  const [installing, setInstalling] = useState(false);
  const [sandboxPowers, setSandboxPowers] = useState({
    prIntercept: true,
    deepAST: true,
    autoRemediate: true,
    telemetryStreaming: true,
  });

  // Action State
  const [actionLog, setActionLog] = useState<{prNumber: number, action: string, timeMs: number, status: string}[]>([]);

  const fetchData = useCallback(async () => {
    try {
      // 1. Obtener datos del repo en BD
      const { data: repoData, error } = await supabase
        .from('repositories')
        .select('*')
        .eq('id', repoId)
        .single();

      if (error) throw error;
      setRepo(repoData);

      // 2. Obtener PRs de GitHub
      const { data: { session } } = await supabase.auth.getSession();
      const token = session?.provider_token;

      if (repoData) {
        const headers: Record<string, string> = {};
        if (token) headers['Authorization'] = `Bearer ${token}`;

        const res = await fetch(`https://api.github.com/repos/${repoData.github_full_name}/pulls?state=open`, { headers });
        if (res.ok) {
          const prData = await res.json();
          setPrs(prData);
        } else {
          console.error("GitHub API fetch failed:", await res.text());
        }
      }
    } catch (e) {
      console.error("Error fetching repo details", e);
    } finally {
      setLoading(false);
    }
  }, [repoId, supabase]);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    fetchData();
  }, [fetchData]);

  const togglePower = (power: keyof typeof sandboxPowers) => {
    setSandboxPowers(prev => ({ ...prev, [power]: !prev[power] }));
  };

  const handleInstallSandbox = async () => {
    setInstalling(true);
    // Simulación de instalación vía API de GitHub (creando workflow .yml)
    setTimeout(() => {
      setInstalling(false);
      setShowSandboxModal(false);
      // Registrar log local simulando tiempo de ejecución
      alert("SANDBOX INSTALADO. El contenedor analizará nuevos commits silenciosamente y enviará telemetría encriptada.");
    }, 2400);
  };

  const executeAction = async (prNumber: number, actionName: string) => {
    // eslint-disable-next-line react-hooks/purity
    const startTime = Date.now();
    
    try {
      if (actionName === 'FORENSIC_SCAN') {
        const repoName = repo?.github_full_name || "Unknown Repo";
        const res = await fetch("https://sentinel-engine-production.up.railway.app/analyze", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ repo: repoName })
        });
        
        const data = await res.json();
        
        const endTime = Date.now();
        setActionLog(prev => [{
          prNumber,
          action: `${actionName} (Vulns: ${data.vulnerabilities})`,
          timeMs: endTime - startTime,
          status: data.status.toUpperCase()
        }, ...prev]);

      } else {
        // Simulación para otras acciones
        setTimeout(() => {
          const endTime = Date.now();
          setActionLog(prev => [{
            prNumber,
            action: actionName,
            timeMs: endTime - startTime,
            status: 'COMPLETED'
          }, ...prev]);
        }, 1500);
      }
    } catch (error) {
      console.error("Error executing action:", error);
      const endTime = Date.now();
      setActionLog(prev => [{
        prNumber,
        action: actionName,
        timeMs: endTime - startTime,
        status: 'FAILED (NETWORK ERROR)'
      }, ...prev]);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-white flex items-center justify-center font-mono uppercase tracking-[0.5em] text-[10px]">
        <span>Loading_Forensic_Data...</span>
      </div>
    );
  }

  if (!repo) {
    return <div className="min-h-screen bg-white p-8 text-black font-mono">NODE NOT FOUND.</div>;
  }

  const [owner, name] = repo.github_full_name.split('/');

  return (
    <div className="min-h-screen bg-white text-black font-mono p-8 selection:bg-black selection:text-white" translate="no">
      <header className="flex justify-between items-end border-b border-gray-100 pb-8 mb-12">
        <div className="flex items-end gap-4">
          <Link href="/" className="text-gray-400 hover:text-black mb-1 font-bold text-xl mr-4 transition-colors">
            ←
          </Link>
          <Image src="/brand/logo.png" alt="Sentinel Logo" width={48} height={48} className="object-contain pb-1 mix-blend-multiply" />
          <div>
            <div className="text-[10px] font-bold text-gray-400 mb-2 uppercase tracking-widest flex items-center gap-4">
              <span>NODE: {repo.id.slice(0, 8)}</span>
              <span className="text-gray-200">|</span>
              <span><span className="text-green-600 pulse-dot inline-block mr-1 text-[12px]">ONLINE</span> SECURE</span>
            </div>
            <h1 className="text-4xl font-bold tracking-tighter uppercase italic glitch-text flex flex-col">
              <span className="text-xl text-gray-400 not-italic tracking-widest">{owner}/</span>
              {name}
            </h1>
          </div>
        </div>
        <div className="flex gap-4 items-center">
            <button 
              onClick={() => setShowSandboxModal(true)}
              className="bg-black text-white px-6 py-3 text-[10px] font-bold uppercase tracking-widest hover:bg-gray-800 transition-all shadow-[6px_6px_0px_0px_rgba(0,0,0,0.1)] active:translate-x-1 active:translate-y-1 active:shadow-none"
            >
              + INSTALL SANDBOX
            </button>
        </div>
      </header>

      <main className="max-w-7xl mx-auto space-y-16">
        <section className="grid grid-cols-1 md:grid-cols-3 gap-8">
          <div className="border border-black p-8 relative overflow-hidden bg-white">
            <div className="absolute top-0 right-0 p-2 text-[8px] font-bold text-gray-400 uppercase">TELEMETRY_A</div>
            <h3 className="text-[10px] text-gray-400 mb-4 uppercase tracking-widest font-bold">Open PRs</h3>
            <p className="text-6xl font-light tabular-nums tracking-tighter italic">{prs.length}</p>
          </div>
          <div className="border border-black p-8 relative overflow-hidden bg-black text-white">
            <div className="absolute top-0 right-0 p-2 text-[8px] font-bold text-gray-800 uppercase bg-white">THREAT_VECTOR</div>
            <h3 className="text-[10px] text-gray-500 mb-4 uppercase tracking-widest font-bold">Risk Level</h3>
            <p className="text-6xl font-light tabular-nums tracking-tighter italic text-green-500">LOW</p>
          </div>
          <div className="border border-black p-8 relative overflow-hidden">
            <div className="absolute top-0 right-0 p-2 text-[8px] font-bold text-gray-400 uppercase">SYS_LOG</div>
            <h3 className="text-[10px] text-gray-400 mb-4 uppercase tracking-widest font-bold">Bot Status</h3>
            <p className="text-2xl font-bold tracking-tighter italic uppercase text-gray-300 mt-6">AWAITING WEBHOOK</p>
          </div>
        </section>

        <section>
          <div className="flex justify-between items-center mb-8 border-l-4 border-black pl-4">
            <h2 className="text-2xl font-bold uppercase tracking-tight italic">Pull Requests & Orchestration</h2>
            <div className="flex gap-4 items-center">
               <span className="text-[10px] font-bold uppercase text-red-600 animate-pulse">● LIVE_FEED</span>
            </div>
          </div>
          
          <div className="border border-black overflow-hidden bg-white">
            <table className="w-full text-left text-xs">
              <thead className="bg-black text-white text-[9px] uppercase font-bold tracking-[0.2em]">
                <tr>
                  <th className="px-6 py-4">PR_ID</th>
                  <th className="px-6 py-4">Author / Title</th>
                  <th className="px-6 py-4">Arsenal Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 font-medium">
                {prs.map((pr) => (
                  <tr key={pr.id} className="hover:bg-gray-50 transition-colors group">
                    <td className="px-6 py-6 text-gray-300 font-bold tabular-nums">#{pr.number}</td>
                    <td className="px-6 py-6">
                      <div className="font-bold text-black uppercase text-[11px] truncate max-w-sm">{pr.title}</div>
                      <div className="text-[9px] text-gray-400 mt-1 uppercase tracking-tighter">BY {pr.user.login}</div>
                    </td>
                    <td className="px-6 py-6">
                      <div className="flex flex-wrap gap-2">
                         <button onClick={() => executeAction(pr.number, 'FORENSIC_SCAN')} className="text-[8px] font-bold border border-black px-3 py-1 hover:bg-black hover:text-white transition-all uppercase italic">Forensic Scan</button>
                         <button onClick={() => executeAction(pr.number, 'VIEW_TELEMETRY')} className="text-[8px] font-bold border border-gray-300 text-gray-500 px-3 py-1 hover:border-black hover:text-black transition-all uppercase italic">View Telemetry</button>
                         <button onClick={() => executeAction(pr.number, 'DEPLOY_JANITOR')} className="text-[8px] font-bold border border-red-200 text-red-500 bg-red-50 px-3 py-1 hover:bg-red-500 hover:text-white transition-all uppercase italic flex items-center gap-1">
                            Deploy Janitor
                         </button>
                      </div>
                    </td>
                  </tr>
                ))}
                {prs.length === 0 && (
                  <tr>
                    <td colSpan={3} className="px-6 py-12 text-center text-[10px] text-gray-400 uppercase font-bold tracking-widest">
                      NO ACTIVE PULL REQUESTS DETECTED.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>

        {actionLog.length > 0 && (
          <section className="bg-gray-50 border border-gray-200 p-6">
             <h3 className="text-[10px] font-bold uppercase tracking-widest text-gray-400 mb-4">Execution Logs</h3>
             <div className="space-y-2 max-h-40 overflow-y-auto">
               {actionLog.map((log, i) => (
                 <div key={i} className="text-[9px] font-mono flex justify-between border-b border-gray-100 pb-2">
                    <span className="text-black font-bold uppercase">PR #{log.prNumber} {'//'} {log.action}</span>
                    <span className="text-gray-400 italic">Executed in {(log.timeMs / 1000).toFixed(2)}s [{log.status}]</span>
                 </div>
               ))}
             </div>
          </section>
        )}
      </main>

      {/* Sandbox Installation Modal */}
      {showSandboxModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-[100] flex items-center justify-center p-4">
          <div className="bg-white border-2 border-black max-w-2xl w-full p-8 relative shadow-[16px_16px_0px_0px_rgba(255,255,255,0.1)]">
            <button onClick={() => setShowSandboxModal(false)} className="absolute top-4 right-4 text-2xl font-light hover:rotate-90 transition-transform">×</button>
            
            <h2 className="text-3xl font-bold uppercase tracking-tighter italic mb-2">Power Selection</h2>
            <p className="text-[10px] text-gray-500 font-bold uppercase tracking-widest mb-8">Configure thin-client sandbox payload for {repo.github_full_name}</p>

            <div className="space-y-4 mb-8">
               <label className="flex items-start gap-4 p-4 border border-gray-200 hover:border-black transition-colors cursor-pointer group">
                 <input type="checkbox" checked={sandboxPowers.prIntercept} onChange={() => togglePower('prIntercept')} className="mt-1" />
                 <div>
                    <div className="text-[11px] font-bold uppercase text-black">PR Intercept & Webhook Setup</div>
                    <div className="text-[9px] text-gray-400 uppercase mt-1">Automatically listens for new Pull Requests and triggers autonomous analysis when offline.</div>
                 </div>
               </label>
               <label className="flex items-start gap-4 p-4 border border-gray-200 hover:border-black transition-colors cursor-pointer group">
                 <input type="checkbox" checked={sandboxPowers.deepAST} onChange={() => togglePower('deepAST')} className="mt-1" />
                 <div>
                    <div className="text-[11px] font-bold uppercase text-black">Technical AST Scanning</div>
                    <div className="text-[9px] text-gray-400 uppercase mt-1">Enables deep code path analysis. Payloads are obfuscated to protect Sentinel IP in public logs.</div>
                 </div>
               </label>
               <label className="flex items-start gap-4 p-4 border border-gray-200 hover:border-black transition-colors cursor-pointer group">
                 <input type="checkbox" checked={sandboxPowers.autoRemediate} onChange={() => togglePower('autoRemediate')} className="mt-1" />
                 <div>
                    <div className="text-[11px] font-bold uppercase text-black">Auto-Remediation (Janitor Mode)</div>
                    <div className="text-[9px] text-gray-400 uppercase mt-1">Allows the Sandbox to automatically apply low-risk patches via Sentinel Janitor.</div>
                 </div>
               </label>
               <label className="flex items-start gap-4 p-4 border border-gray-200 hover:border-black transition-colors cursor-pointer group">
                 <input type="checkbox" checked={sandboxPowers.telemetryStreaming} onChange={() => togglePower('telemetryStreaming')} className="mt-1" />
                 <div>
                    <div className="text-[11px] font-bold uppercase text-black">Encrypted Telemetry Streaming</div>
                    <div className="text-[9px] text-gray-400 uppercase mt-1">Sends JSON telemetry securely to Sentinel SaaS for friendly UI translation and AI argumentation.</div>
                 </div>
               </label>
            </div>

            <div className="flex justify-end pt-4 border-t border-gray-100">
               <button 
                  onClick={handleInstallSandbox}
                  disabled={installing}
                  className="bg-black text-white px-8 py-4 text-[10px] font-bold uppercase tracking-[0.3em] hover:bg-gray-800 transition-all disabled:bg-gray-300"
               >
                 {installing ? 'Injecting Payload...' : 'Install & Arm Sandbox'}
               </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
