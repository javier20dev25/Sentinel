import React from 'react';
import { createClient } from '@/utils/supabase/server';
import { decrypt } from '@/lib/crypto';
import Link from 'next/link';

interface ForensicsPageProps {
  params: Promise<{ id: string }>;
}

interface RepoData {
  github_full_name: string;
}

export default async function ForensicsPage({ params }: ForensicsPageProps) {
  const { id } = await params;
  const supabase = await createClient();
  
  const { data: log, error } = await supabase
    .from('scan_logs')
    .select(`
      *,
      repositories ( github_full_name )
    `)
    .eq('id', id)
    .single();

  if (error || !log) {
    return (
      <div className="min-h-screen bg-white text-black font-mono p-8 flex flex-col items-center justify-center">
        <h1 className="text-2xl font-bold uppercase mb-4">Signal Not Found</h1>
        <Link href="/" className="underline text-[10px] font-bold uppercase">Return to Dashboard</Link>
      </div>
    );
  }

  let evidenceData: string | null = null;
  if (log.evidence_metadata) {
    try {
      const metadata = JSON.parse(log.evidence_metadata) as { encrypted?: string };
      if (metadata.encrypted) {
        const decrypted = decrypt(metadata.encrypted);
        evidenceData = typeof decrypted === 'string' ? decrypted : JSON.stringify(decrypted, null, 2);
      }
    } catch (e: unknown) {
      console.error("Decryption failed:", e);
    }
  }

  const repo = log.repositories as unknown as RepoData | null;

  return (
    <div className="min-h-screen bg-white text-black font-mono p-8 selection:bg-black selection:text-white" translate="no">
      <header className="border-b border-black pb-8 mb-12">
        <Link href="/" className="text-[10px] font-bold text-gray-400 hover:text-black transition-colors uppercase tracking-[0.3em] mb-8 block">
          &larr; Back to Orchestrator
        </Link>
        <div className="flex justify-between items-end">
          <div>
            <div className="text-[10px] font-bold text-red-600 mb-2 uppercase tracking-widest">Forensic Artifact: TRC_{id.toString().padStart(4, '0')}</div>
            <h1 className="text-5xl font-bold tracking-tighter uppercase italic">Forensic_Analysis</h1>
          </div>
          <div className="text-right">
             <div className="text-[10px] font-bold uppercase text-gray-400">Timestamp</div>
             <div className="text-sm font-bold uppercase">{new Date(log.created_at).toLocaleString()}</div>
          </div>
        </div>
      </header>

      <main className="max-w-6xl mx-auto">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-12">
          <div className="lg:col-span-2">
            <section className="mb-12">
              <h3 className="text-[10px] font-bold uppercase tracking-widest mb-6 border-l-4 border-black pl-4">Evidence_Source</h3>
              <div className="bg-gray-50 p-6 border border-gray-100">
                <div className="text-[10px] text-gray-400 uppercase mb-1">Repository</div>
                <div className="text-lg font-bold uppercase mb-4">{repo?.github_full_name || 'UNKNOWN_REPO'}</div>
                <div className="text-[10px] text-gray-400 uppercase mb-1">Description</div>
                <div className="text-sm italic">{log.description}</div>
              </div>
            </section>

            <section>
              <h3 className="text-[10px] font-bold uppercase tracking-widest mb-6 border-l-4 border-red-600 pl-4">De-Encrypted_Payload</h3>
              <div className="bg-black text-green-500 p-8 overflow-x-auto font-mono text-xs leading-relaxed border-[10px] border-gray-900 shadow-2xl">
                {evidenceData ? (
                  <pre>{evidenceData}</pre>
                ) : (
                  <div className="text-gray-600 italic uppercase tracking-widest text-center py-12">
                    [ No encrypted evidence attached to this signal ]
                  </div>
                )}
              </div>
            </section>
          </div>

          <div>
            <section className="mb-12">
              <h3 className="text-[10px] font-bold uppercase tracking-widest mb-6 border-l-4 border-black pl-4">Risk_Assessment</h3>
              <div className={`p-8 border-2 ${log.risk_level >= 8 ? 'border-red-600' : 'border-black'} text-center`}>
                <div className="text-[10px] font-bold uppercase text-gray-400 mb-2">Threat Score</div>
                <div className={`text-7xl font-bold italic tracking-tighter ${log.risk_level >= 8 ? 'text-red-600' : 'text-black'}`}>
                  {log.risk_level}/10
                </div>
                <div className="mt-4 text-[10px] font-bold uppercase tracking-widest">
                  {log.risk_level >= 8 ? 'CRITICAL_THREAT_DETECTED' : 'AUDIT_COMPLETE_LOW_RISK'}
                </div>
              </div>
            </section>

            <section>
              <h3 className="text-[10px] font-bold uppercase tracking-widest mb-6 border-l-4 border-black pl-4">Vector_Profile</h3>
              <div className="border border-gray-200 p-6 space-y-4">
                <div className="flex justify-between items-center border-b border-gray-100 pb-2">
                  <span className="text-[10px] text-gray-400 uppercase">Vector</span>
                  <span className="text-[10px] font-bold uppercase">{log.event_type}</span>
                </div>
                <div className="flex justify-between items-center border-b border-gray-100 pb-2">
                  <span className="text-[10px] text-gray-400 uppercase">Detection</span>
                  <span className="text-[10px] font-bold uppercase">AST_INSPECTOR_V1</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-[10px] text-gray-400 uppercase">Status</span>
                  <span className="text-[10px] font-bold uppercase text-green-600">ISOLATED</span>
                </div>
              </div>
            </section>
          </div>
        </div>
      </main>

      <footer className="mt-32 pt-8 border-t border-gray-100 text-[9px] text-gray-300 flex justify-between uppercase font-bold tracking-[0.4em] italic">
        <div>Forensic Node: {log.id.slice(0, 8)}</div>
        <div>Sentinel Elite Cryptographic Layer // AES-256-GCM Verified</div>
      </footer>
    </div>
  );
}
