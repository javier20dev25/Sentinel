'use client';

import React from 'react';
import Link from 'next/link';
import Image from 'next/image';

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-white text-black font-mono selection:bg-black selection:text-white" translate="no">
      {/* Navigation */}
      <nav className="flex justify-between items-center p-8 border-b border-gray-100 sticky top-0 bg-white/80 backdrop-blur-md z-50">
        <div className="flex items-center gap-4">
          <Image 
            src="/brand/logo.png" 
            alt="Sentinel Logo" 
            width={40} 
            height={40} 
            className="object-contain mix-blend-multiply" 
          />
          <div className="text-xl font-bold tracking-tighter uppercase">SENTINEL</div>
        </div>
        <div className="hidden md:flex gap-12 text-[10px] font-bold uppercase tracking-widest">
          <Link href="#protocol" className="hover:line-through transition-all">Protocol</Link>
          <Link href="#forensics" className="hover:line-through transition-all">Forensics</Link>
          <Link href="#standards" className="hover:line-through transition-all">Standards</Link>
          <Link href="/auth/login" className="bg-black text-white px-6 py-2 hover:bg-gray-800 transition-all">Access Terminal</Link>
        </div>
      </nav>

      {/* Hero Section */}
      <main className="pt-32 pb-20 px-8">
        <div className="max-w-7xl mx-auto">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-20 items-center">
            <div>
              <span className="inline-block bg-gray-100 text-[10px] font-bold px-3 py-1 mb-6 uppercase tracking-[0.2em]">
                Next-Gen Security Signal Orchestrator
              </span>
              <h1 className="text-7xl font-bold leading-[0.9] uppercase tracking-tighter mb-8 glitch-text">
                Protect Your Code <br /> 
                <span className="text-gray-300">Before It&apos;s Built.</span>
              </h1>
              <p className="text-lg text-gray-500 max-w-lg mb-12 leading-relaxed">
                SENTINEL is an enterprise-grade forensic engine that intercepts threats in real-time. 
                From secret detection to advanced mathematical supply-chain analysis.
              </p>
              <div className="flex gap-6">
                <Link href="/auth/login" className="bg-black text-white px-10 py-5 font-bold uppercase text-xs tracking-widest hover:bg-gray-800 transition-all shadow-[12px_12px_0px_0px_rgba(0,0,0,0.1)] active:shadow-none active:translate-x-1 active:translate-y-1">
                  Get Started Free
                </Link>
                <Link href="#whitepaper" className="border border-black px-10 py-5 font-bold uppercase text-xs tracking-widest hover:bg-black hover:text-white transition-all">
                  Read Whitepaper
                </Link>
              </div>
            </div>

            {/* Dashboard Mockup (Always visible for impact) */}
            <div className="relative border border-black p-4 bg-white shadow-[24px_24px_0px_0px_rgba(0,0,0,0.02)] overflow-hidden">
              <div className="flex justify-between items-center mb-6 border-b border-gray-100 pb-4">
                <div className="flex flex-col">
                    <div className="text-[10px] font-bold text-black uppercase tracking-widest mb-1">Active Intercepts</div>
                    <div className="text-[9px] text-gray-400 uppercase italic">Real-time trace telemetry (TRC)</div>
                </div>
                <div className="w-3 h-3 bg-red-500 rounded-full shadow-[0_0_10px_rgba(239,68,68,0.5)] pulse-dot"></div>
              </div>
              <div className="space-y-4">
                {[
                  { id: 'TRC_0923_NODE_1', label: 'AST_SCAN_PENDING', value: 45 },
                  { id: 'TRC_0923_NODE_2', label: 'NETWORK_EXFIL_WATCH', value: 82 },
                  { id: 'TRC_0923_NODE_3', label: 'ReDoS_PATTERN_CHECK', value: 12 },
                ].map((item) => (
                  <div key={item.id} className="space-y-2">
                    <div className="flex justify-between text-[8px] font-bold uppercase tracking-widest text-gray-400">
                      <span>{item.id} {' // '} {item.label}</span>
                      <span>{item.value}%</span>
                    </div>
                    <div className="h-1 bg-gray-50 overflow-hidden">
                      <div className="h-full bg-black transition-all duration-1000" style={{ width: `${item.value}%` }}></div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </main>

      {/* The Sentinel Standard */}
      <section className="py-32 px-8 bg-gray-50 border-y border-gray-100">
          <div className="max-w-4xl mx-auto text-center">
              <h2 className="text-4xl font-bold uppercase tracking-tighter mb-8 italic">The Sentinel Standard</h2>
              <p className="text-gray-500 leading-relaxed mb-12">
                  We don&apos;t just scan code. We orchestrate security signals. Sentinel implements a 
                  <span className="text-black font-bold"> Zero-Trust Build Pipeline </span> 
                  where every commit is treated as a potential forensic artifact. Our strict CI/CD guardrails are not a hindrance—they are your greatest defense.
              </p>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
                  <div className="border border-black/10 p-8 bg-white">
                      <div className="text-2xl font-bold mb-2 tracking-tighter">01.</div>
                      <div className="text-[10px] font-bold uppercase tracking-widest">Type-Safe Forensics</div>
                  </div>
                  <div className="border border-black/10 p-8 bg-white">
                      <div className="text-2xl font-bold mb-2 tracking-tighter">02.</div>
                      <div className="text-[10px] font-bold uppercase tracking-widest">AST Deconstruction</div>
                  </div>
                  <div className="border border-black/10 p-8 bg-white">
                      <div className="text-2xl font-bold mb-2 tracking-tighter">03.</div>
                      <div className="text-[10px] font-bold uppercase tracking-widest">Encrypted Telemetry</div>
                  </div>
              </div>
          </div>
      </section>

      {/* Technical Whitepaper Section */}
      <section id="whitepaper" className="py-32 px-8 border-t border-gray-100 bg-black text-white">
          <div className="max-w-4xl mx-auto">
              <span className="text-[10px] font-bold text-gray-500 uppercase tracking-[0.5em] mb-8 block">Sentinel Research Group // v4.2</span>
              <h2 className="text-6xl font-bold uppercase tracking-tighter mb-16 italic glitch-text">Technical Whitepaper</h2>
              <div className="space-y-12 text-gray-400 leading-relaxed">
                  <div>
                      <h4 className="text-white font-bold uppercase mb-4 tracking-widest">Abstract: The Forensic Intercept</h4>
                      <p>Traditional static analysis fails because it operates at the surface level. Sentinel operates at the Abstract Syntax Tree (AST) layer, intercepting logic patterns before they are compiled into vulnerabilities.</p>
                  </div>
              </div>
          </div>
      </section>

      <footer className="p-20 text-center border-t border-gray-100">
        <div className="text-[10px] font-bold uppercase tracking-[0.5em] text-gray-300">
          SENTINEL // SECURITY SIGNAL ORCHESTRATOR // 2026
        </div>
      </footer>
    </div>
  );
}
