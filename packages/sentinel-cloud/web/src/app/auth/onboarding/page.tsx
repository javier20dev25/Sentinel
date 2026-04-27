'use client';

import React, { useState } from 'react';
import { useRouter } from 'next/navigation';

export default function OnboardingPage() {
  const [step, setStep] = useState(1);
  const router = useRouter();

  const handleComplete = () => {
    // In a real app, we would update the user profile in Supabase
    router.push('/');
  };

  return (
    <div className="min-h-screen bg-white text-black font-mono flex flex-col items-center justify-center p-8 selection:bg-black selection:text-white" translate="no">
      <div className="w-full max-w-2xl border border-black p-12 bg-gray-50 shadow-[20px_20px_0px_0px_rgba(0,0,0,0.05)]">
        <div className="flex justify-between items-center mb-12">
            <div className="text-xl font-bold tracking-tighter uppercase">SENTINEL ONBOARDING</div>
            <div className="text-[10px] font-bold text-gray-400">STEP {step} / 2</div>
        </div>

        {step === 1 && (
            <div className="animate-in fade-in slide-in-from-bottom-4 duration-500">
                <h2 className="text-3xl font-bold uppercase tracking-tight mb-6 text-black">Terms of Service & Data Policy</h2>
                <div className="h-64 overflow-y-auto border border-gray-200 bg-white p-6 text-xs text-gray-500 leading-relaxed mb-8 space-y-4">
                    <p className="font-bold text-black uppercase">1. DATA PRIVACY</p>
                    <p>Sentinel processes code metadata and structural patterns to identify security risks. We do not store your source code unless explicit &quot;Deep Scan&quot; is triggered, in which case it is processed in an isolated ephemeral sandbox and immediately purged.</p>
                    <p className="font-bold text-black uppercase">2. INTELLECTUAL PROPERTY</p>
                    <p>The forensic engine, mathematical models, and risk patterns used by Sentinel are proprietary. Reverse engineering is strictly prohibited.</p>
                    <p className="font-bold text-black uppercase">3. LIABILITY</p>
                    <p>Sentinel is a detection tool. While we aim for 100% accuracy, we are not responsible for undetected breaches. Security is a shared responsibility.</p>
                </div>
                <button 
                    onClick={() => setStep(2)}
                    className="w-full bg-black text-white py-4 font-bold uppercase text-sm hover:bg-gray-800 transition-all"
                >
                    I Accept the Protocol
                </button>
            </div>
        )}

        {step === 2 && (
            <div className="animate-in fade-in slide-in-from-right-4 duration-500">
                <h2 className="text-3xl font-bold uppercase tracking-tight mb-6">Permission Requests</h2>
                <p className="text-gray-500 text-sm mb-12 italic">Select the access levels you wish to grant to the Sentinel Engine.</p>

                <div className="space-y-8 mb-12">
                    <div className="flex gap-6 items-start">
                        <input type="checkbox" defaultChecked className="mt-1 w-5 h-5 accent-black" />
                        <div>
                            <div className="font-bold text-sm uppercase mb-1">GitHub Repository Read Access</div>
                            <p className="text-[11px] text-gray-400 leading-normal">
                                WHY: Required to scan your codebase for secrets and vulnerabilities. 
                                <br />IMPACT: Enables real-time detection of high-risk commits.
                            </p>
                        </div>
                    </div>

                    <div className="flex gap-6 items-start opacity-50 grayscale">
                        <input type="checkbox" disabled className="mt-1 w-5 h-5 accent-black" />
                        <div>
                            <div className="font-bold text-sm uppercase mb-1">Pull Request Interaction (ELITE ONLY)</div>
                            <p className="text-[11px] text-gray-400 leading-normal">
                                WHY: To comment on and block unsafe PRs automatically. 
                                <br />IMPACT: Prevents human error from merging critical flaws into production.
                            </p>
                        </div>
                    </div>

                    <div className="flex gap-6 items-start">
                        <input type="checkbox" defaultChecked className="mt-1 w-5 h-5 accent-black" />
                        <div>
                            <div className="font-bold text-sm uppercase mb-1">Webhook Orchestration</div>
                            <p className="text-[11px] text-gray-400 leading-normal">
                                WHY: To receive instant notifications when new code is pushed. 
                                <br />IMPACT: Zero-latency security monitoring.
                            </p>
                        </div>
                    </div>
                </div>

                <button 
                    onClick={handleComplete}
                    className="w-full bg-black text-white py-4 font-bold uppercase text-sm hover:bg-gray-800 transition-all"
                >
                    Initialize Dashboard
                </button>
            </div>
        )}
      </div>
    </div>
  );
}
