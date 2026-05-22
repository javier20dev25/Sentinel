'use client';

import React from 'react';
import Link from 'next/link';
import Image from 'next/image';

const COMMANDS = [
  {
    cmd: 'sentinel scan [path] [--json]',
    desc: 'Scans a local file or directory using 30 deterministic SAST rules. Outputs human-readable or JSON format.',
    usage: 'sentinel scan ./src\nsentinel scan . --json',
  },
  {
    cmd: 'sentinel verify-pkg <package> [--details] [--summary]',
    desc: 'Downloads a package tarball from npm via npm pack, extracts it to a temp directory, and runs LiteScanner on all JS/TS files. Returns verdict: SAFE, SUSPICIOUS, or MALICIOUS.',
    usage: 'sentinel verify-pkg dotenv --details\nsentinel verify-pkg utilz --summary',
  },
  {
    cmd: 'sentinel doctor [--deep]',
    desc: 'System health audit. Without --deep, scans package.json only. With --deep, walks all node_modules dependencies and scans with LiteScanner.',
    usage: 'sentinel doctor --deep',
  },
  {
    cmd: 'sentinel integrity [--uptime] [--watch]',
    desc: 'Six-point host integrity verification: ruleset hash, PATH poisoning, vault integrity, signed manifest, environment flags, Merkle-chain of boot sessions.',
    usage: 'sentinel integrity --uptime',
  },
  {
    cmd: 'sentinel permissions [package]',
    desc: 'Maps LiteScanner findings to capability categories (NETWORK, PROCESS_EXEC, ENV_ACCESS, DYNAMIC_EXEC, DOM_MANIPULATION, CREDENTIAL_LEAK). Runs on all dependencies or a single package.',
    usage: 'sentinel permissions\nsentinel permissions dotenv',
  },
  {
    cmd: 'sentinel memory --status',
    desc: 'Local Signal Vault (SQLite at ~/.sentinel/vault.db). Stores scans, findings, and signals for temporal drift detection and multi-author correlation.',
    usage: 'sentinel memory --status --threshold 5\nsentinel memory --ingest report.json',
  },
  {
    cmd: 'sentinel guard <enable|disable|status|trust-cache>',
    desc: 'OS-level package manager interception. Injects shell aliases that route npm/pip/yarn/docker through Sentinel before execution.',
    usage: 'sentinel guard enable\nsentinel guard status',
  },
  {
    cmd: 'sentinel hub',
    desc: 'Interactive TUI with 11 operations: PR batch analysis, workspace selection, system doctor, integrity check, permissions audit, classified documents, signal vault, and configuration.',
    usage: 'sentinel hub',
  },
  {
    cmd: 'sentinel baseline <create|diff> [name]',
    desc: 'System snapshot management. Captures dependency versions, SHA-256 hashes, and capability fingerprints. Reports version drift and shadow drift (hash mismatch).',
    usage: 'sentinel baseline create prod-v1\nsentinel baseline diff prod-v1',
  },
  {
    cmd: 'sentinel env-encrypt <file> / sentinel env-decrypt <file>',
    desc: 'AES-256-CBC encryption/decryption for .env files. Key derived via SHA-256 of SENTINEL_ENV_KEY or hostname.',
    usage: 'sentinel env-encrypt .env.production',
  },
  {
    cmd: 'sentinel check-classified <repoPath>',
    desc: 'Pre-commit hook entry point. Compares staged files against the classified file database and blocks commits containing classified documents.',
    usage: 'sentinel check-classified .',
  },
  {
    cmd: 'sentinel install <manager> [args...]',
    desc: 'Security-gated installation. Routes through SupplyChainShield.analyzeBatch() before delegating to the native package manager.',
    usage: 'sentinel install npm express',
  },
];

export default function CLIPage() {
  const [copied, setCopied] = React.useState<string | null>(null);

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopied(label);
    setTimeout(() => setCopied(null), 1500);
  };

  return (
    <div className="min-h-screen bg-white text-black font-mono selection:bg-black selection:text-white">
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
          <span className="text-[10px] text-gray-300 uppercase tracking-[0.2em] hidden md:inline">/ CLI Reference</span>
        </div>
        <Link href="/" className="text-[10px] font-bold uppercase tracking-widest hover:line-through transition-all">
          Back to Home
        </Link>
      </nav>

      {/* Header */}
      <section className="pt-24 pb-12 px-8 border-b border-gray-100">
        <div className="max-w-4xl mx-auto">
          <span className="inline-block bg-black text-white text-[10px] font-bold px-3 py-1 mb-6 uppercase tracking-[0.2em]">
            Sentinel CLI // v4.0 Oracle Lite
          </span>
          <h1 className="text-5xl font-bold uppercase tracking-tighter mb-6 leading-[0.95]">
            Terminal Security<br />
            <span className="text-gray-300">Reference.</span>
          </h1>
          <p className="text-gray-500 leading-relaxed max-w-2xl">
            Complete command reference for the Sentinel CLI. Every command, option, and subcommand 
            documented below. The CLI runs locally with zero cloud dependency — same engine as the 
            cloud platform, intentionally degraded to protect proprietary reasoning IP.
          </p>
        </div>
      </section>

      {/* Quick Install */}
      <section className="py-12 px-8 bg-gray-50 border-b border-gray-100">
        <div className="max-w-4xl mx-auto">
          <div className="flex flex-col md:flex-row md:items-center gap-4 justify-between">
            <div>
              <span className="text-[10px] font-bold uppercase tracking-[0.2em] text-gray-400">Install</span>
              <div className="font-mono text-sm mt-2 text-black">npm install -g @sentinel/cli</div>
            </div>
            <div className="text-gray-400 text-xs">
              Requires Node.js &ge; 18.0.0
            </div>
          </div>
        </div>
      </section>

      {/* Commands */}
      <section className="py-16 px-8">
        <div className="max-w-4xl mx-auto space-y-1">
          {COMMANDS.map((item) => (
            <details key={item.cmd} className="group border border-gray-100 hover:border-gray-300 transition-colors open:border-black">
              <summary className="p-5 cursor-pointer list-none flex items-center justify-between gap-4 hover:bg-gray-50 transition-colors">
                <div className="min-w-0">
                  <div className="font-mono text-xs text-black break-all">{item.cmd}</div>
                  <div className="text-[10px] text-gray-400 mt-1 uppercase tracking-wider">{item.desc.substring(0, 80)}...</div>
                </div>
                <span className="text-gray-300 group-open:text-black shrink-0 text-xs">+</span>
              </summary>
              <div className="px-5 pb-6 border-t border-gray-100">
                <p className="text-gray-500 text-xs leading-relaxed mt-4 mb-4">{item.desc}</p>
                <div className="bg-gray-50 p-4 rounded-sm font-mono text-xs relative">
                  <button
                    onClick={() => copyToClipboard(item.usage, item.cmd)}
                    className="absolute top-2 right-2 text-[9px] uppercase tracking-widest text-gray-400 hover:text-black transition-colors"
                  >
                    {copied === item.cmd ? 'Copied' : 'Copy'}
                  </button>
                  <pre className="text-gray-600 whitespace-pre-wrap">{item.usage}</pre>
                </div>
              </div>
            </details>
          ))}
        </div>
      </section>

      {/* Engine Specs */}
      <section className="py-20 px-8 bg-black text-white border-t border-gray-800">
        <div className="max-w-4xl mx-auto">
          <h3 className="text-[10px] font-bold text-gray-500 uppercase tracking-[0.5em] mb-8">Engine Specifications</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            {[
              { label: 'SAST Rules', value: '30', sub: '5 detection intents' },
              { label: 'Scan Targets', value: 'JS/TS', sub: 'Also .mjs, .cjs' },
              { label: 'Persistence', value: 'SQLite', sub: '~/.sentinel/vault.db' },
              { label: 'Integrity', value: 'SHA-256', sub: 'Merkle-chain boot verification' },
              { label: 'Supply Chain', value: 'npm pack', sub: 'No-install tarball extraction' },
              { label: 'Guard', value: 'OS-Level', sub: 'PowerShell / POSIX alias injection' },
            ].map((spec) => (
              <div key={spec.label} className="border border-white/10 p-5">
                <div className="text-[10px] font-bold uppercase tracking-widest text-gray-500 mb-2">{spec.label}</div>
                <div className="text-2xl font-bold tracking-tighter mb-1">{spec.value}</div>
                <div className="text-gray-600 text-xs">{spec.sub}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Security Policy */}
      <section className="py-20 px-8 border-t border-gray-100 bg-gray-50">
        <div className="max-w-4xl mx-auto text-center">
          <h3 className="text-[10px] font-bold uppercase tracking-[0.5em] text-gray-400 mb-4">Integrity & Disclosure</h3>
          <p className="text-gray-500 text-xs leading-relaxed max-w-xl mx-auto">
            Sentinel&apos;s CLI is protected by its own integrity verification system. 
            Any modification to the compiled ruleset is detected at runtime and reported as COMPROMISED. 
            Security vulnerabilities in the CLI itself should be reported via GitHub issues with the 
            <span className="text-black font-bold"> security</span> label.
          </p>
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
