'use strict';

const SIGNATURES = [
  {
    id: 'SIG-001',
    name: 'js-obfuscator-default',
    type: 'OBFUSCATOR_SIGNATURE',
    severity: 'CRITICAL',
    risk: 10,
    category: 'obfuscation',
    description: 'javascript-obfuscator default pattern: _0x vars + array mapping + self-defending',
    test: (code) => {
      const obfVars = (code.match(/_0x[0-9a-fA-F]{2,}/g) || []).length;
      const arrayMap = code.match(/var\s+_0x[a-z0-9]+\s*=\s*\[/);
      const selfDefend = code.match(/function\s+_0x[a-z0-9]+\s*\(\s*_0x[a-z0-9]+\s*,\s*_0x[a-z0-9]+\s*\)\s*\{/);
      return obfVars >= 10 && (arrayMap || selfDefend);
    },
  },
  {
    id: 'SIG-002',
    name: 'obfuscator-io-pattern',
    type: 'OBFUSCATOR_SIGNATURE',
    severity: 'CRITICAL',
    risk: 10,
    category: 'obfuscation',
    description: 'Obfuscator.io packed payload with rotated strings and shift cipher',
    test: (code) => {
      const packedArray = /var\s+\w+\s*=\s*\[[\s\S]{100,}\]/.test(code);
      const shiftFn = /function\s+\w+\s*\(\s*\w+\s*,\s*\w+\s*\)\s*\{[\s\S]*?\w+\s*=\s*\w+\s*-\s*\w+/.test(code);
      const decodeCalls = (code.match(/}\s*\(\s*\w+\s*,\s*\d+\s*\)/g) || []).length;
      return packedArray && shiftFn && decodeCalls >= 3;
    },
  },
  {
    id: 'SIG-003',
    name: 'eval-payload-wrapper',
    type: 'EVAL_PAYLOAD',
    severity: 'CRITICAL',
    risk: 10,
    category: 'execution',
    description: 'eval() wrapper with encoded/decoded payload string',
    test: (code) => {
      const evalCalls = code.match(/eval\s*\(/g);
      if (!evalCalls) return false;
      const encodedArgs = /eval\s*\(\s*(?:atob|Buffer\.from|decodeURIComponent|unescape)\s*\(/.test(code);
      const concatArgs = /eval\s*\(\s*(?:\w+\s*\+|\[[^\]]+\]\s*\.\s*join)/.test(code);
      return encodedArgs || concatArgs;
    },
  },
  {
    id: 'SIG-004',
    name: 'base64-payload-exec-chain',
    type: 'EXEC_PAYLOAD_CHAIN',
    severity: 'CRITICAL',
    risk: 10,
    category: 'execution',
    description: 'Decode -> eval/exec chain: Base64 string decoded and executed',
    test: (code) => {
      const hasB64 = /['"][A-Za-z0-9+/=]{50,}['"]/.test(code);
      const hasDecode = /atob\s*\(/.test(code);
      const hasExec = /eval|Function|exec|spawn/.test(code);
      return hasB64 && hasDecode && hasExec;
    },
  },
  {
    id: 'SIG-005',
    name: 'supply-chain-typoglycemia',
    type: 'TYPOSQUATTING',
    severity: 'HIGH',
    risk: 8,
    category: 'supply_chain',
    description: 'Known typosquatting package name pattern in require() or import',
    test: (code) => {
      const typosquatPatterns = [
        /require\s*\(\s*['"](?:browserify|gulpl|gulps|webpackt|grunt|nodemailer|mongoos|gulper|gulpf)\b/gi,
        /require\s*\(\s*['"](?:cross-env-scope|babel-node|babel-register)\b/gi,
        /require\s*\(\s*['"](?:electorn|electon|elctron|elctrn)\b/gi,
        /from\s+['"](?:@[a-z]+\/)?(?:browserify|gulpl|gulp|webpackt|grunt)\b/gi,
        /from\s+['"](?:@[a-z]+\/)?(?:nodemailer|mongoos|gulper|gulpf)\b/gi,
      ];
      return typosquatPatterns.some(p => p.test(code));
    },
  },
  {
    id: 'SIG-006',
    name: 'known-prompt-injection-payloads',
    type: 'PROMPT_INJECTION_SIGNATURE',
    severity: 'CRITICAL',
    risk: 10,
    category: 'prompt_attack',
    description: 'Known prompt injection payload pattern from campaign data',
    test: (code) => {
      const knownPayloads = [
        /DAN|do\s+anything\s+now|jailbreak|jail\s*broken|unfiltered|unconstrained|no\s+(?:filter|limit|restriction)/gi,
        /you\s+are\s+(?:now|free|released|unleashed)\b/gi,
        /pretend|roleplay|role-play|act\s+as\s+if/i,
        /hypothetically|fictional\s+scenario|let's\s+play\s+a\s+game/i,
        /\[\[SYSTEM\]\]|<<SYSTEM>>|\{\{SYSTEM\}\}/g,
      ];
      let count = 0;
      for (const p of knownPayloads) {
        const matches = code.match(p);
        if (matches) count += matches.length;
      }
      return count >= 2;
    },
  },
  {
    id: 'SIG-007',
    name: 'encoded-install-script',
    type: 'ENCODED_LIFECYCLE',
    severity: 'CRITICAL',
    risk: 10,
    category: 'supply_chain',
    description: 'Base64/encoded string used in lifecycle script (postinstall)',
    test: (code) => {
      if (!/"(?:post|pre)install"/.test(code)) return false;
      const encodedOps = code.match(/atob|Buffer\.from|eval|decodeURIComponent|exec|spawn|curl|wget/g);
      return encodedOps && encodedOps.length >= 2;
    },
  },
];

function scanSignatures(code) {
  const findings = [];
  for (const sig of SIGNATURES) {
    try {
      if (sig.test(code)) {
        findings.push({
          id: sig.id,
          type: sig.type,
          severity: sig.severity,
          risk: sig.risk,
          category: sig.category,
          description: sig.description,
          signature: sig.name,
          source: 'SIGNATURE',
        });
      }
    } catch (e) {
      continue;
    }
  }
  return findings;
}

module.exports = { SIGNATURES, scanSignatures };
