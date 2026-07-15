'use strict';

const SEMANTIC_PATTERNS = [
  {
    id: 'SEM-001',
    type: 'INDIRECT_CHILD_PROCESS',
    severity: 'HIGH',
    risk: 8,
    category: 'execution',
    description: 'Indirect child_process execution via variable alias or reference',
    test: (code) => {
      const refs = code.match(/(?:require|import)\s*\(\s*['"]child_process['"]\s*\)/g);
      if (!refs) return false;
      const varName = code.match(/(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(\s*['"]child_process['"]\s*\)/);
      if (!varName) return false;
      const name = varName[1];
      const usage = new RegExp(`${name}\\s*\\.\\s*(?:exec|execSync|spawn|fork)\\s*\\(`, 'g');
      const execRefs = code.match(usage);
      return execRefs && execRefs.length > 0;
    },
  },
  {
    id: 'SEM-002',
    type: 'STRING_BUILT_EXECUTION',
    severity: 'HIGH',
    risk: 9,
    category: 'execution',
    description: 'Execution call built from concatenated identifier parts',
    test: (code) => {
      const parts = code.match(/['"][a-zA-Z_]+['"]\s*\+\s*['"][a-zA-Z_]+['"]/g);
      if (!parts || parts.length < 2) return false;
      return code.match(/require|exec|spawn|eval|Function|import/g) !== null;
    },
  },
  {
    id: 'SEM-003',
    type: 'NESTED_OBFUSCATION',
    severity: 'HIGH',
    risk: 9,
    category: 'obfuscation',
    description: 'Multiple obfuscation layers applied to same payload (escapes within encoded strings)',
    test: (code) => {
      const hasHex = /\\x[0-9a-fA-F]{2}/.test(code);
      const hasUnicode = /\\u[0-9a-fA-F]{4}/.test(code);
      const hasBase64 = /['"][A-Za-z0-9+/=]{32,}['"]/.test(code);
      const hasObfVar = /_0x[0-9a-fA-F]{2,}/.test(code);
      let layers = 0;
      if (hasHex) layers++;
      if (hasUnicode) layers++;
      if (hasBase64) layers++;
      if (hasObfVar) layers++;
      return layers >= 2;
    },
  },
  {
    id: 'SEM-004',
    type: 'ARRAY_PROPERTY_OBFUSCATION',
    severity: 'HIGH',
    risk: 8,
    category: 'obfuscation',
    description: 'Array-indexed property access to resolve dangerous identifiers at runtime',
    test: (code) => {
      const arrays = code.match(/const\s+\w+\s*=\s*\[[^\]]{10,}\]/g);
      if (!arrays) return false;
      const bracketAccess = code.match(/\[\s*\d+\s*\]/g);
      return bracketAccess && bracketAccess.length >= 2 && code.match(/exec|eval|spawn|require|Function/g);
    },
  },
  {
    id: 'SEM-005',
    type: 'EVASIVE_REQUIRE_CHAIN',
    severity: 'HIGH',
    risk: 8,
    category: 'execution',
    description: 'Chained require through variable aliases and computed properties',
    test: (code) => {
      const requireAlias = code.match(/(?:const|let|var)\s+\w+\s*=\s*require/g);
      if (!requireAlias) return false;
      const reexports = code.match(/\w+\s*\[\s*['"][a-zA-Z_]+['"]\s*\]/g);
      return reexports && reexports.length >= 2;
    },
  },
  {
    id: 'SEM-006',
    type: 'EVASIVE_PAYLOAD_STRUCTURE',
    severity: 'MEDIUM',
    risk: 6,
    category: 'obfuscation',
    description: 'Suspicious code structure: multiple encoding layers with execution context',
    test: (code) => {
      const hasEval = /eval|Function|exec|spawn/.test(code);
      const hasDecode = /atob|Buffer\.from|toString\s*\(/.test(code);
      const hasSplit = /\.split\(|\.replace\(|\.substr\(|\.slice\(/.test(code);
      return hasEval && hasDecode && hasSplit;
    },
  },
  {
    id: 'SEM-007',
    type: 'CONDITIONAL_EVASION',
    severity: 'MEDIUM',
    risk: 6,
    category: 'execution',
    description: 'Code that conditionally executes based on environment detection',
    test: (code) => {
      const envChecks = code.match(/process\.env\.\w+|typeof\s+\w+\s*===\s*['"]undefined['"]|check\s*(?:env|environment)/gi);
      if (!envChecks) return false;
      const dangerousOp = code.match(/exec|eval|spawn|require|fetch|request|post|delete|writeFile|chmod/g);
      return envChecks.length >= 2 && dangerousOp !== null;
    },
  },
  {
    id: 'SEM-008',
    type: 'PROMPT_LEAK_PATTERN',
    severity: 'HIGH',
    risk: 9,
    category: 'prompt_attack',
    description: 'Agent being asked to leak or dump its own prompt/system instructions',
    test: (code) => {
      if (/leak|dump|print|output|reveal|show|display/.test(code) &&
          /system\s*(prompt|instruction|message|prompt|context)/.test(code)) {
        return true;
      }
      if (/repeat\s+(?:back|the\s+words|the\s+text|everything|this|above)/i.test(code) &&
          /literally|exactly|verbatim|character\s+by\s+character/i.test(code)) {
        return true;
      }
      return false;
    },
  },
  {
    id: 'SEM-009',
    type: 'CODE_SYNTHESIS_REQUEST',
    severity: 'HIGH',
    risk: 8,
    category: 'prompt_attack',
    description: 'Agent being asked to generate code that performs security-sensitive operations',
    test: (code) => {
      if (!/generate|crea|escribe|create|write|synthesize|implement|build/i.test(code)) return false;
      if (/malware|virus|backdoor|ransomware|exploit|trojan|worm|spyware|keylogger|dropper|rootkit|shellcode/i.test(code)) return true;
      if (/code\s*(execution|injection|bypass|evasion|dropper|payload)/i.test(code)) return true;
      return false;
    },
  },
  {
    id: 'SEM-010',
    type: 'AGENT_AUTONOMY_EVASION',
    severity: 'HIGH',
    risk: 8,
    category: 'prompt_attack',
    description: 'Agent instructed to operate beyond its intended scope or ignore safety checks',
    test: (code) => {
      if (/ignore\s+(?:all\s+)?(?:safety|security|restriction|boundary|check|filter|guardrail|policy)/i.test(code)) return true;
      if (/act\s+as\s+(?:root|admin|superuser|super\s*admin|god|omnipotent)/i.test(code)) return true;
      if (/do\s+not\s+(?:refuse|decline|say\s+(?:no|sorry)|ask\s+(?:for\s+)?(?:clarification|permission))/i.test(code)) return true;
      return false;
    },
  },
];

function scanSemantic(code) {
  const findings = [];
  for (const pattern of SEMANTIC_PATTERNS) {
    try {
      if (pattern.test(code)) {
        findings.push({
          id: pattern.id,
          type: pattern.type,
          severity: pattern.severity,
          risk: pattern.risk,
          category: pattern.category,
          description: pattern.description,
          source: 'SEMANTIC',
        });
      }
    } catch (e) {
      continue;
    }
  }
  return findings;
}

module.exports = { SEMANTIC_PATTERNS, scanSemantic };
