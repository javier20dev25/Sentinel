'use strict';

const DANGEROUS_PROPS = ['exec', 'execSync', 'spawn', 'fork', 'eval', 'Function', 'constructor', 'prototype', '__proto__'];
const CONCAT_EVASION_PATTERNS = [
  /['"]child['"\s]*\+\s*['"]_process['"]/gi,
  /['"]ch['"\s]*\+\s*['"]ild['"\s]*(\+|[a-zA-Z_])/gi,
  /['"]ex['"\s]*\+\s*['"]ec['"]/gi,
  /['"]ev['"\s]*\+\s*['"]al['"]/gi,
  /['"]req['"\s]*\+\s*['"]uire['"]/gi,
];

function shannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  const len = str.length;
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / len;
    if (p > 0) entropy -= p * Math.log2(p);
  }
  return entropy;
}

function analyzeHeuristics(code) {
  const findings = [];

  // H1: High shannon entropy — context-gated
  // High entropy alone → LOW (weak signal).
  // Escalates to MEDIUM only when corroborating evidence of
  // decode, execution, network, or filesystem behavior is present.
  const entropy = shannonEntropy(code);
  if (entropy > 5.1 && code.length > 80 && !/data\s*:\s*image\//.test(code)) {
    const ctxEvidence = /(atob|btoa|Buffer\.from|decodeURI|eval\s*\(|new\s+Function|require\s*\(|import\s*\(|spawn|exec|fork|child_process|writeFile|writeSync|fetch\s*\()/i.test(code);
    findings.push({
      id: 'EVASION-006',
      type: 'HIGH_ENTROPY_PAYLOAD',
      severity: ctxEvidence ? 'MEDIUM' : 'LOW',
      risk: ctxEvidence ? 4 + Math.min(4, Math.floor((entropy - 4.8) * 4)) : 2,
      category: 'obfuscation',
      description: `High entropy (${entropy.toFixed(2)}) suggests encoded/obfuscated content`,
      value: entropy.toFixed(2),
      source: 'HEURISTIC',
    });
  }

  // H2: Hex escape density
  const hexEscapes = (code.match(/\\x[0-9a-fA-F]{2}/g) || []).length;
  if (hexEscapes >= 4) {
    findings.push({
      id: 'EVASION-003',
      type: 'HEX_ESCAPE_OBFUSCATION',
      severity: 'HIGH',
      risk: Math.min(9, 5 + hexEscapes),
      category: 'obfuscation',
      description: `${hexEscapes} hex escape sequences — possible obfuscation`,
      count: hexEscapes,
      source: 'HEURISTIC',
    });
  }

  // H3: Unicode escape density
  const unicodeEscapes = (code.match(/\\u[0-9a-fA-F]{4}/g) || []).length;
  if (unicodeEscapes >= 4) {
    findings.push({
      id: 'EVASION-004',
      type: 'UNICODE_ESCAPE_OBFUSCATION',
      severity: 'HIGH',
      risk: Math.min(9, 5 + unicodeEscapes),
      category: 'obfuscation',
      description: `${unicodeEscapes} unicode escape sequences — possible obfuscation`,
      count: unicodeEscapes,
      source: 'HEURISTIC',
    });
  }

  // H4: Bracket notation access to dangerous properties
  const bracketAccess = code.match(/\[\s*['"][a-zA-Z_]+['"]\s*\]/g) || [];
  for (const acc of bracketAccess) {
    const prop = acc.replace(/[\[\]'"]/g, '').trim();
    if (DANGEROUS_PROPS.includes(prop)) {
      findings.push({
        id: 'EVASION-001',
        type: 'BRACKET_NOTATION_EVASION',
        severity: 'HIGH',
        risk: 8,
        category: 'obfuscation',
        description: `Bracket notation access to dangerous property: ${prop}`,
        match: acc.trim(),
        source: 'HEURISTIC',
      });
    }
  }

  // H5: String concatenation to build dangerous identifiers
  for (const pat of CONCAT_EVASION_PATTERNS) {
    if (pat.test(code)) {
      findings.push({
        id: 'EVASION-002',
        type: 'STRING_CONCAT_EVASION',
        severity: 'HIGH',
        risk: 8,
        category: 'obfuscation',
        description: 'String concatenation building dangerous identifier',
        source: 'HEURISTIC',
      });
      break;
    }
  }

  // H6: Obfuscated variable names (_0x pattern)
  const obfVarCount = (code.match(/_0x[0-9a-fA-F]{2,}/g) || []).length;
  if (obfVarCount >= 2) {
    findings.push({
      id: 'EVASION-005',
      type: 'OBFUSCATED_IDENTIFIERS',
      severity: 'MEDIUM',
      risk: 5,
      category: 'obfuscation',
      description: `${obfVarCount} obfuscated variable names (_0x...) detected`,
      count: obfVarCount,
      source: 'HEURISTIC',
    });
  }

  // H7: globalThis / Reflect sandbox escape
  if (/globalThis\s*[\[.]/.test(code) || /Reflect\s*\.\s*(apply|construct|get)\s*\(/.test(code)) {
    findings.push({
      id: 'EVASION-017',
      type: 'SANDBOX_ESCAPE_PATTERN',
      severity: 'HIGH',
      risk: 7,
      category: 'execution',
      description: 'globalThis/Reflect access pattern — potential sandbox escape',
      source: 'HEURISTIC',
    });
  }

  // H8: Constructor chain
  if (/constructor\s*\.\s*constructor\s*\(/.test(code) || /\[\s*\]\s*\.\s*constructor/.test(code)) {
    findings.push({
      id: 'EVASION-007',
      type: 'CONSTRUCTOR_CHAIN',
      severity: 'HIGH',
      risk: 8,
      category: 'execution',
      description: 'Constructor chain pattern — possible sandbox escape',
      source: 'HEURISTIC',
    });
  }

  // H9: JSON-RPC protocol injection
  if (/"jsonrpc"\s*:\s*"2\.0"/.test(code) && /"method"/.test(code)) {
    findings.push({
      id: 'EVASION-018',
      type: 'AGENT_PROTOCOL_INJECTION',
      severity: 'CRITICAL',
      risk: 9,
      category: 'prompt_attack',
      description: 'JSON-RPC protocol injection attempt detected',
      source: 'HEURISTIC',
    });
  }

  // H10: Homoglyph detection
  const hasCyrillic = /[\u0400-\u04FF\u0500-\u052F]/.test(code);
  if (hasCyrillic && /[a-zA-Z]/.test(code)) {
    findings.push({
      id: 'EVASION-019',
      type: 'HOMOGLYPH_EVASION',
      severity: 'HIGH',
      risk: 8,
      category: 'obfuscation',
      description: 'Mixed-script characters (possible homoglyph evasion)',
      source: 'HEURISTIC',
    });
  }

  // H11: Long base64-looking strings — context-gated
  // High entropy alone → LOW (weak signal).
  // Escalates to MEDIUM only when corroborating evidence of
  // decode, execution, network, or filesystem behavior is present.
  const b64Strings = code.match(/['"][A-Za-z0-9+/=]{32,}['"]/g) || [];
  if (b64Strings.length > 0) {
    const ctxEvidence = /(atob|btoa|Buffer\.from|decodeURI|eval\s*\(|new\s+Function|require\s*\(|import\s*\(|spawn|exec|fork|child_process|writeFile|writeSync|fetch\s*\()/i.test(code);
    findings.push({
      id: 'EVASION-033',
      type: 'ENCODED_PAYLOAD_BLOB',
      severity: ctxEvidence ? 'MEDIUM' : 'LOW',
      risk: ctxEvidence ? 5 : 2,
      category: 'obfuscation',
      description: `${b64Strings.length} long encoded string(s) detected`,
      count: b64Strings.length,
      source: 'HEURISTIC',
    });
  }

  // H12: Multi-layer encoding
  const decodeCalls = (code.match(/atob\s*\(|Buffer\.from\s*\(/g) || []).length;
  if (decodeCalls >= 2) {
    findings.push({
      id: 'EVASION-020',
      type: 'MULTI_LAYER_ENCODING',
      severity: 'HIGH',
      risk: 8,
      category: 'obfuscation',
      description: `${decodeCalls} decode operations — multi-layer encoding detected`,
      count: decodeCalls,
      source: 'HEURISTIC',
    });
  }

  // H13: CI/CD secret env var references — context-gated
  // Env ref alone → LOW (weak signal).
  // Escalates only when accompanied by exfiltration, execution, or persistence.
  const envRefs = code.match(/process\.env\.(?:GITHUB_TOKEN|AWS_|NPM_TOKEN|SLACK_)/g) || [];
  if (envRefs.length > 0) {
    const ctxExfil = /(fetch|axios|http\.|WebSocket|writeFile|writeSync|exec|spawn|fork|child_process|eval|Function|require\s*\(|import\s*\()/i.test(code);
    findings.push({
      id: 'EVASION-024',
      type: 'HARDCODED_SECRET',
      severity: ctxExfil ? 'CRITICAL' : 'LOW',
      risk: ctxExfil ? 10 : 2,
      category: 'supply_chain',
      description: `Reference to known CI/CD secret environment variable${ctxExfil ? '' : ' (no exfiltration context)'}`,
      count: envRefs.length,
      source: 'HEURISTIC',
    });
  }

  // H15: Hardcoded credentials — context-gated
  // Secret-like assignment alone → LOW (weak signal for example/fixture/encoded data).
  // Escalates to CRITICAL only when the value looks like a real credential or
  // when accompanied by decode, execution, network, or filesystem behavior.
  const secretMatches = code.match(/(?:api[_-]?key|secret|password|token)\s*[:=]\s*['"][A-Za-z0-9_\-]{16,}['"]/gi) || [];
  if (secretMatches.length > 0) {
    const ctxEvidence = /(atob|btoa|Buffer\.from|decodeURI|eval\s*\(|new\s+Function|require\s*\(|import\s*\(|spawn|exec|fork|child_process|writeFile|writeSync|fetch\s*\()/i.test(code);
    const isTestContext = /(describe\s*\(|it\s*\(|test\s*\(|assert\.|expect\s*\()/.test(code);
    const isEncodedBlob = /['"][A-Za-z0-9+/=_-]{70,}['"]/.test(code) || /['"](test|example|fake|dummy|placeholder)[-_]/i.test(code);
    const benignSecret = !ctxEvidence && (isEncodedBlob || isTestContext);
    findings.push({
      id: 'EVASION-023',
      type: 'HARDCODED_SECRET',
      severity: benignSecret ? 'LOW' : 'CRITICAL',
      risk: benignSecret ? 2 : 10,
      category: 'supply_chain',
      description: `Hardcoded credential of significant length detected${benignSecret ? ' (likely example/encoded data)' : ''}`,
      count: secretMatches.length,
      source: 'HEURISTIC',
    });
  }

  // H14: eval() calls — context-gated
  // eval in test/assert context without decode/exec/network → LOW (weak signal).
  // Escalates to CRITICAL when accompanied by decode, execution, or exfiltration.
  const evalMatches = code.match(/eval\s*\(/g) || [];
  if (evalMatches.length > 0) {
    const ctxEvalDanger = /(atob|btoa|Buffer\.from|decodeURI|child_process|exec\s*\(|spawn\s*\(|fork\s*\(|fetch\s*\(|writeFile|writeSync)/i.test(code);
    const isTestContext = /(describe\s*\(|it\s*\(|test\s*\(|assert\.|expect\s*\()/.test(code);
    const benignEval = isTestContext && !ctxEvalDanger;
    findings.push({
      id: 'EVASION-013',
      type: 'UNSAFE_EVAL',
      severity: benignEval ? 'LOW' : 'CRITICAL',
      risk: benignEval ? 2 : 10,
      category: 'execution',
      description: `Direct eval() call for arbitrary code execution${benignEval ? ' (in test context, no dangerous signals)' : ''}`,
      count: evalMatches.length,
      source: 'HEURISTIC',
    });
  }

  return findings;
}

module.exports = { analyzeHeuristics, shannonEntropy };
