/**
 * Sentinel: Rust AST Inspector — Tree-sitter based analyzer
 *
 * Implements Phase 1 MVP focusing on supply chain vector analysis targeting build.rs,
 * process execution, network connections, unsafe blocks, and compiler macro exploitation.
 */

import { type ForensicFinding } from './types';
import * as ParserModule from 'web-tree-sitter';
import { checkUrl } from './threat_intel';

type TSParser = InstanceType<typeof ParserModule.Parser>;
type TSNode = InstanceType<typeof ParserModule.Node>;
type TSLanguage = InstanceType<typeof ParserModule.Language>;

let tsParser: TSParser | null = null;
let parserInitPromise: Promise<void> | null = null;

async function ensureParser(): Promise<TSParser> {
  if (tsParser) return tsParser;
  if (!parserInitPromise) {
    parserInitPromise = (async () => {
      await ParserModule.Parser.init();
      const path = require('path');
      const fs = require('fs');

      let rustWasmPath = path.join(process.cwd(), 'node_modules', 'tree-sitter-rust', 'tree-sitter-rust.wasm');

      const lang: TSLanguage = await ParserModule.Language.load(rustWasmPath);
      const p = new ParserModule.Parser();
      p.setLanguage(lang);
      tsParser = p;
    })();
  }
  await parserInitPromise;
  return tsParser!;
}

function classifyFileContext(filePath: string): 'PRODUCTION' | 'TEST_FIXTURE' | 'SANDBOX' {
  const lower = filePath.toLowerCase();
  const testPatterns = ['security_tests/', 'test/', 'tests/', '__tests__/', 'spec/', 'fixtures/', 'mocks/', 'examples/'];
  const sandboxPatterns = ['sandbox', 'sentinel-sandbox', 'baseline.js', 'simulation'];
  if (sandboxPatterns.some(p => lower.includes(p))) return 'SANDBOX';
  if (testPatterns.some(p => lower.includes(p))) return 'TEST_FIXTURE';
  return 'PRODUCTION';
}

interface WalkState {
  filePath: string;
  findings: ForensicFinding[];
  hasNetworkCall: boolean;
  hasCommandExecution: boolean;
  hasUnsafeBlock: boolean;
  isBuildRs: boolean;
}

function walkTree(node: TSNode, sourceCode: string, state: WalkState): void {
  if (!node) return;
  const type = node.type;
  const lineNum = node.startPosition.row + 1;
  const text = node.text || '';
  const snippet = sourceCode.substring(node.startIndex, Math.min(node.endIndex, node.startIndex + 150));
  const context = classifyFileContext(state.filePath);

  // 1. Process imports (use declarations)
  if (type === 'use_declaration' || type === 'use_list' || type === 'use_wildcard') {
    if (text.includes('std::process::Command') || text.includes('std::process')) {
      state.findings.push({
        type: 'RUST_PROCESS_IMPORT',
        severity: state.isBuildRs ? 'HIGH' : 'LOW',
        riskLevel: state.isBuildRs ? 8 : 3,
        message: `Process execution library imported in Rust file: '${state.filePath}'`,
        evidence: text,
        line_number: lineNum,
        source_engine: 'AST',
        context,
      });
    }
    if (text.includes('std::net') || text.includes('reqwest') || text.includes('hyper')) {
      state.findings.push({
        type: 'RUST_NETWORK_IMPORT',
        severity: state.isBuildRs ? 'HIGH' : 'LOW',
        riskLevel: state.isBuildRs ? 8 : 3,
        message: `Network/Socket library imported in Rust file: '${state.filePath}'`,
        evidence: text,
        line_number: lineNum,
        source_engine: 'AST',
        context,
      });
    }
  }

  // 2. Process call expressions
  if (type === 'call_expression') {
    // Look for Command::new / process execution
    if (text.includes('Command::new') || text.includes('process::Command')) {
      state.hasCommandExecution = true;

      let severity: ForensicFinding['severity'] = 'MEDIUM';
      let riskLevel = 6;
      let msg = `System process execution capability detected via Command::new() in '${state.filePath}'`;
      let typeStr = 'RUST_PROCESS_EXEC';

      if (state.isBuildRs) {
        severity = 'CRITICAL';
        riskLevel = 9;
        msg = `CRITICAL: System process execution initiated within build script (build.rs) at '${state.filePath}' — potential supply chain downloader/RCE cradle!`;
        typeStr = 'MALICIOUS_BUILD_SCRIPT_EXEC';
      }

      // Check if arguments or text are dangerous (curl, sh, netcat, etc.)
      if (/curl\s+|wget\s+|bash\s+|sh\s+|powershell\s+|cmd\s+|nc\s+|netcat|chmod\s+\+x/i.test(text)) {
        severity = 'CRITICAL';
        riskLevel = 10;
        msg = `CRITICAL: Dangerous shell command pattern or download utility execution detected via Command::new() in '${state.filePath}'`;
        typeStr = 'MALICIOUS_SHELL_EXEC';
      }

      state.findings.push({
        type: typeStr,
        severity,
        riskLevel,
        message: msg,
        evidence: snippet,
        line_number: lineNum,
        source_engine: 'AST',
        context,
        impact: 'Arbitrary shell command execution on building/running machine',
        remediation: 'Avoid running child processes in build.rs. If necessary, use precise static target rules and validate all parameters.',
      });
    }

    // Look for network connect/get
    if (text.includes('TcpStream::connect') || text.includes('UdpSocket::') || text.includes('reqwest::get') || text.includes('Client::new') || text.includes('std::net::') || text.includes('reqwest::')) {
      state.hasNetworkCall = true;

      let severity: ForensicFinding['severity'] = 'MEDIUM';
      let riskLevel = 6;
      let msg = `Network connection capability detected in '${state.filePath}'`;
      let typeStr = 'RUST_NETWORK_CALL';

      if (state.isBuildRs) {
        severity = 'CRITICAL';
        riskLevel = 9;
        msg = `CRITICAL: Outbound network request initiated within build script (build.rs) at '${state.filePath}' — potential environment exfiltration / dynamic payload loader!`;
        typeStr = 'MALICIOUS_BUILD_SCRIPT_NET';
      }

      state.findings.push({
        type: typeStr,
        severity,
        riskLevel,
        message: msg,
        evidence: snippet,
        line_number: lineNum,
        source_engine: 'AST',
        context,
        impact: 'Data exfiltration or dynamic code loader',
        remediation: 'Build scripts should never initiate network requests. Cargo relies on offline-first reproducible building. Remove all networking from build.rs.',
      });
    }
  }

  // 3. Process macro invocations
  if (type === 'macro_invocation') {
    if (text.startsWith('include_bytes!') || text.startsWith('include_str!')) {
      state.findings.push({
        type: 'RUST_PAYLOAD_EMBEDDING',
        severity: state.isBuildRs ? 'HIGH' : 'LOW',
        riskLevel: state.isBuildRs ? 8 : 4,
        message: `Compile-time file embedding detected via macro in '${state.filePath}' — inspect embedded file integrity`,
        evidence: snippet,
        line_number: lineNum,
        source_engine: 'AST',
        context,
        impact: 'Malicious payload embedding in compiled output',
        remediation: 'Verify the referenced file path and ensure it is not an obfuscated or untrusted payload binary.',
      });
    }
  }

  // 4. Process unsafe blocks
  if (type === 'unsafe_block' || text.startsWith('unsafe ')) {
    state.hasUnsafeBlock = true;
    if (state.isBuildRs) {
      state.findings.push({
        type: 'RUST_UNSAFE_BUILD_SCRIPT',
        severity: 'HIGH',
        riskLevel: 7,
        message: `Unsafe code block inside build script (build.rs) at '${state.filePath}' — inspect for raw pointers, native loads or memory safety bypasses`,
        evidence: snippet,
        line_number: lineNum,
        source_engine: 'AST',
        context,
        impact: 'Bypassing Rust safety guarantees in build toolchain',
        remediation: 'Avoid unsafe blocks in build.rs scripts to preserve chain reliability.',
      });
    }
  }

  // 5. Look at string literals for C2 URL / threat intelligence or dangerous command execution patterns
  if (type === 'string_literal') {
    const textVal = text.replace(/^["']|["']$/g, ''); // strip quotes
    if (textVal.startsWith('http://') || textVal.startsWith('https://')) {
      try {
        const iocResult = checkUrl(textVal, { isLifecycleScript: state.isBuildRs });
        if (iocResult.blocked) {
          state.findings.push({
            type: 'KNOWN_C2_DOMAIN',
            severity: iocResult.severity as any,
            riskLevel: iocResult.severity === 'CRITICAL' ? 10 : 8,
            message: `URL in Rust file matches known malicious C2: ${iocResult.campaign}`,
            evidence: textVal,
            line_number: lineNum,
            source_engine: 'AST',
            context,
          });
        }
      } catch {
        // Best-effort if threat intel module isn't fully loaded or available in test script
      }
    }

    // Check if the string literal contains suspicious command piping or cradles
    if (/curl\s+|wget\s+|bash\s+|sh\s+|powershell\s+|cmd\s+|nc\s+|netcat|chmod\s+\+x/i.test(textVal)) {
      state.findings.push({
        type: 'MALICIOUS_SHELL_EXEC',
        severity: 'CRITICAL',
        riskLevel: 10,
        message: `CRITICAL: Dangerous shell command pattern or download cradle detected in string literal: '${textVal}'`,
        evidence: textVal,
        line_number: lineNum,
        source_engine: 'AST',
        context,
      });
    }
  }

  // Recurse into children
  if (node.children) {
    for (const child of node.children) {
      walkTree(child, sourceCode, state);
    }
  }
}

export async function analyze(code: string, filePath: string = 'unknown'): Promise<ForensicFinding[]> {
  const findings: ForensicFinding[] = [];
  const context = classifyFileContext(filePath);
  const isBuildRs = filePath.endsWith('build.rs') || filePath.includes('build.rs');

  let parser: TSParser;
  try {
    parser = await ensureParser();
  } catch (err: any) {
    findings.push({
      type: 'PARSER_INIT_FAILURE',
      severity: 'LOW',
      riskLevel: 4,
      message: 'Rust AST parser initialization failed for \'' + filePath + '\'',
      evidence: `Tree-sitter WASM could not be loaded: ${err?.message || err}`,
      source_engine: 'AST',
      context,
    });
    return findings;
  }

  let tree: any;
  try {
    tree = parser.parse(code);
  } catch (err: any) {
    findings.push({
      type: 'PARSER_FAILURE',
      severity: 'LOW',
      riskLevel: 4,
      message: 'AST parsing failed for \'' + filePath + '\'',
      evidence: `Tree-sitter parse error: ${err?.message || err}`,
      source_engine: 'AST',
      context,
    });
    return findings;
  }

  if (!tree || !tree.rootNode) {
    findings.push({
      type: 'PARSER_FAILURE',
      severity: 'LOW',
      riskLevel: 4,
      message: 'AST parsing returned null/empty tree for \'' + filePath + '\'',
      evidence: code.substring(0, 100),
      source_engine: 'AST',
      context,
    });
    return findings;
  }

  const root = tree.rootNode;

  if (root.hasError) {
    findings.push({
      type: 'PARSE_ERROR_IN_TREE',
      severity: 'LOW',
      riskLevel: 3,
      message: 'Rust file \'' + filePath + '\' contains parsing errors',
      evidence: code.substring(0, 200),
      line_number: 1,
      source_engine: 'AST',
      context,
    });
  }

  const state: WalkState = {
    filePath,
    findings: [],
    hasNetworkCall: false,
    hasCommandExecution: false,
    hasUnsafeBlock: false,
    isBuildRs,
  };

  walkTree(root, code, state);

  // Return deduplicated findings (merge identical types on same line)
  const seenKeys = new Set<string>();
  for (const f of state.findings) {
    const key = `${f.type}:${f.line_number}`;
    if (!seenKeys.has(key)) {
      seenKeys.add(key);
      findings.push(f);
    }
  }

  return findings;
}
