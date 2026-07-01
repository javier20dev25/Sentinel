/**
 * Sentinel: Python AST Inspector — Tree-sitter based analyzer
 *
 * Replaces regex-only Python scanning with a real parser, enabling
 * semantic detection of supply chain attacks, dataflow lite analysis,
 * and composite kill-chain detection.
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
      const pythonWasmPath = path.join(process.cwd(), 'node_modules', 'tree-sitter-python', 'tree-sitter-python.wasm');
      const lang: TSLanguage = await ParserModule.Language.load(pythonWasmPath);
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

const DANGEROUS_EXEC_MODULES = new Set([
  'os', 'subprocess', 'shutil', 'pty', 'signal',
]);

const EXEC_SINKS = new Set([
  'exec', 'eval', 'execfile', 'compile',
  'system', 'popen', 'call', 'run', 'check_call', 'check_output',
]);

const NETWORK_MODULES = new Set([
  'requests', 'urllib', 'urllib2', 'urllib3', 'aiohttp', 'httpx',
  'http.client', 'http.server', 'socketserver', 'socket',
  'ftplib', 'smtplib', 'poplib', 'imaplib',
]);

const SENSITIVE_PATHS = [
  '.ssh', '.aws', '.gcs', '.azure', '/etc/passwd', '/etc/shadow',
  '/etc/ssl', '/etc/kubernetes', '.kube', 'id_rsa', 'id_ed25519',
  '.npmrc', '.npmtoken', 'credentials', 'secrets.json', '.htpasswd',
  'authorized_keys', '.gitconfig', '.docker', 'config.json',
];

const SENSITIVE_ENV_VARS = [
  'AWS_SECRET', 'AWS_ACCESS', 'GITHUB_TOKEN', 'GH_TOKEN',
  'NPM_TOKEN', 'DATABASE_URL', 'SECRET_KEY', 'API_KEY',
  'AUTH_TOKEN', 'PRIVATE_KEY', 'STRIPE', 'SLACK_TOKEN',
  'DISCORD_TOKEN', 'SUPABASE_URL', 'SUPABASE_KEY',
  'OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'TOGETHER_API_KEY',
];

const DANGEROUS_SHELL_COMMANDS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /curl\s+(?:-fsSL|-s|-L)?\s*\S+\s*(?:\||\|;)\s*(?:bash|sh|zsh|node|python)/i, label: 'curl_pipe_shell' },
  { pattern: /wget\s+(?:-qO-|-qO|-O-)?\s*\S+\s*(?:\||\|;)\s*(?:bash|sh|zsh|node|python)/i, label: 'wget_pipe_shell' },
  { pattern: /bash\s+-c\s+[\""'].*curl/, label: 'bash_c_curl' },
  { pattern: /(?:curl|wget)\s+.*(?:--output|-o)\s+\S+/i, label: 'curl_wget_download' },
  { pattern: /chmod\s+\+x\s+\S+/, label: 'chmod_plus_x' },
  { pattern: /(?:mv|cp)\s+\S+\s+\/usr\/(?:local\/)?bin\//, label: 'binary_injection' },
  { pattern: /powershell\s+(?:-enc|-e|-command|-c)\s+/i, label: 'powershell_encoded' },
  { pattern: /Invoke-Expression|Invoke-WebRequest|IEX\s*\(/i, label: 'powershell_download_cradle' },
];

interface TaintRecord {
  isTainted: boolean;
  source: 'literal' | 'parameter' | 'call' | 'concat' | 'unknown' | 'import';
  sourceCall?: string;
  dependsOn: string[];
  fromConcat: boolean;
  line: number;
}

interface WalkState {
  filePath: string;
  imports: Map<string, { module: string; alias: string | null; line: number }>;
  variables: Map<string, TaintRecord>;
  taints: string[];
  strings: Array<{ value: string; line: number; start: number; end: number }>;
  dangerousCalls: Array<{
    call: string;
    fullName: string;
    args: string[];
    line: number;
    snippet: string;
  }>;
  findings: ForensicFinding[];
  hasBase64Decode: boolean;
  hasExecCall: boolean;
  hasNetworkCall: boolean;
  hasEnvAccess: boolean;
  hasSensitivePathRef: boolean;
  sysModulesManipulated: boolean;
  hasSetupPyNetworkCall: boolean;
  isSetupPy: boolean;
  isLifecycleScript: boolean;
  executedArgs: string[];
  networkArgs: string[];
}

function extractStringValue(node: TSNode, _sourceCode: string): string | null {
  if (!node) return null;
  const t = node.type;
  if (t === 'string') {
    const text = node.text;
    if (!text) return null;
    const first = text[0];
    if (first === 'f' || first === 'F') return null;
    let content: string;
    if (text.startsWith('r') || text.startsWith('R') || text.startsWith('b') || text.startsWith('B')) {
      content = text.slice(2, -1);
    } else if (text.startsWith('u')) {
      content = text.slice(2, -1);
    } else {
      content = text.slice(1, -1);
    }
    return content;
  }
  if (t === 'concatenated_string') {
    const parts: string[] = [];
    for (const child of node.children) {
      const part = extractStringValue(child, _sourceCode);
      if (part === null) return null;
      parts.push(part);
    }
    return parts.join('');
  }
  return null;
}

function getCallTarget(node: TSNode): { module: string | null; func: string; full: string } | null {
  if (node.type === 'identifier') {
    return { module: null, func: node.text, full: node.text };
  }
  if (node.type === 'attribute') {
    const children = node.children;
    if (children.length < 2) return null;
    const obj = children[0];
    const attr = children[children.length - 1];
    if (attr.type !== 'identifier') return null;
    const func = attr.text;
    if (obj.type === 'identifier') {
      return { module: obj.text, func, full: obj.text + '.' + func };
    }
    if (obj.type === 'attribute') {
      const inner = getCallTarget(obj);
      if (inner) return { module: inner.full, func, full: inner.full + '.' + func };
    }
    return { module: null, func, full: func };
  }
  return null;
}

function isLiteralNode(node: TSNode): boolean {
  const t = node.type;
  if (t === 'string' || t === 'interpolated_string') {
    const text = node.text;
    return !(text[0] === 'f' || text[0] === 'F' || text.startsWith('f"') || text.startsWith("f'"));
  }
  return t === 'true' || t === 'false' || t === 'integer' || t === 'float' || t === 'none';
}

function getArgs(node: TSNode): TSNode[] {
  for (const child of node.children) {
    if (child.type === 'argument_list') {
      return child.children.filter((c: TSNode) =>
        c.type !== '(' && c.type !== ')' && c.type !== ','
      );
    }
  }
  return [];
}

function isStringConcat(node: TSNode): boolean {
  if (node.type !== 'binary_operator') return false;
  const children = node.children;
  if (children.length < 2) return false;
  const opIdx = children.findIndex((c: TSNode) => c.type === 'operator');
  if (opIdx === -1) return false;
  const op = children[opIdx];
  return op.text === '+' && children.some((c: TSNode) => isLiteralNode(c) || c.type === 'identifier');
}

function isTaintedNode(node: TSNode, state: WalkState): boolean {
  if (node.type === 'identifier') {
    const name = node.text;
    if (name === 'input' || name === 'raw_input') return false;
    const record = state.variables.get(name);
    if (record && record.isTainted) return true;
    if (state.taints.includes(name)) return true;
    return false;
  }
  if (node.type === 'binary_operator') {
    return node.children.some((c: TSNode) => isTaintedNode(c, state));
  }
  if (node.type === 'call') {
    return true;
  }
  return false;
}

function containsDangerousCommand(str: string): { matched: boolean; label: string } {
  for (const entry of DANGEROUS_SHELL_COMMANDS) {
    if (entry.pattern.test(str)) {
      return { matched: true, label: entry.label };
    }
  }
  return { matched: false, label: '' };
}

function taintVariable(name: string, source: TaintRecord['source'], state: WalkState,
  sourceCall?: string, dependsOn?: string[]): void {
  const existing = state.variables.get(name);
  if (existing && existing.isTainted) return;
  state.variables.set(name, {
    isTainted: true,
    source,
    sourceCall,
    dependsOn: dependsOn ?? [],
    fromConcat: false,
    line: 0,
  });
}

function propagateTaintFromCall(callName: string, targetVar: string | null, state: WalkState): void {
  const taintSources = new Set([
    'input', 'raw_input', 'sys.stdin.read', 'sys.stdin.readline',
    'sys.argv', 'os.environ.get', 'os.environ', 'open', 'io.open',
    'pathlib.Path.read_text', 'pathlib.Path.read_bytes',
  ]);
  if (callName && taintSources.has(callName) && targetVar) {
    if (callName === 'input' || callName === 'raw_input') {
      taintVariable(targetVar, 'call', state, 'input', []);
    } else if (callName === 'sys.argv' || callName === 'sys.stdin.read') {
      taintVariable(targetVar, 'call', state, 'stdin', []);
    } else if (callName.startsWith('os.environ')) {
      taintVariable(targetVar, 'call', state, 'environ', []);
    } else if (callName === 'open') {
      taintVariable(targetVar, 'call', state, 'file_read', []);
    }
  }
}

function walkFunctionDef(node: TSNode, _sourceCode: string, state: WalkState): void {
  for (const child of node.children) {
    if (child.type === 'parameters') {
      for (const param of child.children) {
        if (param.type === 'identifier') {
          const name = param.text;
          if (name !== 'self' && name !== 'cls') {
            taintVariable(name, 'parameter', state, 'function_param', []);
          }
        }
        if (param.type === 'typed_parameter' || param.type === 'default_parameter') {
          for (const sub of param.children) {
            if (sub.type === 'identifier' && sub.text !== 'self' && sub.text !== 'cls') {
              taintVariable(sub.text, 'parameter', state, 'function_param', []);
            }
          }
        }
      }
    }
  }
}

function processImportStatement(node: TSNode, _sourceCode: string, state: WalkState): void {
  if (node.type === 'import_statement') {
    for (const child of node.children) {
      if (child.type === 'dotted_name') {
        state.imports.set(child.text, { module: child.text, alias: null, line: child.startPosition.row });
      } else if (child.type === 'aliased_import') {
        const kids = child.children;
        if (kids.length >= 3) {
          const moduleName = kids[0].text;
          const alias = kids[2]?.type === 'identifier' ? kids[2].text : null;
          state.imports.set(alias || moduleName, { module: moduleName, alias, line: child.startPosition.row });
        }
      }
    }
  }
  if (node.type === 'import_from_statement') {
    let sourceModule = '';
    const members: Array<{ name: string; alias: string | null }> = [];
    for (const child of node.children) {
      if (child.type === 'dotted_name' && !sourceModule) {
        sourceModule = child.text;
      } else if (child.type === 'dotted_name' && sourceModule) {
        members.push({ name: child.text, alias: null });
      } else if (child.type === 'aliased_import') {
        const kids = child.children;
        if (kids.length >= 1) {
          const memberName = kids[0].text;
          const alias = kids[2]?.type === 'identifier' ? kids[2].text : null;
          members.push({ name: memberName, alias });
        }
      }
    }
    for (const member of members) {
      const fullName = sourceModule + '.' + member.name;
      const alias = member.alias || member.name;
      state.imports.set(alias, { module: fullName, alias, line: node.startPosition.row });
    }
  }
}

function resolveImport(name: string, state: WalkState): string | null {
  const record = state.imports.get(name);
  if (record) return record.module;
  return null;
}

function processAssignment(node: TSNode, _sourceCode: string, state: WalkState): void {
  const children = node.children;
  if (children.length < 2) return;
  const rhsIndex = children.findIndex((c: TSNode) => c.type === '=' || c.type === '+=' || c.type === '-=' || c.type === '*' || c.type === '/=' || c.type === ':' || c.type === 'operator');
  if (rhsIndex === -1) return;
  const lhs = children.slice(0, rhsIndex).filter((c: TSNode) => c.type === 'identifier' || c.type === 'attribute' || c.type === 'subscript');
  const rhs = children.slice(rhsIndex + 1);
  if (lhs.length === 0) return;
  const targetName = lhs[0].text;
  const isAugmented = children.some((c: TSNode) => c.type === '+=' || c.type === '-=');
  if (targetName.startsWith('sys.modules') && targetName.includes('[')) {
    state.sysModulesManipulated = true;
    state.findings.push({
      type: 'SYS_MODULES_MANIPULATION', severity: 'HIGH', riskLevel: 8,
      message: 'sys.modules manipulation via subscript assignment in \'' + state.filePath + '\'',
      evidence: targetName, line_number: node.startPosition.row + 1,
      source_engine: 'AST', context: classifyFileContext(state.filePath),
    });
  }
  if (rhs.length === 0) return;
  const valueNode = rhs[0];
  if (isAugmented) {
    const existing = state.variables.get(targetName);
    const isValueNonLiteral = valueNode && !isLiteralNode(valueNode);
    state.variables.set(targetName, {
      isTainted: existing?.isTainted || isValueNonLiteral || false,
      source: 'concat',
      sourceCall: existing?.sourceCall,
      dependsOn: existing?.dependsOn || [],
      fromConcat: true,
      line: node.startPosition.row,
    });
    return;
  }
  if (isLiteralNode(valueNode)) {
    state.variables.set(targetName, { isTainted: false, source: 'literal', dependsOn: [], fromConcat: false, line: node.startPosition.row });
    return;
  }
  if (valueNode.type === 'binary_operator') {
    const depNames: string[] = [];
    for (const child of valueNode.children) {
      if (child.type === 'identifier') depNames.push(child.text);
    }
    const anyTainted = depNames.some((n: string) => {
      const r = state.variables.get(n);
      return r?.isTainted || state.taints.includes(n);
    });
    state.variables.set(targetName, {
      isTainted: anyTainted || isAugmented,
      source: anyTainted ? 'concat' : 'unknown',
      dependsOn: depNames,
      fromConcat: true,
      line: node.startPosition.row,
    });
    return;
  }
  if (valueNode.type === 'call') {
    const callCallee = valueNode.children.length > 0 ? valueNode.children[0] : null;
    const target = callCallee ? getCallTarget(callCallee) : null;
    const args = getArgs(valueNode);
    const callFull = target ? target.full : 'unknown';
    const anyTaintedArg = args.some((a: TSNode) => isTaintedNode(a, state));
    state.variables.set(targetName, {
      isTainted: anyTaintedArg || false,
      source: 'call',
      sourceCall: callFull,
      dependsOn: args.filter((a: TSNode) => a.type === 'identifier').map((a: TSNode) => a.text),
      fromConcat: false,
      line: node.startPosition.row,
    });
    propagateTaintFromCall(callFull, targetName, state);
    return;
  }
  if (valueNode.type === 'identifier' || valueNode.type === 'attribute') {
    const name = valueNode.type === 'identifier' ? valueNode.text : valueNode.text.split('.').pop()!;
    const existing = state.variables.get(name);
    if (existing) {
      state.variables.set(targetName, { ...existing, line: node.startPosition.row });
    } else if (state.taints.includes(name)) {
      taintVariable(targetName, 'unknown', state, undefined, [name]);
    } else {
      state.variables.set(targetName, { isTainted: false, source: 'unknown', dependsOn: [name], fromConcat: false, line: node.startPosition.row });
    }
    if (valueNode.type === 'attribute' && valueNode.text.includes('environ')) {
      taintVariable(targetName, 'call', state, 'environ', []);
    }
    return;
  }
  if (valueNode.type === 'subscript') {
    const objNode = valueNode.children[0];
    if (objNode) {
      const fullText = valueNode.text;
      if (fullText.includes('argv') || fullText.includes('environ')) {
        taintVariable(targetName, 'call', state, 'subscript_access', [objNode.text]);
      } else if (objNode.type === 'identifier') {
        const existing = state.variables.get(objNode.text);
        if (existing) {
          state.variables.set(targetName, { ...existing, line: node.startPosition.row });
        }
      }
    }
    return;
  }
  state.variables.set(targetName, { isTainted: false, source: 'unknown', dependsOn: [], fromConcat: false, line: node.startPosition.row });
}

function processCall(node: TSNode, sourceCode: string, state: WalkState): void {
  const callee = node.children.length > 0 ? node.children[0] : null;
  if (!callee) return;
  const target = getCallTarget(callee);
  if (!target) return;
  const { module, func, full } = target;
  const args = getArgs(node);
  const argTexts = args.map((a: TSNode) => sourceCode.substring(a.startIndex, a.endIndex));
  const snippet = sourceCode.substring(node.startIndex, Math.min(node.endIndex, node.startIndex + 150));
  const lineNum = node.startPosition.row + 1;
  state.dangerousCalls.push({ call: func, fullName: full, args: argTexts, line: lineNum, snippet });

  const isOsOrSubprocess = (full === 'os.system' || full === 'os.popen' ||
    func === 'system' || func === 'popen' || func === 'call' || func === 'run' ||
    func === 'check_call' || func === 'check_output');
  const parentModule = resolveImport(module || '', state);
  const isSubprocessExec = !!parentModule && parentModule.startsWith('subprocess') &&
    (func === 'call' || func === 'run' || func === 'Popen' || func === 'check_call' || func === 'check_output');

  if (isOsOrSubprocess || isSubprocessExec) {
    state.hasExecCall = true;
    const cmdArg = args[0];
    if (cmdArg && isLiteralNode(cmdArg)) {
      const strVal = extractStringValue(cmdArg, sourceCode);
      if (strVal) {
        const dangerCheck = containsDangerousCommand(strVal);
        if (dangerCheck.matched) {
          state.findings.push({
            type: 'MALICIOUS_DOWNLOAD_EXEC', severity: 'CRITICAL', riskLevel: 10,
            message: 'Dangerous command pattern \'' + dangerCheck.label + '\' in ' + full + ' in \'' + state.filePath + '\'',
            evidence: snippet, line_number: lineNum, source_engine: 'AST', context: classifyFileContext(state.filePath),
          });
        }
      }
    } else if (cmdArg && isTaintedNode(cmdArg, state)) {
      state.executedArgs.push(snippet);
      state.hasExecCall = true;
      state.findings.push({
        type: 'COMMAND_INJECTION_USER_CONTROLLED', severity: 'CRITICAL', riskLevel: 10,
        message: 'User-controlled input passed to ' + full + ' in \'' + state.filePath + '\' — command injection risk',
        evidence: snippet, line_number: lineNum,
        impact: 'Remote code execution via shell command injection',
        remediation: 'Use subprocess with argument list instead of shell=True and validate all user input',
        source_engine: 'AST', context: classifyFileContext(state.filePath),
      });
    }
  }

  if (func === 'exec' || func === 'eval') {
    state.hasExecCall = true;
    state.executedArgs.push(snippet);
    const codeArg = args[0];
    if (!codeArg || isTaintedNode(codeArg, state)) {
      state.findings.push({
        type: 'DYNAMIC_CODE_EXECUTION', severity: 'CRITICAL', riskLevel: 10,
        message: func + '() with potentially user-controlled input in \'' + state.filePath + '\'',
        evidence: snippet, line_number: lineNum,
        impact: 'Arbitrary code execution',
        remediation: 'Avoid exec/eval entirely. Use safe sandboxed evaluation.',
        source_engine: 'AST', context: classifyFileContext(state.filePath),
      });
    } else if (!isLiteralNode(codeArg)) {
      state.findings.push({
        type: 'DYNAMIC_CODE_EXECUTION', severity: 'HIGH', riskLevel: 9,
        message: func + '() with non-literal argument in \'' + state.filePath + '\'',
        evidence: snippet, line_number: lineNum, source_engine: 'AST', context: classifyFileContext(state.filePath),
      });
    } else {
      state.findings.push({
        type: 'DYNAMIC_CODE_EXECUTION', severity: 'HIGH', riskLevel: 8,
        message: func + '() with literal code in \'' + state.filePath + '\'',
        evidence: snippet, line_number: lineNum, source_engine: 'AST', context: classifyFileContext(state.filePath),
      });
    }
  }

  if ((full === 'requests.get' || full === 'requests.post' || full === 'requests.put' ||
      full === 'requests.request') || func === 'urlopen' || func === 'urlretrieve') {
    state.hasNetworkCall = true;
    state.networkArgs.push(snippet);
    const urlArg = args[0];
    const isInterpolated = urlArg && (urlArg.type === 'interpolated_string' || urlArg.type === 'string_interpolation');
    const varRecord = urlArg && urlArg.type === 'identifier' ? state.variables.get(urlArg.text) : undefined;
    if (urlArg && (isStringConcat(urlArg) || (urlArg.type === 'identifier' && (varRecord?.fromConcat || varRecord?.isTainted)))) {
      state.findings.push({
        type: 'DYNAMIC_URL_CONSTRUCTION', severity: 'CRITICAL', riskLevel: 10,
        message: 'URL constructed via string concatenation in ' + full + ' call in \'' + state.filePath + '\' — potential SSRF',
        evidence: snippet, line_number: lineNum,
        impact: 'Server-Side Request Forgery or data exfiltration',
        remediation: 'Use allowlisted URLs only. Never construct URLs from untrusted input.',
        source_engine: 'AST', context: classifyFileContext(state.filePath),
      });
    } else if (urlArg && (!isLiteralNode(urlArg) || isInterpolated)) {
      state.findings.push({
        type: 'NETWORK_CALL_VARIABLE_URL', severity: 'HIGH', riskLevel: 8,
        message: 'Network call with non-literal URL in \'' + state.filePath + '\'',
        evidence: snippet, line_number: lineNum, source_engine: 'AST', context: classifyFileContext(state.filePath),
      });
    } else if (urlArg) {
      const urlStr = extractStringValue(urlArg, sourceCode);
      if (urlStr) {
        try {
          const iocResult = checkUrl(urlStr, { isLifecycleScript: state.isLifecycleScript });
          if (iocResult.blocked) {
            state.findings.push({
              type: 'KNOWN_C2_DOMAIN', severity: iocResult.severity as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO',
              riskLevel: iocResult.severity === 'CRITICAL' ? 10 : 8,
              message: 'URL in \'' + state.filePath + '\' matches known C2: ' + iocResult.campaign,
              evidence: urlStr.substring(0, 200), line_number: lineNum, source_engine: 'AST', context: classifyFileContext(state.filePath),
            });
          }
        } catch {
          // threat intel unavailable
        }
      }
    }
  }

  const isBase64Decode = full === 'base64.b64decode' || full === 'base64.decodestring' ||
    func === 'b64decode' || func === 'decodestring' || full === 'codecs.decode' ||
    func === 'base64_decode';
  if (isBase64Decode) state.hasBase64Decode = true;
  if (callee.type === 'attribute') {
    for (const sub of callee.children) {
      if (sub.type === 'call') processCall(sub, sourceCode, state);
    }
  }

  if (full === '__import__' || full === '__builtins__.__import__' || full === 'builtins.__import__') {
    const nameArg = args[0];
    if (!nameArg || !isLiteralNode(nameArg)) {
      state.findings.push({
        type: 'DYNAMIC_IMPORT', severity: 'CRITICAL', riskLevel: 10,
        message: 'Dynamic __import__() with non-literal module name in \'' + state.filePath + '\'',
        evidence: snippet, line_number: lineNum,
        impact: 'Arbitrary module loading',
        remediation: 'Use static imports only. Do not dynamically import modules based on user input.',
        source_engine: 'AST', context: classifyFileContext(state.filePath),
      });
    }
  }

  if (full === 'importlib.import_module' || full === 'importlib.importlib.import_module') {
    const nameArg = args[0];
    if (!nameArg || !isLiteralNode(nameArg)) {
      state.findings.push({
        type: 'DYNAMIC_IMPORT', severity: 'CRITICAL', riskLevel: 10,
        message: 'importlib.import_module() with non-literal module name in \'' + state.filePath + '\'',
        evidence: snippet, line_number: lineNum, source_engine: 'AST', context: classifyFileContext(state.filePath),
      });
    }
  }

  if (full === 'pickle.loads' || full === 'pickle.load' || full === 'pickle.Unpickler') {
    state.findings.push({
      type: 'UNSAFE_DESERIALIZATION', severity: 'CRITICAL', riskLevel: 10,
      message: 'Unsafe pickle deserialization in \'' + state.filePath + '\'',
      evidence: snippet, line_number: lineNum,
      impact: 'Remote code execution via pickle opcodes',
      remediation: 'Use JSON or other safe serialization formats. Never unpickle untrusted data.',
      source_engine: 'AST', context: classifyFileContext(state.filePath),
    });
  }

  if (func === 'compile') {
    const sourceArg = args[0];
    if (!sourceArg || !isLiteralNode(sourceArg)) {
      state.findings.push({
        type: 'DYNAMIC_COMPILE', severity: 'HIGH', riskLevel: 9,
        message: 'compile() with non-literal source in \'' + state.filePath + '\'',
        evidence: snippet, line_number: lineNum, source_engine: 'AST', context: classifyFileContext(state.filePath),
      });
    }
  }

  if (full === 'open' || func === 'open') {
    const pathArg = args[0];
    const modeArg = args[1];
    if (pathArg && isLiteralNode(pathArg)) {
      const pathStr = extractStringValue(pathArg, sourceCode);
      if (pathStr) {
        let isWrite = true;
        if (modeArg && isLiteralNode(modeArg)) {
          const modeVal = extractStringValue(modeArg, sourceCode);
          if (modeVal && !modeVal.includes('w') && !modeVal.includes('a') && !modeVal.includes('+')) isWrite = false;
        }
        if (isWrite && SENSITIVE_PATHS.some((p: string) => pathStr.includes(p))) {
          state.hasSensitivePathRef = true;
          state.findings.push({
            type: 'SENSITIVE_FILE_WRITE', severity: 'HIGH', riskLevel: 9,
            message: 'Writing to sensitive path \'' + pathStr + '\' in \'' + state.filePath + '\'',
            evidence: snippet, line_number: lineNum, source_engine: 'AST', context: classifyFileContext(state.filePath),
          });
        }
      }
    }
  }

  if (full === 'os.environ.get' || func === 'environ.get' || full === 'os.getenv' ||
    func === 'getenv' || full === 'os.environ') {
    const keyArg = args[0];
    state.hasEnvAccess = true;
    if (keyArg && isLiteralNode(keyArg)) {
      const keyStr = extractStringValue(keyArg, sourceCode);
      if (keyStr && SENSITIVE_ENV_VARS.some((v: string) => keyStr.toUpperCase().includes(v))) {
        state.findings.push({
          type: 'SENSITIVE_ENV_ACCESS', severity: 'HIGH', riskLevel: 9,
          message: 'Access to sensitive environment variable \'' + keyStr + '\' in \'' + state.filePath + '\'',
          evidence: snippet, line_number: lineNum, source_engine: 'AST', context: classifyFileContext(state.filePath),
        });
      }
    } else if (keyArg && isTaintedNode(keyArg, state)) {
      state.findings.push({
        type: 'SENSITIVE_ENV_ACCESS', severity: 'HIGH', riskLevel: 8,
        message: 'Environment variable access with dynamic key in \'' + state.filePath + '\'',
        evidence: snippet, line_number: lineNum, source_engine: 'AST', context: classifyFileContext(state.filePath),
      });
    }
  }

  if (full.includes('sys.modules') || (func === 'modules' && module === 'sys') ||
    argTexts.some((a: string) => a.includes('sys.modules'))) {
    state.sysModulesManipulated = true;
    state.findings.push({
      type: 'SYS_MODULES_MANIPULATION', severity: 'HIGH', riskLevel: 9,
      message: 'sys.modules manipulation in \'' + state.filePath + '\' — potential module hijacking',
      evidence: snippet, line_number: lineNum,
      impact: 'Module hijacking: attacker can replace loaded modules with malicious code',
      remediation: 'Do not modify sys.modules. Use virtual environments for dependency isolation.',
      source_engine: 'AST', context: classifyFileContext(state.filePath),
    });
  }

  if ((state.isSetupPy || state.isLifecycleScript) &&
    (full.includes('ftplib') || full.includes('smtplib') || full.includes('request') || full.includes('urllib'))) {
    state.findings.push({
      type: 'NETWORK_CALL_INSTALL_SCRIPT', severity: 'HIGH', riskLevel: 9,
      message: 'Network call (' + full + ') in setup.py/install script in \'' + state.filePath + '\'',
      evidence: snippet, line_number: lineNum,
      impact: 'Package installation can silently exfiltrate data or download additional payloads',
      remediation: 'Remove network calls from package install scripts.',
      source_engine: 'AST', context: classifyFileContext(state.filePath),
    });
  }

  if ((full === 'yaml.load' || full === 'yaml.load_all') &&
    !argTexts.some((a: string) => a.includes('SafeLoader') || a.includes('BaseLoader') || a.includes('CSafeLoader'))) {
    state.findings.push({
      type: 'UNSAFE_YAML_LOAD', severity: 'MEDIUM', riskLevel: 6,
      message: 'yaml.load() without SafeLoader in \'' + state.filePath + '\' — arbitrary code execution risk',
      evidence: snippet, line_number: lineNum,
      impact: 'YAML deserialization can execute arbitrary Python code',
      remediation: 'Use yaml.safe_load() instead of yaml.load(), or specify SafeLoader explicitly.',
      source_engine: 'AST', context: classifyFileContext(state.filePath),
    });
  }
}

function processStringLiteral(node: TSNode, sourceCode: string, state: WalkState): void {
  const strVal = extractStringValue(node, sourceCode);
  if (strVal === null) return;
  state.strings.push({ value: strVal, line: node.startPosition.row + 1, start: node.startIndex, end: node.endIndex });

  if (SENSITIVE_PATHS.some((p: string) => strVal.includes(p))) {
    state.hasSensitivePathRef = true;
    state.findings.push({
      type: 'SENSITIVE_PATH_REFERENCE', severity: 'HIGH', riskLevel: 7,
      message: 'Reference to sensitive path \'' + strVal.substring(0, 100) + '\' in \'' + state.filePath + '\'',
      evidence: strVal.substring(0, 200), line_number: node.startPosition.row + 1,
      source_engine: 'AST', context: classifyFileContext(state.filePath),
    });
  }

  if (strVal.startsWith('http://') || strVal.startsWith('https://')) {
    try {
      const iocResult = checkUrl(strVal, { isLifecycleScript: state.isLifecycleScript });
      if (iocResult.blocked) {
        state.findings.push({
          type: 'KNOWN_C2_DOMAIN', severity: iocResult.severity as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO',
          riskLevel: iocResult.severity === 'CRITICAL' ? 10 : 8,
          message: 'URL in \'' + state.filePath + '\' matches known C2: ' + iocResult.campaign,
          evidence: strVal.substring(0, 200), line_number: node.startPosition.row + 1,
          source_engine: 'AST', context: classifyFileContext(state.filePath),
        });
      }
    } catch {
      // threat intel unavailable
    }
  }
}

function walkTree(node: TSNode, sourceCode: string, state: WalkState): void {
  if (!node) return;
  const type = node.type;
  switch (type) {
    case 'module':
      for (const child of node.children) walkTree(child, sourceCode, state);
      return;
    case 'import_statement':
    case 'import_from_statement':
      processImportStatement(node, sourceCode, state);
      return;
    case 'function_definition':
      walkFunctionDef(node, sourceCode, state);
      for (const child of node.children) {
        if (child.type === 'block') {
          for (const stmt of child.children) walkTree(stmt, sourceCode, state);
        }
      }
      return;
    case 'expression_statement':
      for (const child of node.children) walkTree(child, sourceCode, state);
      return;
    case 'delete_statement':
      for (const child of node.children) {
        if (child.type === 'subscript' && /sys\.modules/i.test(child.text)) {
          state.sysModulesManipulated = true;
          state.findings.push({
            type: 'SYS_MODULES_MANIPULATION', severity: 'HIGH', riskLevel: 8,
            message: 'sys.modules manipulation via delete in \'' + state.filePath + '\'',
            evidence: child.text, line_number: node.startPosition.row + 1,
            source_engine: 'AST', context: classifyFileContext(state.filePath),
          });
        }
        walkTree(child, sourceCode, state);
      }
      return;
    case 'assignment':
    case 'augmented_assignment':
      processAssignment(node, sourceCode, state);
      for (const child of node.children) {
        if (child.type === 'call') {
          processCall(child, sourceCode, state);
        } else {
          walkTree(child, sourceCode, state);
        }
      }
      return;
    case 'call':
      processCall(node, sourceCode, state);
      return;
    case 'string':
      processStringLiteral(node, sourceCode, state);
      return;
    case 'with_statement':
    case 'decorated_definition':
      for (const child of node.children) walkTree(child, sourceCode, state);
      return;
    case 'try_statement':
    case 'if_statement':
    case 'elif_clause':
    case 'else_clause':
    case 'for_statement':
    case 'while_statement':
    case 'except_clause':
    case 'finally_clause':
      for (const child of node.children) {
        if (child.type !== 'block') walkTree(child, sourceCode, state);
      }
      for (const child of node.children) {
        if (child.type === 'block') {
          for (const stmt of child.children) walkTree(stmt, sourceCode, state);
        }
      }
      return;
    case 'class_definition':
      for (const child of node.children) {
        if (child.type === 'block') {
          for (const stmt of child.children) walkTree(stmt, sourceCode, state);
        }
      }
      return;
    case 'lambda':
      for (const child of node.children) {
        if ((child.type === 'parameters' || child.type === 'lambda_parameters')) {
          for (const param of child.children) {
            if (param.type === 'identifier' && param.text !== 'self' && param.text !== 'cls') {
              taintVariable(param.text, 'parameter', state, 'function_param', []);
            }
          }
        } else if (child.type === 'identifier' && child.text !== 'self' && child.text !== 'cls' && child.text !== 'lambda') {
          taintVariable(child.text, 'parameter', state, 'function_param', []);
        }
        walkTree(child, sourceCode, state);
      }
      return;
    case 'ERROR':
      return;
    default:
      for (const child of node.children) walkTree(child, sourceCode, state);
  }
}

function detectKillChains(state: WalkState): ForensicFinding[] {
  const findings: ForensicFinding[] = [];
  const chain: string[] = [];
  const signals: string[] = [];

  if (state.hasBase64Decode) { chain.push('BASE64_DECODE'); signals.push('Base64 decode operation detected'); }
  if (state.hasExecCall) { chain.push('CODE_EXECUTION'); signals.push('Dynamic code execution: ' + (state.executedArgs[0]?.substring(0, 80) || 'detected')); }
  if (state.hasNetworkCall) { chain.push('NETWORK_CALL'); signals.push('Network request: ' + (state.networkArgs[0]?.substring(0, 80) || 'detected')); }
  if (state.hasEnvAccess) { chain.push('ENV_ACCESS'); signals.push('Environment variable access'); }
  if (state.hasSensitivePathRef) { chain.push('SENSITIVE_PATH'); signals.push('Sensitive file path reference'); }

  if (state.hasBase64Decode && state.hasExecCall) {
    findings.push({
      type: 'KILL_CHAIN_BASE64_EXEC', severity: 'CRITICAL', riskLevel: 10,
      message: 'Kill Chain: Base64 decode → Code execution in \'' + state.filePath + '\'',
      evidence: 'Signals: Base64 decode → Dynamic code execution\n' + signals.join('\n'),
      source_engine: 'HEURISTIC', context: classifyFileContext(state.filePath),
      metadata: { intent_signature: ['EVASION', 'EXECUTION'], signal_pattern: chain, composite: true },
    });
  }

  if (state.hasBase64Decode && state.hasExecCall && state.hasNetworkCall) {
    findings.push({
      type: 'KILL_CHAIN_STAGED_EXFILTRATION', severity: 'CRITICAL', riskLevel: 10,
      message: 'Kill Chain: Base64 decode → Code execution → Network call in \'' + state.filePath + '\'',
      evidence: 'Signals:\n' + signals.join('\n'),
      source_engine: 'HEURISTIC', context: classifyFileContext(state.filePath),
      metadata: { intent_signature: ['EVASION', 'EXECUTION', 'EXFILTRATION'], signal_pattern: chain, composite: true },
    });
  }

  if (state.hasEnvAccess && state.hasNetworkCall && state.hasExecCall) {
    findings.push({
      type: 'KILL_CHAIN_ENV_EXEC_EXFIL', severity: 'CRITICAL', riskLevel: 10,
      message: 'Kill Chain: Environment access → Code execution → Network exfiltration in \'' + state.filePath + '\'',
      evidence: 'Signals:\n' + signals.join('\n'),
      source_engine: 'HEURISTIC', context: classifyFileContext(state.filePath),
      metadata: { intent_signature: ['RECONNAISSANCE', 'EXECUTION', 'EXFILTRATION'], signal_pattern: chain, composite: true },
    });
  }

  if (chain.length >= 3 && !findings.length) {
    findings.push({
      type: 'BEHAVIOR_GRAPH_COMPOSITE', severity: 'HIGH', riskLevel: 8,
      message: 'Composite suspicious behavior pattern (' + chain.length + ' signals) in \'' + state.filePath + '\'',
      evidence: 'Behavior chain: [' + chain.join(' → ') + ']\n' + signals.join('\n'),
      source_engine: 'HEURISTIC', context: classifyFileContext(state.filePath),
      metadata: { intent_signature: chain, signal_pattern: chain, diversity: chain.length, composite: true },
    });
  }

  return findings;
}

const MODULE_SIGNATURES: Array<{ type: string; severity: 'MEDIUM' | 'LOW'; riskLevel: number; module: string; message: string }> = [
  { type: 'SOCKET_MODULE_USAGE', severity: 'MEDIUM', riskLevel: 6, module: 'socket', message: 'socket module imported — network capability signal' },
  { type: 'CTYPES_MODULE_USAGE', severity: 'MEDIUM', riskLevel: 6, module: 'ctypes', message: 'ctypes module imported — native code loading capability' },
  { type: 'TEMPFILE_USAGE', severity: 'LOW', riskLevel: 5, module: 'tempfile', message: 'tempfile usage — potential race condition vector (TOCTOU)' },
  { type: 'SUBPROCESS_MODULE_USAGE', severity: 'MEDIUM', riskLevel: 5, module: 'subprocess', message: 'subprocess module imported — command execution capability' },
];

export async function analyze(code: string, filePath: string = 'unknown'): Promise<ForensicFinding[]> {
  const findings: ForensicFinding[] = [];
  const context = classifyFileContext(filePath);
  const isSetupPy = filePath.endsWith('setup.py') || filePath.includes('setup.py');
  const isLifecycleScript = filePath.includes('setup.py') || filePath.includes('install.py') ||
    filePath.includes('postinstall') || filePath.includes('preinstall');

  let parser: TSParser;
  try {
    parser = await ensureParser();
  } catch {
    findings.push({
      type: 'PARSER_INIT_FAILURE', severity: 'LOW', riskLevel: 4,
      message: 'Python AST parser initialization failed for \'' + filePath + '\'',
      evidence: 'Tree-sitter WASM could not be loaded',
      source_engine: 'AST', context,
    });
    return findings;
  }

  let tree: any;
  try {
    tree = parser.parse(code);
  } catch {
    findings.push({
      type: 'PARSER_FAILURE', severity: 'LOW', riskLevel: 4,
      message: 'AST parsing failed for \'' + filePath + '\'',
      evidence: code.substring(0, 100), source_engine: 'AST', context,
    });
    return findings;
  }

  if (!tree) {
    findings.push({
      type: 'PARSER_FAILURE', severity: 'LOW', riskLevel: 4,
      message: 'AST parsing returned null for \'' + filePath + '\'',
      evidence: code.substring(0, 100), source_engine: 'AST', context,
    });
    return findings;
  }

  const root = tree.rootNode;

  if (root.hasError) {
    findings.push({
      type: 'PARSE_ERROR_IN_TREE', severity: 'LOW', riskLevel: 3,
      message: 'Python file \'' + filePath + '\' contains syntax errors',
      evidence: code.substring(0, 200), line_number: 1,
      source_engine: 'AST', context,
    });
  }

  const state: WalkState = {
    filePath,
    imports: new Map(),
    variables: new Map(),
    taints: [],
    strings: [],
    dangerousCalls: [],
    findings: [],
    hasBase64Decode: false,
    hasExecCall: false,
    hasNetworkCall: false,
    hasEnvAccess: false,
    hasSensitivePathRef: false,
    sysModulesManipulated: false,
    hasSetupPyNetworkCall: false,
    isSetupPy,
    isLifecycleScript,
    executedArgs: [],
    networkArgs: [],
  };

  for (const child of root.children) {
    walkTree(child, code, state);
  }

  for (const finding of state.findings) {
    findings.push(finding);
  }

  for (const sig of MODULE_SIGNATURES) {
    for (const [alias, record] of state.imports) {
      if (record.module === sig.module || record.module.startsWith(sig.module + '.')) {
        findings.push({
          type: sig.type, severity: sig.severity, riskLevel: sig.riskLevel,
          message: sig.message + ' in \'' + filePath + '\'',
          evidence: 'import ' + record.module + (record.alias && record.alias !== record.module ? ' as ' + record.alias : ''),
          line_number: record.line + 1,
          source_engine: 'AST', context,
        });
      }
    }
  }

  const chainFindings = detectKillChains(state);
  for (const f of chainFindings) {
    findings.push(f);
  }

  return findings;
}
