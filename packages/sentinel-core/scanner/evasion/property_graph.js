'use strict';

const SENSITIVE_MODULES = ['child_process', 'fs', 'net', 'http', 'https', 'vm', 'worker_threads', 'cluster', 'dgram', 'dns', 'tls'];

const CAPABILITY_MAP = {
  'exec': 'Execution',
  'execSync': 'Execution',
  'spawn': 'Execution',
  'spawnSync': 'Execution',
  'fork': 'Execution',
  'execFile': 'Execution',
  'execFileSync': 'Execution',
  'eval': 'DynamicCodeExecution',
  'Function': 'DynamicCodeExecution',
  'setTimeout': 'DelayedExecution',
  'setImmediate': 'DelayedExecution',
  'setInterval': 'DelayedExecution',
  'constructor': 'ReflectionAccess',
  'require': 'ModuleImport',
  'child_process': 'OSCapability',
  'child_process.exec': 'Execution',
  'child_process.spawn': 'Execution',
  'child_process.fork': 'Execution',
  'child_process.execSync': 'Execution',
  'child_process.execFile': 'Execution',
  'child_process.execFileSync': 'Execution',
  'child_process.spawnSync': 'Execution',
  'vm.runInContext': 'SandboxEscape',
  'vm.runInNewContext': 'SandboxEscape',
  'vm.runInThisContext': 'SandboxEscape',
  'fetch': 'NetworkAccess',
  'axios': 'NetworkAccess',
  'axios.get': 'NetworkAccess',
  'axios.post': 'NetworkAccess',
  'axios.put': 'NetworkAccess',
  'axios.delete': 'NetworkAccess',
  'http.get': 'NetworkAccess',
  'https.get': 'NetworkAccess',
  'request': 'NetworkAccess',
  'net.connect': 'NetworkAccess',
  'dns.lookup': 'NetworkAccess',
  'fs.writeFile': 'FilesystemWrite',
  'fs.writeFileSync': 'FilesystemWrite',
  'fs.appendFile': 'FilesystemWrite',
  'fs.appendFileSync': 'FilesystemWrite',
  'fs.unlink': 'FilesystemWrite',
  'fs.unlinkSync': 'FilesystemWrite',
  'fs.rmdir': 'FilesystemWrite',
  'fs.rmdirSync': 'FilesystemWrite',
  'fs.rm': 'FilesystemWrite',
  'fs.rmSync': 'FilesystemWrite',
  'fs.readFile': 'FilesystemRead',
  'fs.readFileSync': 'FilesystemRead',
  'Buffer.from': 'Decode',
  'atob': 'Decode',
  'String.fromCharCode': 'Decode',
  'decodeURIComponent': 'Decode',
  'decodeURI': 'Decode',
  'JSON.parse': 'Parse',
  'process.env': 'EnvironmentAccess',
  'Reflect.get': 'ReflectionAccess',
  'Reflect.construct': 'ReflectionAccess',
  'Reflect.apply': 'ReflectionAccess',
  'globalThis': 'GlobalAccess',
  'Proxy': 'ProxyWrapping',
};

const CAPABILITY_RISK = {
  'Execution': 0.9,
  'DynamicCodeExecution': 0.95,
  'SandboxEscape': 0.95,
  'NetworkAccess': 0.8,
  'FilesystemWrite': 0.75,
  'FilesystemRead': 0.6,
  'OSCapability': 0.7,
  'ModuleImport': 0.2,
  'DelayedExecution': 0.5,
  'ReflectionAccess': 0.7,
  'Decode': 0.4,
  'Parse': 0.3,
  'EnvironmentAccess': 0.5,
  'GlobalAccess': 0.5,
  'ProxyWrapping': 0.85,
  'Unknown': 0.1,
};

class PropertyGraph {
  constructor() {
    this.nodes = [];
    this.edges = [];
    this.nodeMap = new Map();
  }

  addNode(type, label, data = {}) {
    const id = `${type}:${label}-${this.nodes.length}`;
    const node = { id, type, label, data };
    this.nodes.push(node);
    this.nodeMap.set(id, node);
    return node;
  }

  addEdge(fromId, toId, relation, confidence = 1.0) {
    this.edges.push({ from: fromId, to: toId, relation, confidence });
  }

  getOrCreate(type, label, data = {}) {
    const existing = this.nodes.find(n => n.type === type && n.label === label);
    if (existing) return existing;
    return this.addNode(type, label, data);
  }

  toEvidenceGraphFormat() {
    return {
      nodes: this.nodes.map(n => ({
        id: n.id,
        type: n.type,
        label: n.label,
        data: n.data,
        severity: n.data.risk || 5,
      })),
      edges: this.edges,
    };
  }

  toJSON() {
    return {
      nodes: this.nodes,
      edges: this.edges,
      stats: {
        totalNodes: this.nodes.length,
        totalEdges: this.edges.length,
        capabilities: this.nodes.filter(n => n.type === 'capability').map(n => n.label),
      },
    };
  }
}

function buildPropertyGraph(symbols, code) {
  const graph = new PropertyGraph();
  const filename = 'evasion';

  const fileNode = graph.addNode('file', filename, { path: filename });

  for (const cs of symbols.callSites) {
    const callName = cs.name;
    const capability = CAPABILITY_MAP[callName] || 'Unknown';
    const risk = CAPABILITY_RISK[capability] || 0.1;

    const findingId = `finding:call_${symbols.callSites.indexOf(cs)}`;
    const findingNode = graph.addNode('finding', findingId, {
      risk,
      severity: risk >= 0.8 ? 'CRITICAL' : risk >= 0.6 ? 'HIGH' : risk >= 0.4 ? 'MEDIUM' : 'LOW',
      description: `Call to ${callName}`,
      snippet: cs.raw ? cs.raw.substring(0, 150) : '',
      line: cs.node && cs.node.loc ? cs.node.loc.start.line : 0,
    });

    graph.addEdge(fileNode.id, findingNode.id, 'contains', 1.0);

    const capNode = graph.getOrCreate('capability', capability, { risk });
    graph.addEdge(findingNode.id, capNode.id, 'enables', 0.9);
  }

  // Add requires as module import nodes
  for (const [varName, moduleName] of symbols.requires) {
    const capNode = graph.getOrCreate('capability', 'ModuleImport', { risk: 0.2 });
    const findingId = `finding:require_${varName}`;
    const findingNode = graph.addNode('finding', findingId, {
      risk: 0.2,
      severity: SENSITIVE_MODULES.includes(moduleName) ? 'HIGH' : 'LOW',
      description: `Import of module '${moduleName}' via ${varName}`,
    });
    graph.addEdge(fileNode.id, findingNode.id, 'contains', 1.0);
    graph.addEdge(findingNode.id, capNode.id, 'enables', 0.8);

    // If it's a sensitive module, add a specific capability
    if (SENSITIVE_MODULES.includes(moduleName)) {
      const modCap = graph.getOrCreate('capability', 'OSCapability', { risk: 0.7 });
      graph.addEdge(findingNode.id, modCap.id, 'provides', 0.9);
    }
  }

  // Add string literals that look like encoded content
  for (const sl of symbols.stringLiterals) {
    if (sl.value.length > 40) {
      const findingId = `finding:string_lit_${symbols.stringLiterals.indexOf(sl)}`;
      const findingNode = graph.addNode('finding', findingId, {
        risk: 0.4,
        severity: 'MEDIUM',
        description: `Long string literal (${sl.value.length} chars)`,
        snippet: sl.value.substring(0, 80),
      });
      graph.addEdge(fileNode.id, findingNode.id, 'contains', 1.0);
    }
  }

  // Detect Source→Sink chains in the graph
  const capabilityNodes = graph.nodes.filter(n => n.type === 'capability');
  const sourceCaps = ['EnvironmentAccess', 'FilesystemRead', 'NetworkAccess', 'Decode'];
  const sinkCaps = ['Execution', 'DynamicCodeExecution', 'FilesystemWrite', 'NetworkAccess'];

  for (const src of sourceCaps) {
    for (const sink of sinkCaps) {
      const srcNode = graph.nodes.find(n => n.type === 'capability' && n.label === src);
      const sinkNode = graph.nodes.find(n => n.type === 'capability' && n.label === sink);
      if (srcNode && sinkNode && srcNode.id !== sinkNode.id) {
        const hasExistingEdge = graph.edges.some(e =>
          e.from === srcNode.id && e.to === sinkNode.id && e.relation === 'flows_to');
        if (!hasExistingEdge) {
          graph.addEdge(srcNode.id, sinkNode.id, 'flows_to', 0.6);
        }
      }
    }
  }

  return graph;
}

function build(symbols, code) {
  const graph = buildPropertyGraph(symbols, code);
  return graph;
}

module.exports = { PropertyGraph, buildPropertyGraph, build, CAPABILITY_MAP, CAPABILITY_RISK, SENSITIVE_MODULES };