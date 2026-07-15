'use strict';

let acorn, walk;
try {
  acorn = require('acorn');
  walk = require('acorn-walk');
} catch (e) {
  acorn = null;
  walk = null;
}

const BUILTIN_DECODERS = ['atob', 'Buffer.from', 'String.fromCharCode', 'decodeURIComponent', 'decodeURI'];
const DANGEROUS_SINKS = ['exec', 'execSync', 'spawn', 'spawnSync', 'fork', 'execFile', 'execFileSync',
  'eval', 'Function', 'setTimeout', 'setImmediate', 'setInterval',
  'constructor', 'child_process', 'process', 'require', 'vm'];
const SENSITIVE_MODULES = ['child_process', 'fs', 'net', 'http', 'https', 'vm', 'worker_threads', 'cluster', 'dgram', 'dns', 'tls'];

class SymbolTable {
  constructor() {
    this.variables = new Map();
    this.requires = new Map();
    this.aliases = new Map();
    this.arrayLiterals = new Map();
    this.callSites = [];
    this.stringLiterals = [];
  }

  setVar(name, value, confidence) {
    this.variables.set(name, { value, confidence });
  }

  getVar(name) {
    return this.variables.get(name);
  }

  resolveAlias(name) {
    const seen = new Set();
    let current = name;
    while (current && this.aliases.has(current)) {
      if (seen.has(current)) return current;
      seen.add(current);
      current = this.aliases.get(current);
    }
    return current || name;
  }

  addAlias(from, to) {
    this.aliases.set(from, to);
  }

  addCallSite(node, resolvedName, args, sourceCode) {
    this.callSites.push({ node, name: resolvedName, args, raw: sourceCode });
  }

  addStringLiteral(value, node) {
    this.stringLiterals.push({ value, node });
  }
}

function tryFoldString(node, code) {
  if (!node) return null;
  if (node.type === 'Literal' && typeof node.value === 'string') return node.value;
  if (node.type === 'TemplateLiteral') {
    if (node.expressions.length === 0 && node.quasis.length > 0) {
      return node.quasis[0].value.cooked;
    }
    const parts = [];
    for (let i = 0; i < node.quasis.length; i++) {
      parts.push(node.quasis[i].value.cooked || '');
      if (i < node.expressions.length) {
        const exprVal = tryFoldString(node.expressions[i], code);
        if (exprVal === null) return null;
        parts.push(exprVal);
      }
    }
    return parts.join('');
  }
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    const left = tryFoldString(node.left, code);
    const right = tryFoldString(node.right, code);
    if (left !== null && right !== null) return left + right;
    return null;
  }
  return null;
}

function tryFoldBoolean(node) {
  if (!node) return null;
  if (node.type === 'Literal' && typeof node.value === 'boolean') return node.value;
  if (node.type === 'UnaryExpression' && node.operator === '!') {
    const arg = tryFoldBoolean(node.argument);
    if (typeof arg === 'boolean') return !arg;
  }
  if (node.type === 'BinaryExpression') {
    const l = node.left, r = node.right;
    if (['===', '!==', '==', '!='].includes(node.operator)) {
      if (l.type === 'Literal' && r.type === 'Literal' && typeof l.value === typeof r.value) {
        const eq = l.value === r.value;
        if (node.operator === '===' || node.operator === '==') return eq;
        if (node.operator === '!==' || node.operator === '!=') return !eq;
      }
    }
  }
  return null;
}

function extractStringFromCall(node, code) {
  if (!node || node.type !== 'CallExpression') return null;
  const callee = extractCalleeName(node.callee);

  if (callee === 'String.fromCharCode') {
    const nums = node.arguments.map(a => {
      if (a.type === 'Literal' && typeof a.value === 'number') return a.value;
      return null;
    });
    if (nums.every(n => n !== null)) return String.fromCharCode(...nums);
  }

  if (callee === 'atob' || callee === 'decodeURIComponent' || callee === 'decodeURI') {
    if (node.arguments[0] && node.arguments[0].type === 'Literal' && typeof node.arguments[0].value === 'string') {
      try {
        if (callee === 'atob') return Buffer.from(node.arguments[0].value, 'base64').toString('utf8');
        return decodeURIComponent(node.arguments[0].value);
      } catch (e) { return null; }
    }
  }

  if (callee === 'Buffer.from') {
    const arg = node.arguments[0];
    const encoding = node.arguments[1] && node.arguments[1].type === 'Literal' ? node.arguments[1].value : 'utf8';
    if (arg && arg.type === 'Literal' && typeof arg.value === 'string') {
      try {
        return Buffer.from(arg.value, encoding).toString('utf8');
      } catch (e) { return null; }
    }
  }

  if (callee && callee.endsWith('.join')) {
    const obj = extractArrayFromCall(node.callee.object, code);
    if (obj && Array.isArray(obj)) {
      const sepArg = node.arguments[0];
      const sep = (sepArg && sepArg.type === 'Literal' && typeof sepArg.value === 'string') ? sepArg.value : ',';
      return obj.join(sep);
    }
  }

  return null;
}

function extractArrayFromCall(node, code) {
  if (!node) return null;
  if (node.type === 'ArrayExpression') {
    const elements = [];
    for (const el of node.elements) {
      if (el && el.type === 'Literal' && typeof el.value === 'string') elements.push(el.value);
      else if (el && el.type === 'Literal' && typeof el.value === 'number') elements.push(el.value);
      else return null;
    }
    return elements;
  }
  return null;
}

function extractCalleeName(node) {
  if (!node) return null;
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'MemberExpression') {
    const obj = extractCalleeName(node.object);
    const prop = node.property && (node.property.name || (node.property.type === 'Literal' ? node.property.value : null));
    if (obj && prop) return `${obj}.${prop}`;
  }
  return null;
}

function getRootObject(node) {
  let current = node;
  while (current && current.type === 'MemberExpression') current = current.object;
  return (current && current.type === 'Identifier') ? current.name : null;
}

class NormalizationEngine {
  constructor() {
    this.symbols = new SymbolTable();
  }

  normalize(code) {
    this.symbols = new SymbolTable();
    if (!acorn || !walk) return this.symbols;

    let ast;
    for (const sourceType of ['module', 'script']) {
      try {
        ast = acorn.parse(code, { ecmaVersion: 'latest', sourceType, locations: true });
        break;
      } catch (_) {}
    }
    if (!ast) return this.symbols;

    this._walkAST(ast, code);
    return this.symbols;
  }

  _isDeadBranch(ancestors) {
    if (!ancestors || ancestors.length < 2) return false;
    for (let i = 0; i < ancestors.length - 1; i++) {
      const anc = ancestors[i];
      if (!anc) continue;

      if (anc.type === 'IfStatement') {
        const testVal = tryFoldBoolean(anc.test);
        if (testVal === null) continue;
        for (let j = i + 1; j < ancestors.length; j++) {
          if (ancestors[j] === anc.consequent && testVal === false) return true;
          if (ancestors[j] === anc.alternate && testVal === true) return true;
        }
      }

      if (anc.type === 'ConditionalExpression') {
        const testVal = tryFoldBoolean(anc.test);
        if (testVal === null) continue;
        for (let j = i + 1; j < ancestors.length; j++) {
          if (ancestors[j] === anc.consequent && testVal === false) return true;
          if (ancestors[j] === anc.alternate && testVal === true) return true;
        }
      }

      if (anc.type === 'LogicalExpression' && anc.operator === '&&') {
        const leftVal = tryFoldBoolean(anc.left);
        if (leftVal === true) continue;
        if (leftVal === false) {
          for (let j = i + 1; j < ancestors.length; j++) {
            if (ancestors[j] === anc.right) return true;
          }
        }
      }

      if (anc.type === 'LogicalExpression' && anc.operator === '||') {
        const leftVal = tryFoldBoolean(anc.left);
        if (leftVal === false) continue;
        if (leftVal === true) {
          for (let j = i + 1; j < ancestors.length; j++) {
            if (ancestors[j] === anc.right) return true;
          }
        }
      }
    }
    return false;
  }

  _walkAST(ast, code) {
    const sym = this.symbols;
    const engine = this;

    walk.ancestor(ast, {
      VariableDeclarator: (node, ancestors) => {
        if (engine._isDeadBranch(ancestors)) return;
        if (node.id.type !== 'Identifier') return;

        const name = node.id.name;

        // require('module') tracking
        if (node.init && node.init.type === 'CallExpression' &&
            node.init.callee && node.init.callee.name === 'require') {
          const arg = node.init.arguments[0];
          if (arg && arg.type === 'Literal' && typeof arg.value === 'string') {
            sym.requires.set(name, arg.value);
            sym.setVar(name, arg.value, 0.95);
          }
          return;
        }

        // const x = 'string'
        if (node.init && node.init.type === 'Literal') {
          sym.setVar(name, node.init.value, 0.95);
          if (typeof node.init.value === 'string') {
            sym.addStringLiteral(node.init.value, node.init);
          }
          return;
        }

        // const x = y (alias)
        if (node.init && node.init.type === 'Identifier') {
          sym.addAlias(name, node.init.name);
          const resolved = sym.resolveAlias(node.init.name);
          sym.setVar(name, resolved, 0.8);
          return;
        }

        // const x = y + z (string concat)
        if (node.init) {
          const folded = tryFoldString(node.init, code);
          if (folded !== null && typeof folded === 'string') {
            sym.setVar(name, folded, 0.9);
            sym.addStringLiteral(folded, node.init);
            return;
          }

          // Buffer.from(...) / String.fromCharCode(...) / atob(...)
          const decoded = extractStringFromCall(node.init, code);
          if (decoded !== null && typeof decoded === 'string') {
            sym.setVar(name, decoded, 0.85);
            sym.addStringLiteral(decoded, node.init);
            return;
          }

          // Array expression — track all string/number literals
          if (node.init.type === 'ArrayExpression') {
            const elements = [];
            let allLiteral = true;
            for (const el of node.init.elements) {
              if (el && el.type === 'Literal' && typeof el.value === 'string') elements.push(el.value);
              else if (el && el.type === 'Literal' && typeof el.value === 'number') elements.push(String(el.value));
              else if (el && el.type === 'Identifier') {
                const varValue = sym.resolveAlias(el.name);
                const resolved = sym.variables.get(varValue);
                if (resolved && typeof resolved.value === 'string') elements.push(resolved.value);
                else if (resolved && typeof resolved.value === 'number') elements.push(String(resolved.value));
                else allLiteral = false;
              } else allLiteral = false;
            }
            if (allLiteral) sym.arrayLiterals.set(name, elements);
          }
        }
      },

      AssignmentExpression: (node, ancestors) => {
        if (engine._isDeadBranch(ancestors)) return;
        if (node.left.type === 'Identifier' && node.right.type === 'Identifier') {
          sym.addAlias(node.left.name, node.right.name);
        }
      },

      CallExpression: (node, ancestors) => {
        if (engine._isDeadBranch(ancestors)) return;
        let callName = extractCalleeName(node.callee);

        // If extractCalleeName fails due to computed nested member (e.g. cp[methods[0]]),
        // get the root object name to let bracket resolution handle it
        if (!callName && node.callee.type === 'MemberExpression' && node.callee.computed) {
          callName = extractCalleeName(node.callee.object);
        }
        if (!callName) return;

        // Resolve through aliases
        const resolved = sym.resolveAlias(callName);
        callName = resolved;

        // Resolve variable-based bracket access FIRST (before require resolution)
        if (node.callee.type === 'MemberExpression' && node.callee.computed) {
          const objName = extractCalleeName(node.callee.object);
          const propNode = node.callee.property;
          let resolvedProp = null;

          if (propNode.type === 'Literal' && typeof propNode.value === 'string') {
            resolvedProp = propNode.value;
          } else if (propNode.type === 'Identifier') {
            const varValue = sym.variables.get(propNode.name);
            if (varValue && typeof varValue.value === 'string') {
              resolvedProp = varValue.value;
            }
          } else if (propNode.type === 'MemberExpression') {
            // array[index] resolution: methods[0], arr[key]
            const arrName = extractCalleeName(propNode.object);
            const indexNode = propNode.property;
            if (arrName && indexNode) {
              let idx = null;
              if (indexNode.type === 'Literal' && typeof indexNode.value === 'number') {
                idx = indexNode.value;
              } else if (indexNode.type === 'Identifier') {
                const idxVar = sym.variables.get(indexNode.name);
                if (idxVar && typeof idxVar.value === 'number') idx = idxVar.value;
              }
              if (idx !== null) {
                const arr = sym.arrayLiterals.get(arrName);
                if (arr && idx >= 0 && idx < arr.length) {
                  resolvedProp = arr[idx];
                }
              }
            }
          } else {
            const folded = tryFoldString(propNode, code);
            if (folded !== null) resolvedProp = folded;
          }

          if (resolvedProp && objName) {
            callName = `${objName}.${resolvedProp}`;
          }
        }

        // Resolve require('child_process').exec (works on the post-bracket-resolution callName too)
        if (node.callee.type === 'MemberExpression') {
          const obj = node.callee.object;
          let rawProp = node.callee.property && (node.callee.property.name ||
            (node.callee.property.type === 'Literal' ? node.callee.property.value : null));

          // If callName was resolved via bracket access, it's objName.resolvedProp
          // Extract the objName part for require resolution
          const dotIdx = callName.indexOf('.');
          let resolvedObjName = dotIdx > 0 ? callName.substring(0, dotIdx) : null;

          if (resolvedObjName) {
            const resolvedObj = sym.resolveAlias(resolvedObjName);
            const requiredModule = sym.requires.get(resolvedObj) || sym.variables.get(resolvedObj)?.value;
            if (requiredModule) {
              const propPart = callName.substring(dotIdx + 1);
              callName = `${requiredModule}.${propPart}`;
            }
          } else if (obj && obj.type === 'Identifier' && rawProp) {
            const resolvedObj = sym.resolveAlias(obj.name);
            const requiredModule = sym.requires.get(resolvedObj) || sym.variables.get(resolvedObj)?.value;
            if (requiredModule) {
              callName = `${requiredModule}.${rawProp}`;
            }
          }
        }

        sym.addCallSite(node, callName, node.arguments, code.substring(node.start, node.end));
      },
    });

    // Post-walk: resolve call sites with array literals
    for (const cs of sym.callSites) {
      if (cs.name && cs.name.includes('[')) {
        const match = cs.name.match(/^(.+?)\[(.+)\]$/);
        if (match) {
          const arrName = match[1];
          const idxStr = match[2];
          const arr = sym.arrayLiterals.get(arrName);
          const idx = parseInt(idxStr);
          if (arr && !isNaN(idx) && idx >= 0 && idx < arr.length) {
            cs.name = `${arrName}.${arr[idx]}`;
          }
        }
      }
    }
  }
}

function normalize(code) {
  const engine = new NormalizationEngine();
  return engine.normalize(code);
}

module.exports = { NormalizationEngine, normalize, SymbolTable };