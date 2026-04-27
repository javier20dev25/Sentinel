/**
 * Sentinel: NPM Ecosystem Adapter
 * Handles npm, yarn, pnpm package analysis.
 */
'use strict';

const PROTECTED = [
    'axios', 'lodash', 'express', 'react', 'react-dom', 'vue', 'chalk',
    'moment', 'dotenv', 'typescript', 'webpack', 'babel-core', '@babel/core',
    'jest', 'eslint', 'prettier', 'rollup', 'vite', 'next', 'nuxt',
    'socket.io', 'commander', 'inquirer', 'yargs', 'minimist', 'semver',
    'uuid', 'cors', 'helmet', 'passport', 'jsonwebtoken', 'bcrypt'
];

const LIFECYCLE_HOOKS = ['preinstall', 'install', 'postinstall', 'prepare', 'prepublish'];

const MALICIOUS_PATTERNS = [
    { regex: /cat\s+~\/\.ssh|\/etc\/passwd|AWS_SECRET/i,      category: 'credential_theft',      severity: 'MALICIOUS' },
    { regex: /base64\s+(-d|--decode)|echo\s+[A-Za-z0-9+/]{20,}\s*\|/i, category: 'obfuscated_payload', severity: 'MALICIOUS' },
    { regex: /(curl|wget)\s+https?:\/\//i,                    category: 'network_download',       severity: 'SUSPICIOUS' },
    { regex: /chmod\s+(\+x|777|a\+x)/i,                       category: 'permission_escalation',  severity: 'SUSPICIOUS' },
    { regex: /eval\(|new\s+Function\(/i,                       category: 'dynamic_execution',      severity: 'SUSPICIOUS' },
    { regex: /node-gyp|node-pre-gyp|prebuild/i,                category: 'native_compilation',     severity: 'SAFE' }
];

const NpmAdapter = {
    id: 'npm',
    aliases: ['npm', 'yarn', 'pnpm'],
    installCmd: (pkg, args = []) => ['npm', ['install', pkg, ...args]],
    protected: PROTECTED,

    /** Parse a package.json manifest and extract risky scripts */
    parseManifest(manifest = {}) {
        const scripts = {};
        for (const hook of LIFECYCLE_HOOKS) {
            if (manifest.scripts?.[hook]) scripts[hook] = manifest.scripts[hook];
        }
        return { scripts, name: manifest.name, version: manifest.version };
    },

    auditScripts(scripts = {}) {
        const findings = [];
        for (const [hook, script] of Object.entries(scripts)) {
            for (const p of MALICIOUS_PATTERNS) {
                if (p.severity === 'SAFE') continue;
                if (p.regex.test(script)) {
                    findings.push({ hook, category: p.category, severity: p.severity });
                    break;
                }
            }
        }
        return findings;
    },

    /** npm-specific: detect scoped package camouflage */
    checkScopeAbuse(pkgName) {
        // @evil-org/axios — looks like a scoped fork
        if (pkgName.includes('/')) {
            const bare = pkgName.split('/')[1];
            if (PROTECTED.includes(bare)) return { type: 'SCOPE_CAMOUFLAGE', target: bare };
        }
        // axios-utils-pro, axios_helper
        for (const p of PROTECTED) {
            if (pkgName.startsWith(p + '-') || pkgName.startsWith(p + '_')) {
                return { type: 'EXTENSION_CAMOUFLAGE', target: p };
            }
        }
        return null;
    }
};

module.exports = NpmAdapter;
