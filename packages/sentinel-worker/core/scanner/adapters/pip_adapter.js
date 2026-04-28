/**
 * Sentinel: PIP Ecosystem Adapter
 * Handles Python package analysis via PyPI metadata.
 * 
 * Key threat surfaces:
 *  - pyproject.toml [project.scripts] entry_points
 *  - setup.py cmdclass overrides
 *  - Typosquatting against PyPI Top-500
 */
'use strict';

// PyPI Top packages (typosquatting targets)
const PROTECTED = [
    'requests', 'numpy', 'pandas', 'tensorflow', 'torch', 'flask', 'django',
    'scipy', 'matplotlib', 'boto3', 'pydantic', 'fastapi', 'pytest', 'sqlalchemy',
    'celery', 'redis', 'pillow', 'cryptography', 'paramiko', 'aiohttp',
    'httpx', 'click', 'typer', 'pyyaml', 'toml', 'rich', 'tqdm',
    'scikit-learn', 'keras', 'transformers', 'openai', 'anthropic',
    'langchain', 'uvicorn', 'gunicorn', 'alembic', 'black', 'mypy', 'ruff'
];

// Python-specific dangerous patterns in setup.py or scripts
const MALICIOUS_PATTERNS = [
    { regex: /os\.system\(|subprocess\.(call|run|Popen)\s*\(\s*['"][^'"]*curl/i, category: 'system_exec',    severity: 'MALICIOUS' },
    { regex: /open\(.*\/\.ssh|open\(.*\/etc\/passwd/i,                            category: 'file_exfil',     severity: 'MALICIOUS' },
    { regex: /base64\.b64decode|codecs\.decode.*rot_?13/i,                        category: 'obfuscation',    severity: 'MALICIOUS' },
    { regex: /urllib\.request\.urlopen|requests\.get.*=\s*exec/i,                 category: 'network_exec',   severity: 'SUSPICIOUS' },
    { regex: /socket\.connect|socket\.create_connection/i,                        category: 'raw_socket',     severity: 'SUSPICIOUS' },
    // SAFE: common in legit packages
    { regex: /Cython|ctypes|cffi|setuptools\.Extension/i,                         category: 'native_ext',     severity: 'SAFE' }
];

// entry_points can execute arbitrary code on install
const RISKY_ENTRY_POINTS = ['console_scripts', 'setuptools.installation'];

const PipAdapter = {
    id: 'pip',
    aliases: ['pip', 'pip3', 'poetry', 'uv'],
    installCmd: (pkg, args = []) => ['pip', ['install', pkg, ...args]],
    protected: PROTECTED,

    /** Parse pyproject.toml-like manifest */
    parseManifest(manifest = {}) {
        const scripts = {};
        // pyproject.toml: [project.scripts]
        if (manifest.project?.scripts) {
            for (const [k, v] of Object.entries(manifest.project.scripts)) {
                scripts[`console_script:${k}`] = v;
            }
        }
        // setup.py style entry_points
        if (manifest.entry_points) {
            for (const group of RISKY_ENTRY_POINTS) {
                if (manifest.entry_points[group]) {
                    for (const ep of manifest.entry_points[group]) {
                        scripts[`entry_point:${group}`] = ep;
                    }
                }
            }
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

    /** Pip-specific: detect common PyPI attack patterns */
    checkScopeAbuse(pkgName) {
        // Python uses hyphens and underscores interchangeably — attackers exploit this
        const normalized = pkgName.replace(/-/g, '_').toLowerCase();
        for (const p of PROTECTED) {
            const protNorm = p.replace(/-/g, '_').toLowerCase();
            if (normalized !== protNorm && normalized.startsWith(protNorm + '_')) {
                return { type: 'EXTENSION_CAMOUFLAGE', target: p };
            }
        }
        return null;
    }
};

module.exports = PipAdapter;
