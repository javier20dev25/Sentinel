/**
 * Sentinel: Scanner Configuration (v1.0)
 * 
 * Centralizes limits, whitelist categories, and directory exclusions.
 * Supports context-aware profiles: DEFAULT, DEEP, FORENSIC.
 */

const CONFIG = {
    PROFILES: {
        DEFAULT: {
            maxFileSize: 1 * 1024 * 1024, // 1MB
            allowedCategories: ['SOURCE_CODE', 'CONFIG', 'LOCKFILE', 'SCRIPT'],
            excludedDirs: ['node_modules', '.git', 'dist', 'build', '.next', 'out', 'vendor', 'coverage', 'obj', 'bin'],
            deepAnalysis: false
        },
        DEEP: {
            maxFileSize: 5 * 1024 * 1024, // 5MB
            allowedCategories: ['SOURCE_CODE', 'CONFIG', 'LOCKFILE', 'SCRIPT', 'DOC'],
            excludedDirs: ['node_modules', '.git', 'dist', 'build', '.next', 'out', 'vendor'],
            deepAnalysis: true
        },
        FORENSIC: {
            maxFileSize: Infinity,
            allowedCategories: ['SOURCE_CODE', 'CONFIG', 'LOCKFILE', 'SCRIPT', 'DOC', 'BINARY', 'UNKNOWN'],
            excludedDirs: [], // Scan EVERYTHING
            deepAnalysis: true
        }
    },
    
    CATEGORIES: {
        SOURCE_CODE: ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs', '.py', '.go', '.rs', '.java', '.cpp', '.c', '.h', '.cs'],
        CONFIG: ['.json', '.yml', '.yaml', '.env', '.toml', '.ini', '.npmrc', '.yarnrc'],
        LOCKFILE: ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lockb'],
        SCRIPT: ['.sh', '.bat', '.ps1', '.cmd'],
        DOC: ['.md', '.txt', '.html', '.css', '.pdf'],
        BINARY: ['.exe', '.dll', '.so', '.dylib', '.pak', '.bin', '.dat']
    },

    PERFORMANCE: {
        CONCURRENCY_LIMIT: require('os').cpus().length * 2, // Elastic concurrency
        FILE_TIMEOUT_MS: 100, // Hard timeout per file to prevent ReDoS hanging
        BINARY_SAMPLE_SIZE: 512 // Bytes to read for binary detection
    },

    SCORING: {
        DAMPING_FACTOR: 1.5,
        CONTEXT_WEIGHTS: {
            'package.json': 1.2,
            'src': 1.0,
            'lib': 1.0,
            'config': 0.9,
            'scripts': 0.85,
            'tests': 0.6,
            '__tests__': 0.5,
            'vendor': 0.1,
            'public': 0.2,
            'assets': 0.2,
            'fixtures': 0.2,
            'dist': 0.4,
            'docs': 0.3,
            'default': 0.7
        },
        SEVERITY_MAP: {
            'CRITICAL': 0.95,
            'HIGH': 0.8,
            'WARNING': 0.4,
            'LOW': 0.1
        },
        OVERRIDES: ['SECRET', 'API_KEY', 'PRIVATE_KEY'] // High severity regardless of context
    }
};

module.exports = CONFIG;
