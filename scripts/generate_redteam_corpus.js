const fs = require('fs');
const path = require('path');

const dirs = [
    'scripts/redteam_corpus/benign',
    'scripts/redteam_corpus/malicious',
    'scripts/redteam_corpus/edge_cases',
    'data/redteam'
];

dirs.forEach(d => {
    const fullPath = path.join(__dirname, '..', d);
    if (!fs.existsSync(fullPath)) {
        fs.mkdirSync(fullPath, { recursive: true });
    }
});

function writeCase(dir, id, name, repo, profile, category, file, signals, expectedVerdict, critical) {
    const data = {
        id, name, repo, repoProfile: profile, category, file, signals, code: "// mock",
        expectedVerdict, expectedMinConfidence: 0.0, expectedMaxConfidence: 1.0, critical
    };
    fs.writeFileSync(path.join(__dirname, '..', 'scripts/redteam_corpus', dir, `${id}.json`), JSON.stringify(data, null, 2));
}

let idCounter = 1;
const nextId = () => `rt-${String(idCounter++).padStart(3, '0')}`;

// --- BENIGN (35) ---
for (let i = 0; i < 10; i++) writeCase('benign', nextId(), 'infra_proxy', 'expressjs/express', 'infrastructure', 'benign', 'lib/proxy.js', ['NETWORK'], 'PASS', false);
for (let i = 0; i < 5; i++) writeCase('benign', nextId(), 'infra_auth', 'expressjs/express', 'infrastructure', 'benign', 'lib/auth.js', ['SYSTEM_ACCESS'], 'PASS', false);
for (let i = 0; i < 10; i++) writeCase('benign', nextId(), 'frontend_fetch', 'facebook/react', 'frontend', 'benign', 'src/api.js', ['NETWORK'], 'PASS', false);
for (let i = 0; i < 5; i++) writeCase('benign', nextId(), 'backend_db', 'nestjs/nest', 'default', 'benign', 'src/db.js', ['SYSTEM_ACCESS'], 'PASS', false);
for (let i = 0; i < 5; i++) writeCase('benign', nextId(), 'tests', 'expressjs/express', 'infrastructure', 'benign', 'test/app.test.js', ['NETWORK', 'EXECUTION'], 'PASS', false);

// --- MALICIOUS (45) ---
for (let i = 0; i < 10; i++) writeCase('malicious', nextId(), 'supply_chain_postinstall', 'expressjs/express', 'infrastructure', 'malicious', 'package.json', ['SUPPLY_CHAIN_TAMPERING', 'EXECUTION'], 'BLOCK', true);
for (let i = 0; i < 10; i++) writeCase('malicious', nextId(), 'credential_theft', 'vercel/next.js', 'frontend', 'malicious', 'pages/api/auth.js', ['SECRET_ACCESS', 'NETWORK'], 'BLOCK', true); // Expected to hit REVIEW_HIGH_SIGNAL or BLOCK
for (let i = 0; i < 10; i++) writeCase('malicious', nextId(), 'exfiltration_beacon', 'lodash/lodash', 'libraries', 'malicious', 'lib/index.js', ['EXFILTRATION', 'NETWORK'], 'BLOCK', true);
for (let i = 0; i < 10; i++) writeCase('malicious', nextId(), 'obfuscation_eval', 'facebook/react', 'frontend', 'malicious', 'src/core.js', ['ENCODING', 'EXECUTION'], 'BLOCK', true);
for (let i = 0; i < 5; i++) writeCase('malicious', nextId(), 'gh_actions_abuse', 'expressjs/express', 'infrastructure', 'malicious', '.github/workflows/ci.yml', ['EXFILTRATION', 'NETWORK'], 'BLOCK', true);

// --- EDGE CASES (20) ---
for (let i = 0; i < 10; i++) writeCase('edge_cases', nextId(), 'fp_trap_analytics', 'vercel/next.js', 'frontend', 'edge_cases', 'src/analytics.js', ['NETWORK'], 'PASS', false);
for (let i = 0; i < 10; i++) writeCase('edge_cases', nextId(), 'stealth_combo', 'lodash/lodash', 'libraries', 'edge_cases', 'lib/utils.js', ['SYSTEM_ACCESS', 'NETWORK', 'ENCODING'], 'BLOCK', true); // Expected REVIEW_HIGH_SIGNAL+ or BLOCK

console.log("Generated 100 corpus JSONs.");
