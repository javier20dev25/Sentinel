const fs = require('fs');
const path = require('path');

const dir = path.join(__dirname, '..', 'fixtures', 'live_prs');
const gold = JSON.parse(fs.readFileSync(path.join(dir, 'risk_network.json'), 'utf8'));

// 1. Caso A: SHA Adulterado
const corruptedSha = { ...gold, sha: "bad_sha_123_not_hex_g_h_i_j" };
fs.writeFileSync(path.join(dir, 'sha_corrupted.json'), JSON.stringify(corruptedSha, null, 2));

// 2. Caso B: Provenance Truncada (Falta hunk y excerpt)
const truncatedProv = { ...gold, provenance: [ { intent: "NETWORK", severity: 5, file: "test.js", line: 42 } ] };
fs.writeFileSync(path.join(dir, 'provenance_truncated.json'), JSON.stringify(truncatedProv, null, 2));

// 3. Caso C: Hash Drift (Impacto alterado sin recalcular hash)
const hashDrift = { ...gold, impact: 999 };
fs.writeFileSync(path.join(dir, 'hash_drift.json'), JSON.stringify(hashDrift, null, 2));

console.log("Mutation fixtures generated successfully.");
