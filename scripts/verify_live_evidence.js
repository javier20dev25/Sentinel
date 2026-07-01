/**
 * Sentinel: Forensic Auditor (v1.0)
 * 
 * DIRECTIVA: Evidencia física primero, cero narrativa.
 */

'use strict';

const fs = require('fs');
const path = require('path');

const LIVE_LOG = path.join(__dirname, '..', 'reports', 'live_scan', 'live_observations.jsonl');
const AUDIT_REPORT = path.join(__dirname, '..', 'reports', 'live_scan', 'evidence_audit.json');

const stats = {
    total_records: 0,
    invalid_sha_count: 0,
    missing_provenance_count: 0,
    duplicate_pr_sha_count: 0,
    mismatch_count: 0,
    failures: []
};

const prShaMap = new Map(); // repo:pr -> sha

function verify() {
    if (!fs.existsSync(LIVE_LOG)) {
        console.error('ERROR: live_observations.jsonl not found.');
        process.exit(1);
    }

    const lines = fs.readFileSync(LIVE_LOG, 'utf8').trim().split('\n');
    stats.total_records = lines.length;

    lines.forEach((line, idx) => {
        let entry;
        try {
            entry = JSON.parse(line);
        } catch (e) {
            stats.failures.push(`Line ${idx + 1}: Invalid JSON`);
            return;
        }

        const { repo, pr, sha, impact, provenance } = entry;

        // 1. SHA Integrity (Strict Hex [a-f0-9])
        if (!/^[a-f0-9]{7,40}$/i.test(sha)) {
            stats.invalid_sha_count++;
            stats.failures.push(`Record ${idx + 1}: Invalid SHA format (${sha})`);
        }

        // 2. Provenance Integrity
        if (impact > 0 && (!provenance || provenance.length === 0)) {
            stats.missing_provenance_count++;
            stats.failures.push(`Record ${idx + 1}: Missing provenance for impact > 0 (PR #${pr})`);
        }

        // 3. PR->SHA Consistency
        const prKey = `${repo}:${pr}`;
        if (prShaMap.has(prKey)) {
            if (prShaMap.get(prKey) !== sha) {
                stats.duplicate_pr_sha_count++;
                stats.failures.push(`Record ${idx + 1}: PR #${pr} mapped to multiple SHAs`);
            }
        } else {
            prShaMap.set(prKey, sha);
        }
    });

    const auditResult = {
        ts: new Date().toISOString(),
        stats,
        integrity_ok: stats.invalid_sha_count === 0 && stats.missing_provenance_count === 0 && stats.duplicate_pr_sha_count === 0
    };

    fs.writeFileSync(AUDIT_REPORT, JSON.stringify(auditResult, null, 2));
    
    console.log('====================================');
    console.log('SENTINEL EVIDENCE AUDIT');
    console.log('====================================');
    console.log(`Total Records: ${stats.total_records}`);
    console.log(`Invalid SHAs:  ${stats.invalid_sha_count}`);
    console.log(`Missing Prov:  ${stats.missing_provenance_count}`);
    console.log(`PR-SHA Dups:   ${stats.duplicate_pr_sha_count}`);
    console.log(`Integrity:     ${auditResult.integrity_ok ? 'PASSED' : 'FAILED'}`);
    console.log('====================================\n');

    if (stats.failures.length > 0) {
        console.log('FAILURES DETECTED:');
        stats.failures.forEach(f => console.log(`- ${f}`));
    }
}

verify();
