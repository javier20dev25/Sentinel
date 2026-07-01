/**
 * Sentinel: Human Feedback Ingestor (v2.0 - Disciplined)
 * 
 * Ingests versioned human labels from JSONL and applies them to ThreatMemory.
 * 
 * RULES:
 *   - Each label MUST have: repoId, fingerprint, label, reviewer, reason
 *   - Labels are versioned (labels_v1, labels_v2, ...) 
 *   - Labels never rewrite history — they are additive only
 *   - All ingested labels are logged to the audit trail
 */

'use strict';

const fs = require('fs');
const path = require('path');
const ThreatMemory = require('../packages/sentinel-worker/core/scanner/threat_memory');
const DataContract = require('../packages/sentinel-worker/core/scanner/data_contract');
const { PATHS, ensureDataDirs } = require('../packages/sentinel-worker/core/scanner/data_paths');

// Support both legacy and new paths
const LEGACY_LABELS = path.join(__dirname, '../lab/labels.jsonl');
const NEW_LABELS = PATHS.LABELS;

async function ingest() {
    ensureDataDirs();
    console.log("📥 Starting Human Feedback Ingestion (v2.0)...");
    
    // Determine which label file to use (prefer new, fall back to legacy)
    let labelsFile = null;
    if (fs.existsSync(NEW_LABELS)) {
        labelsFile = NEW_LABELS;
        console.log(`📂 Using unified labels: ${NEW_LABELS}`);
    } else if (fs.existsSync(LEGACY_LABELS)) {
        labelsFile = LEGACY_LABELS;
        console.log(`📂 Using legacy labels: ${LEGACY_LABELS} (consider migrating)`);
    } else {
        console.log(`ℹ️ No labels file found. Checked:\n   ${NEW_LABELS}\n   ${LEGACY_LABELS}`);
        return;
    }

    const lines = fs.readFileSync(labelsFile, 'utf8').split('\n');
    let applied = 0;
    let skipped = 0;
    let errors = 0;
    const auditLog = [];

    for (const line of lines) {
        if (!line.trim()) continue;
        try {
            const raw = JSON.parse(line);
            
            // Support both legacy format {repoId, fingerprint, label} 
            // and new format {repoId, fingerprint, label, reviewer, reason, ...}
            const repoId = raw.repoId;
            const fingerprint = raw.fingerprint;
            const labelType = raw.label;

            if (!repoId || !fingerprint || !labelType) {
                console.warn(`⚠️ Skipping invalid label (missing fields): ${line.substring(0, 80)}`);
                skipped++;
                continue;
            }

            // Validate label type
            if (!['FALSE_POSITIVE', 'TRUE_POSITIVE', 'NEEDS_REVIEW'].includes(labelType)) {
                console.warn(`⚠️ Skipping unknown label type "${labelType}" for ${fingerprint}`);
                skipped++;
                continue;
            }

            // Create audit record using data contract
            const auditRecord = DataContract.toLabelRecord(repoId, fingerprint, labelType, {
                reviewer: raw.reviewer || 'batch_import',
                reason: raw.reason || 'Imported from labels file',
                repoProfile: raw.repoProfile || 'unknown',
                labelSetVersion: raw.labelSetVersion || _inferVersion(labelsFile)
            });

            // Apply to ThreatMemory
            ThreatMemory.addLabel(repoId, fingerprint, labelType);
            auditLog.push(auditRecord);
            applied++;
            console.log(`✅ Applied ${labelType} to ${repoId} [${fingerprint}]${raw.reviewer ? ` (reviewer: ${raw.reviewer})` : ''}`);

        } catch (e) {
            console.error(`❌ Failed to parse label line: ${e.message}`);
            errors++;
        }
    }

    // Write audit trail
    if (auditLog.length > 0) {
        const auditPath = path.join(PATHS.LABELS_DIR, `audit_${Date.now()}.jsonl`);
        const auditData = auditLog.map(r => JSON.stringify(r)).join('\n') + '\n';
        fs.writeFileSync(auditPath, auditData, 'utf8');
        console.log(`📋 Audit trail written: ${path.basename(auditPath)}`);
    }

    console.log(`\n✨ Ingestion complete.`);
    console.log(`   Applied: ${applied} | Skipped: ${skipped} | Errors: ${errors}`);

    // Memory health check
    const stats = ThreatMemory.getStats();
    console.log(`   Memory: ${stats.repoCount} repos, ${stats.totalEvents} events`);
}

function _inferVersion(filePath) {
    const basename = path.basename(filePath, '.jsonl');
    if (basename.startsWith('labels_v')) return basename;
    return 'labels_v1';
}

ingest().catch(err => {
    console.error(`💥 Fatal error during ingestion:`, err);
    process.exit(1);
});
