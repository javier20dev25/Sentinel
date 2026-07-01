/**
 * Sentinel: Unified Data Directory (v8.1.0 - Single Source of Truth)
 * 
 * ONE root for ALL persistent data. No exceptions.
 * Legacy files are retired (renamed to .migrated) after migration.
 * 
 * Override with SENTINEL_DATA_DIR environment variable for deployment.
 */

'use strict';

const path = require('path');
const fs = require('fs');

const PROJECT_ROOT = path.resolve(__dirname, '../../../../');
const DATA_ROOT = process.env.SENTINEL_DATA_DIR || path.join(PROJECT_ROOT, 'data');

const PATHS = Object.freeze({
    ROOT: DATA_ROOT,

    // --- Telemetry Streams (append-only JSONL) ---
    OBSERVATIONS: path.join(DATA_ROOT, 'observations.jsonl'),
    DETECTIONS:   path.join(DATA_ROOT, 'detections.jsonl'),
    METRICS:      path.join(DATA_ROOT, 'metrics.jsonl'),
    CALIBRATION:  path.join(DATA_ROOT, 'calibration.jsonl'),
    STRESS:       path.join(DATA_ROOT, 'stress.jsonl'),

    // --- Memory (append-only event stream + snapshots) ---
    MEMORY_EVENTS:    path.join(DATA_ROOT, 'memory', 'events.jsonl'),
    MEMORY_SNAPSHOTS: path.join(DATA_ROOT, 'memory', 'snapshots'),

    // --- Human Feedback (versioned) ---
    LABELS:       path.join(DATA_ROOT, 'labels', 'labels_v1.jsonl'),
    LABELS_DIR:   path.join(DATA_ROOT, 'labels')
});

// Legacy paths (used only for migration, then retired)
const LEGACY_FILES = [
    { dir: path.join(PROJECT_ROOT, 'docs'), files: ['shadow_observations.jsonl', 'shadow_detections.jsonl', 'shadow_metrics.jsonl', 'shadow_stress.jsonl', 'calibration_metrics.jsonl'] },
    { dir: path.join(PROJECT_ROOT, 'lab'), files: ['labels.jsonl'] },
    { dir: path.join(__dirname, '../lab'), files: ['threat_memory.jsonl'] }
];

const LEGACY_MIGRATION_MAP = [
    { from: path.join(__dirname, '../lab/threat_memory.jsonl'), to: PATHS.MEMORY_EVENTS },
    { from: path.join(PROJECT_ROOT, 'lab', 'labels.jsonl'), to: PATHS.LABELS },
    { from: path.join(PROJECT_ROOT, 'docs', 'shadow_observations.jsonl'), to: PATHS.OBSERVATIONS },
    { from: path.join(PROJECT_ROOT, 'docs', 'shadow_detections.jsonl'),   to: PATHS.DETECTIONS },
    { from: path.join(PROJECT_ROOT, 'docs', 'shadow_metrics.jsonl'),      to: PATHS.METRICS },
    { from: path.join(PROJECT_ROOT, 'docs', 'shadow_stress.jsonl'),       to: PATHS.STRESS },
    { from: path.join(PROJECT_ROOT, 'docs', 'calibration_metrics.jsonl'), to: PATHS.CALIBRATION }
];

function ensureDataDirs() {
    const dirs = [
        DATA_ROOT,
        path.join(DATA_ROOT, 'memory'),
        path.join(DATA_ROOT, 'memory', 'snapshots'),
        path.join(DATA_ROOT, 'labels')
    ];
    for (const dir of dirs) {
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
    }
}

/**
 * Migrates legacy data files to the unified data directory.
 * Non-destructive: copies, never deletes originals.
 */
function migrateLegacyData() {
    let migrated = 0;
    for (const { from, to } of LEGACY_MIGRATION_MAP) {
        if (fs.existsSync(from) && !fs.existsSync(to)) {
            const dir = path.dirname(to);
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            fs.copyFileSync(from, to);
            migrated++;
            console.log(`[DataPaths] Migrated: ${path.basename(from)} → ${path.relative(PROJECT_ROOT, to)}`);
        }
    }
    if (migrated > 0) console.log(`[DataPaths] Migration complete: ${migrated} files`);
}

/**
 * Retires legacy telemetry files by renaming them to .migrated.
 * Prevents dual-source confusion. Only acts on files that have
 * already been migrated to the unified directory.
 * 
 * Also writes a TOMBSTONE.md explaining where data moved.
 */
function retireLegacyFiles() {
    let retired = 0;
    for (const { dir, files } of LEGACY_FILES) {
        for (const file of files) {
            const fullPath = path.join(dir, file);
            const migratedPath = fullPath + '.migrated';
            // Only retire if: legacy exists, migrated copy doesn't exist yet, AND unified target exists
            const target = LEGACY_MIGRATION_MAP.find(m => path.resolve(m.from) === path.resolve(fullPath));
            if (fs.existsSync(fullPath) && !fs.existsSync(migratedPath) && target && fs.existsSync(target.to)) {
                fs.renameSync(fullPath, migratedPath);
                retired++;
            }
        }
        // Write tombstone in legacy directories
        if (retired > 0 && fs.existsSync(dir)) {
            const tombstone = path.join(dir, 'TOMBSTONE.md');
            if (!fs.existsSync(tombstone)) {
                fs.writeFileSync(tombstone, `# ⚠️ Legacy Data Retired\n\nTelemetry files have been migrated to the unified data directory:\n\`${DATA_ROOT}\`\n\n.migrated files are kept as backup. Safe to delete after confirming data integrity.\n\nMigrated at: ${new Date().toISOString()}\n`, 'utf8');
            }
        }
    }
    if (retired > 0) console.log(`[DataPaths] Retired ${retired} legacy files (renamed to .migrated)`);
}

module.exports = { PATHS, ensureDataDirs, migrateLegacyData, retireLegacyFiles };
