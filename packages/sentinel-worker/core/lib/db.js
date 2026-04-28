/**
 * Sentinel: Database Helper (RESILIENT)
 * Handles persistence for repositories, scan logs, and configurations.
 * 
 * RESILIENCE: Handles ASAR unpacked path resolution for native modules.
 */

let Database;
try {
    Database = require('better-sqlite3');
} catch (e) {
    // In packaged mode, try loading from the unpacked directory explicitly
    try {
        const electron = require('electron');
        const app = electron.app || (electron.remote && electron.remote.app);
        if (app && app.isPackaged) {
            const unpackedPath = app.getAppPath().replace('app.asar', 'app.asar.unpacked');
            const nativePath = require('path').join(unpackedPath, 'node_modules', 'better-sqlite3');
            Database = require(nativePath);
            console.log('[DB] Loaded better-sqlite3 from unpacked path:', nativePath);
        } else {
            throw e; // Re-throw in dev mode
        }
    } catch (e2) {
        console.error('[DB] CRITICAL: Could not load better-sqlite3:', e2.message);
        throw e2;
    }
}
const path = require('path');
const fs = require('fs');
const os = require('os');

function getDataDir() {
    let userDataPath;
    try {
        const electron = require('electron');
        const app = electron.app || (electron.remote && electron.remote.app);
        if (app && typeof app.getPath === 'function') {
            userDataPath = app.getPath('userData');
        }
    } catch (e) {}

    if (!userDataPath) {
        userDataPath = path.join(os.homedir(), '.sentinel');
    }

    if (!fs.existsSync(userDataPath)) {
        fs.mkdirSync(userDataPath, { recursive: true });
    }
    return userDataPath;
}

const dataDir = getDataDir();
const DB_PATH = path.resolve(dataDir, 'sentinel.db');

class SentinelDB {
    constructor() {
        try {
            this.db = new Database(DB_PATH);
            this.init();
        } catch (err) {
            console.error(`[DB] FAILED TO OPEN DATABASE: ${err.message}`);
            throw err;
        }
    }

    init() {
        this.db.exec(`
            CREATE TABLE IF NOT EXISTS repositories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                local_path TEXT UNIQUE,
                github_full_name TEXT,
                last_scan_at DATETIME,
                status TEXT DEFAULT 'SAFE'
            );

            CREATE TABLE IF NOT EXISTS scan_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repo_id INTEGER,
                event_type TEXT,
                risk_level INTEGER,
                description TEXT,
                evidence_metadata TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(repo_id) REFERENCES repositories(id)
            );

            CREATE TABLE IF NOT EXISTS trusted_contributors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                added_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS security_config (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repo_id INTEGER,
                strict_mode BOOLEAN DEFAULT 0,
                ignore_scripts BOOLEAN DEFAULT 1,
                auto_scan_pr BOOLEAN DEFAULT 1,
                FOREIGN KEY(repo_id) REFERENCES repositories(id)
            );

            CREATE TABLE IF NOT EXISTS repo_packs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repo_id INTEGER,
                name TEXT,
                version TEXT,
                author TEXT,
                is_official BOOLEAN DEFAULT 0,
                config_json TEXT,
                is_active BOOLEAN DEFAULT 1,
                installed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(repo_id) REFERENCES repositories(id)
            );

            CREATE TABLE IF NOT EXISTS protected_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repo_id INTEGER,
                file_path TEXT,
                added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(repo_id) REFERENCES repositories(id)
            );
        `);

        try {
            const columns = this.db.prepare("PRAGMA table_info(scan_logs)").all();
            const hasPinned = columns.some(col => col.name === 'pinned');
            if (!hasPinned) {
                this.db.exec('ALTER TABLE scan_logs ADD COLUMN pinned BOOLEAN DEFAULT 0');
            }
        } catch (err) {
            console.error('[DB] Migration failed:', err.message);
        }

        // Migration: Add sandbox columns to repositories if they don't exist
        try {
            const repoCols = this.db.prepare("PRAGMA table_info(repositories)").all();
            const colNames = repoCols.map(c => c.name);
            if (!colNames.includes('sandbox_consent')) {
                this.db.exec('ALTER TABLE repositories ADD COLUMN sandbox_consent BOOLEAN DEFAULT 0');
            }
            if (!colNames.includes('sandbox_version')) {
                this.db.exec('ALTER TABLE repositories ADD COLUMN sandbox_version TEXT DEFAULT NULL');
            }
        } catch (err) {
            console.error('[DB] Sandbox migration failed:', err.message);
        }
    }

    // --- Audit Logs ---
    addAuditLog(repoId, eventType, description, target, commitHash = null) {
        const stmt = this.db.prepare('INSERT INTO audit_logs (repo_id, event_type, description, target, commit_hash) VALUES (?, ?, ?, ?, ?)');
        return stmt.run(repoId, eventType, description, target, commitHash);
    }

    getAuditLogs(repoId = 'all') {
        if (repoId === 'all') {
            return this.db.prepare(`
                SELECT a.*, r.github_full_name 
                FROM audit_logs a 
                LEFT JOIN repositories r ON a.repo_id = r.id 
                ORDER BY a.created_at DESC
            `).all();
        }
        return this.db.prepare(`
            SELECT a.*, r.github_full_name 
            FROM audit_logs a 
            LEFT JOIN repositories r ON a.repo_id = r.id 
            WHERE a.repo_id = ? 
            ORDER BY a.created_at DESC
        `).all(repoId);
    }

    addRepository(localPath, githubName) {
        if (githubName) {
            const existing = this.db.prepare('SELECT id FROM repositories WHERE github_full_name = ?').get(githubName);
            if (existing) return existing.id;
        }
        const pathVal = localPath || null;
        const stmt = this.db.prepare('INSERT OR IGNORE INTO repositories (local_path, github_full_name) VALUES (?, ?)');
        const info = stmt.run(pathVal, githubName);
        return info.lastInsertRowid;
    }

    updateRepoPath(repoId, localPath) {
        const stmt = this.db.prepare('UPDATE repositories SET local_path = ? WHERE id = ?');
        return stmt.run(localPath, repoId).changes > 0;
    }

    deleteRepository(repoId) {
        this.db.prepare('DELETE FROM security_config WHERE repo_id = ?').run(repoId);
        this.db.prepare('DELETE FROM scan_logs WHERE repo_id = ?').run(repoId);
        this.db.prepare('DELETE FROM prohibited_assets WHERE repo_id = ?').run(repoId);
        this.db.prepare('DELETE FROM audit_logs WHERE repo_id = ?').run(repoId);
        const stmt = this.db.prepare('DELETE FROM repositories WHERE id = ?');
        const info = stmt.run(repoId);
        return info.changes > 0;
    }

    getRepositories() {
        return this.db.prepare('SELECT * FROM repositories').all();
    }

    getRepositoryById(id) {
        return this.db.prepare('SELECT * FROM repositories WHERE id = ?').get(id);
    }

    getRepositoryByFullName(fullName) {
        return this.db.prepare('SELECT * FROM repositories WHERE github_full_name = ?').get(fullName);
    }

    updateRepoStatus(repoId, status) {
        const stmt = this.db.prepare('UPDATE repositories SET status = ?, last_scan_at = CURRENT_TIMESTAMP WHERE id = ?');
        return stmt.run(status, repoId);
    }

    // --- Scaling Logs ---
    addScanLog(repoId, eventType, riskLevel, description, evidence) {
        const stmt = this.db.prepare('INSERT INTO scan_logs (repo_id, event_type, risk_level, description, evidence_metadata) VALUES (?, ?, ?, ?, ?)');
        return stmt.run(repoId, eventType, riskLevel, description, JSON.stringify(evidence));
    }

    getLogsByRepoFilter(repoId) {
        if (!repoId || repoId === 'all') {
            return this.db.prepare('SELECT * FROM scan_logs ORDER BY created_at DESC').all();
        }
        return this.db.prepare('SELECT * FROM scan_logs WHERE repo_id = ? ORDER BY created_at DESC').all(repoId);
    }

    getPinnedLogs(repoId) {
        if (!repoId || repoId === 'all') {
            return this.db.prepare('SELECT * FROM scan_logs WHERE pinned = 1 ORDER BY created_at DESC').all();
        }
        return this.db.prepare('SELECT * FROM scan_logs WHERE repo_id = ? AND pinned = 1 ORDER BY created_at DESC').all(repoId);
    }

    togglePin(logId, isPinned) {
        const stmt = this.db.prepare('UPDATE scan_logs SET pinned = ? WHERE id = ?');
        const info = stmt.run(isPinned ? 1 : 0, logId);
        return info.changes > 0;
    }

    // --- Trusted Contributors ---
    getTrustedContributors() {
        return this.db.prepare('SELECT * FROM trusted_contributors ORDER BY username ASC').all();
    }

    addTrustedContributor(username) {
        const stmt = this.db.prepare('INSERT OR IGNORE INTO trusted_contributors (username) VALUES (?)');
        const info = stmt.run(username);
        return info.changes > 0;
    }

    removeTrustedContributor(username) {
        const stmt = this.db.prepare('DELETE FROM trusted_contributors WHERE username = ?');
        const info = stmt.run(username);
        return info.changes > 0;
    }

    // --- System Config ---
    getSystemConfig(key) {
        const stmt = this.db.prepare('SELECT value FROM system_config WHERE key = ?');
        const row = stmt.get(key);
        return row ? row.value : null;
    }

    deleteRepository(repoId) {
        // First delete dependent records
        this.db.prepare('DELETE FROM protected_files WHERE repo_id = ?').run(repoId);
        this.db.prepare('DELETE FROM repo_packs WHERE repo_id = ?').run(repoId);
        this.db.prepare('DELETE FROM security_config WHERE repo_id = ?').run(repoId);
        this.db.prepare('DELETE FROM scan_logs WHERE repo_id = ?').run(repoId);
        
        const stmt = this.db.prepare('DELETE FROM repositories WHERE id = ?');
        const info = stmt.run(repoId);
        return info.changes > 0;
    }

    setSandboxConsent(repoId, consented) {
        const stmt = this.db.prepare('UPDATE repositories SET sandbox_consent = ? WHERE id = ?');
        return stmt.run(consented ? 1 : 0, repoId).changes > 0;
    }

    setSandboxVersion(repoId, version) {
        const stmt = this.db.prepare('UPDATE repositories SET sandbox_version = ? WHERE id = ?');
        return stmt.run(version, repoId).changes > 0;
    }

    // --- Config Packs (Phase 13) ---
    installPack(repoId, packData, isOfficial) {
        const stmt = this.db.prepare(`
            INSERT INTO repo_packs (repo_id, name, version, author, is_official, config_json)
            VALUES (?, ?, ?, ?, ?, ?)
        `);
        const info = stmt.run(
            repoId, 
            packData.metadata.name || 'Unknown Pack', 
            packData.metadata.version || '1.0.0', 
            packData.metadata.author || 'Unknown', 
            isOfficial ? 1 : 0, 
            JSON.stringify(packData.config || {})
        );
        return info.lastInsertRowid;
    }

    getRepoPacks(repoId) {
        return this.db.prepare('SELECT id, repo_id, name, version, author, is_official, is_active, installed_at FROM repo_packs WHERE repo_id = ? ORDER BY installed_at DESC').all(repoId);
    }

    togglePack(packId, active) {
        const stmt = this.db.prepare('UPDATE repo_packs SET is_active = ? WHERE id = ?');
        return stmt.run(active ? 1 : 0, packId).changes > 0;
    }

    deletePack(packId) {
        const stmt = this.db.prepare('DELETE FROM repo_packs WHERE id = ?');
        return stmt.run(packId).changes > 0;
    }

    getEffectiveConfig(repoId) {
        // 1. Get base config (or defaults if missing)
        const baseConfigStmt = this.db.prepare('SELECT strict_mode, ignore_scripts, auto_scan_pr FROM security_config WHERE repo_id = ?').get(repoId);
        
        // Defaults if base is missing
        let effective = baseConfigStmt ? {
            strict_mode: !!baseConfigStmt.strict_mode,
            ignore_scripts: !!baseConfigStmt.ignore_scripts,
            auto_scan_pr: !!baseConfigStmt.auto_scan_pr
        } : {
            strict_mode: false,
            ignore_scripts: true,
            auto_scan_pr: true
        };

        // 2. Get active packs, ordered by ASC so the latest one overrides
        const activePacks = this.db.prepare('SELECT config_json FROM repo_packs WHERE repo_id = ? AND is_active = 1 ORDER BY installed_at ASC').all(repoId);
        
        for (const pack of activePacks) {
            try {
                const config = JSON.parse(pack.config_json);
                effective = { ...effective, ...config }; // Merge!
            } catch (e) {
                console.error('[DB] Failed to parse pack config:', e);
            }
        }
        
        return effective;
    }

    resetPacks(repoId) {
        const stmt = this.db.prepare('DELETE FROM repo_packs WHERE repo_id = ?');
        return stmt.run(repoId).changes > 0;
    }

    // --- Protected Files (Phase 14) ---
    getProtectedFiles(repoId) {
        return this.db.prepare('SELECT * FROM protected_files WHERE repo_id = ? ORDER BY added_at DESC').all(repoId);
    }

    addProtectedFile(repoId, filePath) {
        // Evitar duplicados
        const exists = this.db.prepare('SELECT id FROM protected_files WHERE repo_id = ? AND file_path = ?').get(repoId, filePath);
        if (exists) return exists.id;

        const stmt = this.db.prepare('INSERT INTO protected_files (repo_id, file_path) VALUES (?, ?)');
        return stmt.run(repoId, filePath).lastInsertRowid;
    }

    removeProtectedFile(id) {
        const stmt = this.db.prepare('DELETE FROM protected_files WHERE id = ?');
        return stmt.run(id).changes > 0;
    }
}

module.exports = new SentinelDB();
