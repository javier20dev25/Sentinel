/**
 * Sentinel: Database Helper
 * Handles persistence for repositories, scan logs, and configurations.
 */

const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const DB_PATH = path.join(process.cwd(), 'sentinel.db');

class SentinelDB {
    constructor() {
        this.db = new Database(DB_PATH);
        this.init();
    }

    init() {
        // Create tables if they don't exist
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
        `);

        // Migration: Add pinned column to scan_logs if it doesn't exist
        try {
            const columns = this.db.prepare("PRAGMA table_info(scan_logs)").all();
            const hasPinned = columns.some(col => col.name === 'pinned');
            if (!hasPinned) {
                this.db.exec('ALTER TABLE scan_logs ADD COLUMN pinned BOOLEAN DEFAULT 0');
            }
        } catch (err) {
            console.error('[DB] Migration failed:', err.message);
        }
    }

    addRepository(localPath, githubName) {
        const pathVal = localPath || null;
        const stmt = this.db.prepare('INSERT OR IGNORE INTO repositories (local_path, github_full_name) VALUES (?, ?)');
        const info = stmt.run(pathVal, githubName);
        return info.lastInsertRowid;
    }

    getRepositories() {
        return this.db.prepare('SELECT * FROM repositories').all();
    }

    addScanLog(repoId, eventType, riskLevel, description, evidence) {
        const stmt = this.db.prepare('INSERT INTO scan_logs (repo_id, event_type, risk_level, description, evidence_metadata) VALUES (?, ?, ?, ?, ?)');
        return stmt.run(repoId, eventType, riskLevel, description, JSON.stringify(evidence));
    }

    updateRepoStatus(repoId, status) {
        const stmt = this.db.prepare('UPDATE repositories SET status = ?, last_scan_at = CURRENT_TIMESTAMP WHERE id = ?');
        return stmt.run(status, repoId);
    }

    getLogsByRepoFilter(repoId) {
        if (!repoId || repoId === 'all') {
            return this.db.prepare('SELECT * FROM scan_logs ORDER BY created_at DESC').all();
        }
        return this.db.prepare('SELECT * FROM scan_logs WHERE repo_id = ? ORDER BY created_at DESC').all();
    }

    getPinnedLogs(repoId) {
        if (!repoId || repoId === 'all') {
            return this.db.prepare('SELECT * FROM scan_logs WHERE pinned = 1 ORDER BY created_at DESC').all();
        }
        return this.db.prepare('SELECT * FROM scan_logs WHERE repo_id = ? AND pinned = 1 ORDER BY created_at DESC').all();
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

    isTrusted(username) {
        const stmt = this.db.prepare('SELECT 1 FROM trusted_contributors WHERE username = ?');
        return stmt.get(username) !== undefined;
    }
}

module.exports = new SentinelDB();
