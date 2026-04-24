const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

/**
 * Sentinel: Incremental Cache Engine (v1.0)
 * 
 * Minimizes I/O by skipping files that haven't changed since the last scan.
 */

class CacheEngine {
    constructor() {
        this.cacheDir = path.join(os.homedir(), '.sentinel');
        this.cachePath = path.join(this.cacheDir, 'scan_cache.json');
        this.cache = {};
        this.load();
    }

    load() {
        try {
            if (fs.existsSync(this.cachePath)) {
                this.cache = JSON.parse(fs.readFileSync(this.cachePath, 'utf8'));
            }
        } catch (e) {
            this.cache = {};
        }
    }

    save() {
        try {
            if (!fs.existsSync(this.cacheDir)) fs.mkdirSync(this.cacheDir, { recursive: true });
            fs.writeFileSync(this.cachePath, JSON.stringify(this.cache), 'utf8');
        } catch (e) {
            // Non-fatal if cache fails to save
        }
    }

    /**
     * Checks if a file is in cache and valid.
     * Uses path + size + mtime for fast check.
     */
    isValid(filePath, stats) {
        const key = crypto.createHash('md5').update(filePath).digest('hex');
        const entry = this.cache[key];
        
        if (entry && entry.size === stats.size && entry.mtime === stats.mtime.getTime()) {
            return entry.results;
        }
        return null;
    }

    update(filePath, stats, results) {
        const key = crypto.createHash('md5').update(filePath).digest('hex');
        this.cache[key] = {
            size: stats.size,
            mtime: stats.mtime.getTime(),
            results
        };
    }
}

module.exports = new CacheEngine();
