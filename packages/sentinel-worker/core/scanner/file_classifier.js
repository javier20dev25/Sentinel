const fs = require('fs');
const path = require('path');
const CONFIG = require('./config');

/**
 * Sentinel: Intelligent File Classifier (v1.0)
 * 
 * Handles binary detection and granular categorization of files.
 */

class FileClassifier {
    /**
     * Determines if a file is binary by sampling the first 512 bytes.
     * Looks for null bytes and magic markers.
     */
    static isBinary(filePath) {
        try {
            const fd = fs.openSync(filePath, 'r');
            const buffer = Buffer.alloc(CONFIG.PERFORMANCE.BINARY_SAMPLE_SIZE);
            const bytesRead = fs.readSync(fd, buffer, 0, CONFIG.PERFORMANCE.BINARY_SAMPLE_SIZE, 0);
            fs.closeSync(fd);

            if (bytesRead === 0) return false;

            // Heuristic: If more than 10% of the sample are null bytes or non-text control chars
            let suspiciousChars = 0;
            for (let i = 0; i < bytesRead; i++) {
                const char = buffer[i];
                if (char === 0 || (char < 32 && char !== 9 && char !== 10 && char !== 13)) {
                    suspiciousChars++;
                }
            }

            return (suspiciousChars / bytesRead) > 0.1;
        } catch (e) {
            return false; // Safely assume not binary if unreadable
        }
    }

    /**
     * Classifies a file based on its extension and name.
     */
    static classify(filename, filePath) {
        const ext = path.extname(filename).toLowerCase();
        
        // 1. Check for explicit Lockfiles (higher priority)
        if (CONFIG.CATEGORIES.LOCKFILE.includes(filename)) return 'LOCKFILE';
        
        // 2. Map extensions to categories
        for (const [category, extensions] of Object.entries(CONFIG.CATEGORIES)) {
            if (extensions.includes(ext)) return category;
        }

        // 3. Binary detection fallback for unknown extensions
        if (this.isBinary(filePath)) return 'BINARY';

        return 'UNKNOWN';
    }

    /**
     * Verifies if a file path is safe from path traversal.
     */
    static isPathSafe(filePath, rootPath) {
        const resolved = path.resolve(filePath);
        const resolvedRoot = path.resolve(rootPath);
        return resolved.startsWith(resolvedRoot);
    }
}

module.exports = FileClassifier;
