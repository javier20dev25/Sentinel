/**
 * Sentinel: Filesystem Explorer
 * Provides tree structures of repository folders for UI interaction.
 */

const fs = require('fs');
const path = require('path');

class FSExplorer {
    /**
     * Returns a recursive tree of the repository structure
     * @param {string} rootPath - The base path of the repo
     * @param {number} depth - Max recursion depth to prevent heap overflow
     */
    getStructure(rootPath, depth = 5) {
        if (!fs.existsSync(rootPath)) return null;

        const name = path.basename(rootPath);
        const stats = fs.statSync(rootPath);
        const item = {
            name,
            path: rootPath,
            isDir: stats.isDirectory()
        };

        if (stats.isDirectory() && depth > 0) {
            // Exclude noise
            const excluded = ['node_modules', '.git', 'dist', 'build', '.next', 'out'];
            try {
                const children = fs.readdirSync(rootPath);
                item.children = children
                    .filter(child => !excluded.includes(child))
                    .map(child => this.getStructure(path.join(rootPath, child), depth - 1))
                    .filter(Boolean);
            } catch (err) {
                // Permission denied or other error
                item.error = err.message;
            }
        }

        return item;
    }
}

module.exports = new FSExplorer();
