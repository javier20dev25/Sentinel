const https = require('https');
const path = require('path');

class GitHubBridge {
    static getHeaders() {
        const headers = {
            'User-Agent': 'Sentinel-Shadow-Node/1.0',
            'Accept': 'application/vnd.github.v3+json'
        };
        // Optional: If running in CI or locally with GITHUB_TOKEN for private repos or higher rate limits
        if (process.env.GITHUB_TOKEN) {
            headers['Authorization'] = `Bearer ${process.env.GITHUB_TOKEN}`;
        }
        return headers;
    }

    /**
     * Fetches the files modified in a given Pull Request.
     */
    static async fetchPRFiles(repoFullName, prNumber) {
        return new Promise((resolve, reject) => {
            const options = {
                hostname: 'api.github.com',
                path: `/repos/${repoFullName}/pulls/${prNumber}/files?per_page=100`,
                method: 'GET',
                headers: this.getHeaders()
            };

            const req = https.request(options, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    if (res.statusCode === 200) {
                        try {
                            resolve(JSON.parse(data));
                        } catch (e) {
                            reject(new Error("Failed to parse GitHub API response"));
                        }
                    } else {
                        reject(new Error(`GitHub API Error: ${res.statusCode} - ${data.substring(0, 200)}`));
                    }
                });
            });
            
            req.on('error', reject);
            req.end();
        });
    }

    /**
     * Pre-filter intelligently to save compute and reduce latency.
     * Skips .md, .css, images, etc.
     */
    static isRiskyFile(filename) {
        const basename = path.basename(filename);
        
        // 1. High-risk configuration names
        const riskyNames = [
            'package.json', 
            'package-lock.json', 
            'yarn.lock', 
            '.npmrc', 
            'Dockerfile', 
            'docker-compose.yml'
        ];
        if (riskyNames.includes(basename)) return true;

        // 2. High-risk directories
        if (filename.includes('.github/workflows/')) return true;
        if (filename.includes('scripts/') || filename.includes('hooks/')) return true;

        // 3. Executable code extensions
        const riskyExtensions = ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs', '.py', '.sh', '.bash', '.go', '.rs'];
        if (riskyExtensions.some(ext => filename.endsWith(ext))) return true;

        return false;
    }
}

module.exports = GitHubBridge;
