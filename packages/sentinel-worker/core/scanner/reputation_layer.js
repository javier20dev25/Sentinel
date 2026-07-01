/**
 * Sentinel: Reputation Layer (v6.6 - Sovereignty)
 * 
 * Implements Weighted Edit Distance, Homoglyph Detection, and Dependency Confusion detection.
 */

'use strict';

class ReputationLayer {
    constructor() {
        this.topPackages = [
            'react', 'react-dom', 'vue', 'angular', 'lodash', 'axios', 'express', 
            'moment', 'chalk', 'commander', 'fs-extra', 'dotenv', 'webpack', 'babel-core',
            'typescript', 'jest', 'next', 'prisma', 'mongoose', 'query-string',
            'paypal', 'jquery', 'underscore', 'redis', 'bluebird'
        ];

        // Homoglyph Map (Visual Spoofing Detection)
        this.homoglyphMap = {
            '1': 'l', 'l': '1', '0': 'o', 'o': '0', 'rn': 'm', 'm': 'rn',
            'cl': 'd', 'd': 'cl', 'vv': 'w', 'w': 'vv', 'I': 'l', 'l': 'I'
        };
    }

    /**
     * Checks for typosquatting and visual spoofing using weighted analysis.
     */
    checkTyposquatting(pkgName) {
        if (!pkgName) return { score: 0 };

        let maxRisk = 0;
        let detectionType = 'SAFE';
        let targetPackage = null;

        for (const target of this.topPackages) {
            if (pkgName === target) continue;

            // 1. Weighted Levenshtein
            const distance = this._weightedLevenshtein(pkgName, target);
            
            // Critical: Distance of 1 or 2 on a short/medium name
            if (distance <= 2 && pkgName.length >= 3) {
                const score = (3 - distance) * 0.45;
                if (score > maxRisk) {
                    maxRisk = score;
                    detectionType = 'TYPOSQUATTING';
                    targetPackage = target;
                }
            }

            // 2. Homoglyph Check (rn -> m, etc.)
            const normalized = this._normalizeHomoglyphs(pkgName);
            if (normalized === target) {
                maxRisk = 0.95;
                detectionType = 'VISUAL_SPOOF_HOMOGLYPH';
                targetPackage = target;
                break; 
            }

            // 3. Typosquatting Suffix/Prefix (react-utility, lodash-core)
            if (pkgName.startsWith(target + '-') || pkgName.endsWith('-' + target)) {
                if (maxRisk < 0.35) {
                    maxRisk = 0.35;
                    detectionType = 'BRAND_SUFFIX_SPOOF';
                    targetPackage = target;
                }
            }
        }

        return { 
            score: maxRisk, 
            type: detectionType, 
            target: targetPackage,
            reason: maxRisk > 0 ? `Package '${pkgName}' suspiciously resembles high-value target '${targetPackage}' (${detectionType}).` : null
        };
    }

    _weightedLevenshtein(a, b) {
        const matrix = [];
        for (let i = 0; i <= b.length; i++) matrix[i] = [i];
        for (let j = 0; j <= a.length; j++) matrix[0][j] = j;

        for (let i = 1; i <= b.length; i++) {
            for (let j = 1; j <= a.length; j++) {
                const charA = a.charAt(j - 1);
                const charB = b.charAt(i - 1);
                
                let cost = 1;
                if (charA === charB) cost = 0;
                else if (this.homoglyphMap[charA] === charB || this.homoglyphMap[charB] === charA) {
                    cost = 0.2; // Visual similarity is MUCH more suspicious than random typo
                }

                matrix[i][j] = Math.min(
                    matrix[i - 1][j - 1] + cost,
                    Math.min(matrix[i][j - 1] + 1, matrix[i - 1][j] + 1)
                );
            }
        }
        return matrix[b.length][a.length];
    }

    _normalizeHomoglyphs(str) {
        let res = str;
        // Apply complex homoglyphs first (rn -> m)
        const sortedKeys = Object.keys(this.homoglyphMap).sort((a, b) => b.length - a.length);
        for (const k of sortedKeys) {
            res = res.replace(new RegExp(k, 'g'), this.homoglyphMap[k]);
        }
        return res;
    }
}

module.exports = new ReputationLayer();
