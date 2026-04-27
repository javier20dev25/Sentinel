const crypto = require('crypto');

/**
 * Sentinel: Report Signature Engine (v1.0)
 * 
 * Provides cryptographic integrity and authenticity verification for scan reports.
 * Used to distinguish between Community (Unverified) and Enterprise (Certified) results.
 */

// WARNING: This key is public for Community Edition. 
// REAL SECURITY comes from Enterprise keys which are never checked into source control.
const COMMUNITY_SECRET = 'SENTINEL_COMMUNITY_ASSET_TRUST_2026';

/**
 * Deeply sorts object keys to ensure consistent hashing.
 */
function normalize(obj) {
    if (typeof obj !== 'object' || obj === null) return obj;
    if (Array.isArray(obj)) return obj.map(normalize);
    return Object.keys(obj).sort().reduce((acc, key) => {
        acc[key] = normalize(obj[key]);
        return acc;
    }, {});
}

/**
 * Signs a report object using HMAC-SHA256.
 * 
 * @param {Object} report - The findings/results object
 * @param {string} [licenseKey] - Optional Enterprise license key
 * @returns {Object} { signature, tier, timestamp }
 */
function signReport(report, licenseKey = null) {
    const tier = licenseKey ? 'ENTERPRISE-CERTIFIED' : 'COMMUNITY-UNVERIFIED';
    const secret = licenseKey || COMMUNITY_SECRET;
    
    // Extract only core findings for signing to allow for metadata flexibility without breaking sig
    const signableData = {
        scan_id: report.scan_id || 'legacy',
        threats: report.threats || 0,
        risk_band: report.riskBand || 'UNKNOWN',
        alerts_hash: crypto.createHash('md5').update(JSON.stringify(report.rawAlerts || [])).digest('hex')
    };

    const normalized = JSON.stringify(normalize(signableData));
    const hmac = crypto.createHmac('sha256', secret);
    hmac.update(normalized);
    
    return {
        signature: hmac.digest('hex'),
        tier: tier,
        signed_at: new Date().toISOString()
    };
}

module.exports = { signReport };
