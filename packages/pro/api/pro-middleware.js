/**
 * @sentinel/pro — Pro API Middleware
 *
 * Gates any API route or CLI command behind a valid Pro license.
 * Returns a 402 Payment Required error for non-Pro users with an upgrade URL.
 */

import { validateLicense } from '../license/validator.js';

/**
 * Express middleware: blocks route if no valid Pro license found.
 * Usage: router.get('/pro-feature', requirePro, handler)
 */
export function requirePro(req, res, next) {
  const license = validateLicense();
  if (!license.valid) {
    return res.status(402).json({
      error: 'SENTINEL_PRO_REQUIRED',
      tier: 'free',
      message: 'This feature requires Sentinel Pro. Upgrade to unlock it.',
      reason: license.reason,
      upgrade_url: 'https://sentinel-security.dev/upgrade' // placeholder
    });
  }
  // Attach license info to the request for downstream use
  req.license = license;
  next();
}

/**
 * CLI gate: Check Pro license and exit with clear message if not valid.
 * @param {string} featureName - Human-readable name of the Pro feature
 */
export function requireProCLI(featureName) {
  const license = validateLicense();
  if (!license.valid) {
    console.error(`\n🔒 ${featureName} is a Sentinel Pro feature.\n`);
    console.error(`   Reason: ${license.reason}`);
    console.error(`   Upgrade at: https://sentinel-security.dev/upgrade\n`);
    process.exit(2);
  }
  return license;
}
