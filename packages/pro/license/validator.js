/**
 * @sentinel/pro — License Validator
 * Checks if the current machine has a valid Sentinel Pro license.
 *
 * License file is stored at: ~/.sentinel/license.json
 * Format: { key, activatedAt, machineId, expiresAt }
 */

import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

const LICENSE_PATH = join(homedir(), '.sentinel', 'license.json');

/**
 * @typedef {Object} LicenseStatus
 * @property {boolean} valid - Whether the license is currently valid
 * @property {string} tier - 'free' | 'pro'
 * @property {string|null} key - The license key (masked)
 * @property {string|null} expiresAt - ISO date string or null
 * @property {string|null} reason - Reason for invalidity, if applicable
 */

/**
 * Validate the local Sentinel Pro license.
 * @returns {LicenseStatus}
 */
export function validateLicense() {
  if (!existsSync(LICENSE_PATH)) {
    return { valid: false, tier: 'free', key: null, expiresAt: null, reason: 'NO_LICENSE_FILE' };
  }

  try {
    const raw = readFileSync(LICENSE_PATH, 'utf-8');
    const license = JSON.parse(raw);

    // Check expiry
    if (license.expiresAt && new Date(license.expiresAt) < new Date()) {
      return { valid: false, tier: 'free', key: maskKey(license.key), expiresAt: license.expiresAt, reason: 'LICENSE_EXPIRED' };
    }

    // TODO: Add machine fingerprint verification (license.machineId === currentMachineId)
    // TODO: Add online validation call to licensing server

    return {
      valid: true,
      tier: 'pro',
      key: maskKey(license.key),
      expiresAt: license.expiresAt || null,
      reason: null
    };
  } catch {
    return { valid: false, tier: 'free', key: null, expiresAt: null, reason: 'INVALID_LICENSE_FILE' };
  }
}

/**
 * Mask a license key for safe display (e.g., SNTL-PRO-****-****-****-ABCD)
 * @param {string} key
 * @returns {string}
 */
function maskKey(key) {
  if (!key || key.length < 8) return '****';
  const parts = key.split('-');
  return parts.map((p, i) => (i === 0 || i === parts.length - 1) ? p : '****').join('-');
}
