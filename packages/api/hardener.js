/**
 * Sentinel: Security Hardener Service (HARDENED)
 * Manages global system security configurations (e.g., npm ignore-scripts).
 * 
 * SECURITY: All npm commands use execFileSync with array args.
 * Config values are strictly validated (boolean only).
 * 
 * Audit: VULN-001 remediated — 2 instances of execSync replaced.
 */

'use strict';

const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { isValidNpmConfigValue, sanitizeForLog } = require('../lib/sanitizer');

class SecurityHardener {
  /**
   * Retrieves the current status of known security switches.
   */
  getSwitchesStatus() {
    return {
      npmIgnoreScripts: this.getNpmIgnoreScripts(),
      secretScanning: this.getSecretScanning(),
      // Future switches can be added here (e.g., yarn strict-ssl, cargo settings)
    };
  }


  getConfigPath() {
    const sentinelDir = path.join(os.homedir(), '.sentinel');
    if (!fs.existsSync(sentinelDir)) fs.mkdirSync(sentinelDir, { recursive: true });
    return path.join(sentinelDir, 'config.json');
  }

  getSecretScanning() {
    try {
      const data = JSON.parse(fs.readFileSync(this.getConfigPath(), 'utf8'));
      return data.secretScanning !== false; // Default true
    } catch {
      return true; // Default true
    }
  }

  setSecretScanning(enable) {
    try {
      let data = {};
      const configPath = this.getConfigPath();
      if (fs.existsSync(configPath)) {
        data = JSON.parse(fs.readFileSync(configPath, 'utf8'));
      }
      data.secretScanning = !!enable;
      fs.writeFileSync(configPath, JSON.stringify(data, null, 2), 'utf8');
      return { success: true, enabled: enable };
    } catch (e) {
      return { success: false, error: sanitizeForLog(e.message) };
    }
  }

  /**
   * Checks if npm ignore-scripts is true globally.
   * SECURITY: Uses execFileSync with array args — no shell.
   */
  getNpmIgnoreScripts() {
    try {
      const output = execFileSync('npm', ['config', 'get', 'ignore-scripts', '--global'], {
        encoding: 'utf-8',
        timeout: 10000
      }).trim();
      return output === 'true';
    } catch {
      return false;
    }
  }

  /**
   * Toggles the npm ignore-scripts flag.
   * SECURITY: Value is strictly validated — only "true" or "false" accepted.
   * Uses execFileSync with array args — no shell interpolation.
   */
  setNpmIgnoreScripts(enable) {
    try {
      const val = enable ? 'true' : 'false';
      
      // Defense in depth: validate even though we control the value
      if (!isValidNpmConfigValue(val)) {
        return { success: false, error: 'Invalid config value' };
      }

      execFileSync('npm', ['config', 'set', 'ignore-scripts', val, '--global'], {
        encoding: 'utf-8',
        timeout: 10000
      });
      return { success: true, enabled: enable };
    } catch (e) {
      return { success: false, error: sanitizeForLog(e.message) };
    }
  }
}

module.exports = new SecurityHardener();
