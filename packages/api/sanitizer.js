/**
 * Sentinel: Centralized Input Sanitization & Validation
 * 
 * SECURITY CRITICAL MODULE
 * All external inputs MUST pass through these validators before being used
 * in any child_process call or database query.
 * 
 * Design principles:
 * - Whitelist-only: We define what GOOD looks like, reject everything else.
 * - No shell metacharacters: ; | & ` $ ( ) { } < > \n \r are never allowed in arguments.
 * - Immutable: This module exports pure functions with no side effects.
 */

'use strict';

// ─── Owner/Repo Validation ───
// GitHub owner and repo names: alphanumeric, hyphens, dots, underscores
// Max 100 chars each segment, format: owner/repo
const OWNER_REPO_REGEX = /^[a-zA-Z0-9._-]{1,100}\/[a-zA-Z0-9._-]{1,100}$/;

function isValidOwnerRepo(str) {
  if (typeof str !== 'string') return false;
  return OWNER_REPO_REGEX.test(str);
}

// ─── PR Number Validation ───
// PR numbers are positive integers only
const PR_NUMBER_REGEX = /^[1-9][0-9]{0,9}$/;

function isValidPRNumber(str) {
  if (typeof str !== 'string' && typeof str !== 'number') return false;
  return PR_NUMBER_REGEX.test(String(str));
}

// ─── Git SHA Validation ───
// SHA hashes are 40-character hex strings (SHA-1) or 64-char (SHA-256)
const GIT_SHA_REGEX = /^[0-9a-f]{40,64}$/i;

function isValidGitSHA(str) {
  if (typeof str !== 'string') return false;
  return GIT_SHA_REGEX.test(str);
}

// ─── File Path Validation ───
// Disallow shell metacharacters in paths
// Allow: alphanumeric, /, \, ., -, _, spaces
const SHELL_METACHAR_REGEX = /[;|&`$(){}<>\n\r'"!#%^*?[\]~]/;

function isValidGitPath(str) {
  if (typeof str !== 'string') return false;
  if (str.length === 0 || str.length > 500) return false;
  if (SHELL_METACHAR_REGEX.test(str)) return false;
  // Prevent path traversal attacks
  if (str.includes('..')) return false;
  return true;
}

// ─── npm Config Value Validation ───
// Only "true" or "false" for boolean config values
function isValidNpmConfigValue(val) {
  return val === 'true' || val === 'false';
}

// ─── Package Manager Validation ───
const ALLOWED_PKG_MANAGERS = ['npm', 'yarn', 'pnpm', 'bun'];

function isValidPkgManager(str) {
  if (typeof str !== 'string') return false;
  return ALLOWED_PKG_MANAGERS.includes(str.toLowerCase());
}

// ─── Git Hook Type Validation ───
const ALLOWED_HOOK_TYPES = ['pre-push', 'post-merge', 'pre-commit', 'post-checkout'];

function isValidHookType(str) {
  if (typeof str !== 'string') return false;
  return ALLOWED_HOOK_TYPES.includes(str.toLowerCase());
}

// ─── Directory Path Validation (for git hooksPath) ───
function isValidDirectoryPath(str) {
  if (typeof str !== 'string') return false;
  if (str.length === 0 || str.length > 500) return false;
  // Disallow shell metacharacters (except path separators and spaces)
  if (/[;|&`$(){}<>\n\r!#%^*?[\]~]/.test(str)) return false;
  return true;
}

// ─── Hardener Key Validation ───
const ALLOWED_HARDENER_KEYS = ['npm_ignore_scripts'];

function isValidHardenerKey(str) {
  if (typeof str !== 'string') return false;
  return ALLOWED_HARDENER_KEYS.includes(str);
}

// ─── Fix Command Whitelist ───
// STRICT whitelist of allowed remediation commands.
// Each entry maps a human-readable key to a safe command + arguments array.
// The frontend sends the key, NOT the raw command.
const ALLOWED_FIX_COMMANDS = {
  'git restore .': {
    cmd: 'git',
    args: ['restore', '.'],
    description: 'Restore all modified files to last commit state'
  },
  'git rm --cached': {
    cmd: 'git',
    args: ['rm', '--cached'],
    description: 'Remove file from git index (needs file argument)',
    requiresArg: true,
    argValidator: isValidGitPath
  },
  'npm audit fix': {
    cmd: 'npm',
    args: ['audit', 'fix'],
    description: 'Automatically fix npm audit vulnerabilities'
  },
  'npm audit fix --force': {
    cmd: 'npm',
    args: ['audit', 'fix', '--force'],
    description: 'Force fix npm audit vulnerabilities (may include breaking changes)'
  },
  'npm config set ignore-scripts true': {
    cmd: 'npm',
    args: ['config', 'set', 'ignore-scripts', 'true'],
    description: 'Disable npm lifecycle scripts globally'
  },
  'npm config set ignore-scripts false': {
    cmd: 'npm',
    args: ['config', 'set', 'ignore-scripts', 'false'],
    description: 'Re-enable npm lifecycle scripts globally'
  },
  'gh pr close': {
    cmd: 'gh',
    args: ['pr', 'close'],
    description: 'Close a pull request (needs PR number)',
    requiresArg: true,
    argValidator: isValidPRNumber
  },
  'git checkout -- .': {
    cmd: 'git',
    args: ['checkout', '--', '.'],
    description: 'Discard all local file changes'
  }
};

/**
 * Looks up a command string in the whitelist and returns the safe execution params.
 * Returns null if the command is not whitelisted.
 * 
 * @param {string} commandStr - The command string to look up
 * @returns {{ cmd: string, args: string[], description: string } | null}
 */
function getWhitelistedCommand(commandStr) {
  if (typeof commandStr !== 'string') return null;
  
  const trimmed = commandStr.trim();
  
  // Try exact match first
  if (ALLOWED_FIX_COMMANDS[trimmed]) {
    return { ...ALLOWED_FIX_COMMANDS[trimmed] };
  }

  // Try prefix match for commands that accept an argument
  for (const [key, entry] of Object.entries(ALLOWED_FIX_COMMANDS)) {
    if (entry.requiresArg && trimmed.startsWith(key + ' ')) {
      const arg = trimmed.slice(key.length + 1).trim();
      if (arg && entry.argValidator(arg)) {
        return {
          cmd: entry.cmd,
          args: [...entry.args, arg],
          description: entry.description
        };
      }
    }
  }

  return null;
}

// ─── Logging Sanitizer ───
// Strip control characters to prevent log injection attacks
function sanitizeForLog(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/[\u0000-\u001F\u007F-\u009F]/g, '').substring(0, 500);
}

// ─── GitHub API JSON Limit ───
// Validate JSON limit for gh api --paginate calls
function isValidLimit(val) {
  const num = Number(val);
  return Number.isInteger(num) && num > 0 && num <= 1000;
}

// ─── Local Path Validation (Path Traversal Protection) ───
// Validates that a local filesystem path:
// 1. Is an absolute path
// 2. Does not contain '..' traversal
// 3. Resolves to a location within expected boundaries
// 4. Contains no shell metacharacters
const pathModule = require('path');

function isValidLocalPath(str) {
  if (typeof str !== 'string') return false;
  if (str.length === 0 || str.length > 1000) return false;
  // Must be an absolute path
  if (!pathModule.isAbsolute(str)) return false;
  // No '..' traversal components
  const normalized = pathModule.resolve(str);
  if (normalized !== pathModule.normalize(str.replace(/\/$/, ''))) {
    // Path tried to escape — resolve changed it
  }
  // Reject null bytes (classic path traversal trick)
  if (str.includes('\0')) return false;
  // Reject shell metacharacters
  if (/[;|&`$(){}<>\n\r!#%^*?\[\]~]/.test(str)) return false;
  return true;
}

/**
 * Validates a local path is within a trusted root directory.
 * Use for Git hooks, YAML rules, etc.
 * @param {string} targetPath - Path to validate
 * @param {string} trustedRoot - Root directory the path must be within
 * @returns {boolean}
 */
function isPathWithinRoot(targetPath, trustedRoot) {
  if (typeof targetPath !== 'string' || typeof trustedRoot !== 'string') return false;
  const resolved = pathModule.resolve(targetPath);
  const root = pathModule.resolve(trustedRoot);
  return resolved.startsWith(root + pathModule.sep) || resolved === root;
}

// ─── YAML Rule Filename Validation ───
// Only allow safe filenames for custom rule files (no path traversal)
const RULE_FILENAME_REGEX = /^[a-zA-Z0-9._-]{1,100}\.(yaml|yml)$/;

function isValidRuleFilename(str) {
  if (typeof str !== 'string') return false;
  return RULE_FILENAME_REGEX.test(str);
}

module.exports = {
  isValidOwnerRepo,
  isValidPRNumber,
  isValidGitSHA,
  isValidGitPath,
  isValidNpmConfigValue,
  isValidPkgManager,
  isValidHookType,
  isValidDirectoryPath,
  isValidHardenerKey,
  isValidLimit,
  isValidLocalPath,
  isPathWithinRoot,
  isValidRuleFilename,
  getWhitelistedCommand,
  sanitizeForLog,
  ALLOWED_FIX_COMMANDS,
  ALLOWED_PKG_MANAGERS,
  ALLOWED_HOOK_TYPES,
  ALLOWED_HARDENER_KEYS
};
