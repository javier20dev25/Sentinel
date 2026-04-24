/**
 * Sentinel Guard (v1.0)
 * 
 * Provisions OS-level package manager interception via shell profile aliases.
 * Makes Sentinel ineludible — even when the user types 'npm install' directly.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');

const SUPPORTED_MANAGERS = ['npm', 'pip', 'pip3', 'yarn', 'pnpm', 'cargo', 'docker'];

function getShellProfilePath() {
    const shell = process.env.SHELL || '';
    if (shell.includes('zsh')) return path.join(os.homedir(), '.zshrc');
    if (shell.includes('fish')) return path.join(os.homedir(), '.config/fish/config.fish');
    // PowerShell (Windows)
    if (process.platform === 'win32') {
        // Find PowerShell profile
        return path.join(os.homedir(), 'Documents', 'WindowsPowerShell', 'Microsoft.PowerShell_profile.ps1');
    }
    return path.join(os.homedir(), '.bashrc');
}

function generateUnixAliases() {
    return SUPPORTED_MANAGERS.map(mgr => {
        return [
            `# Sentinel Guard: ${mgr} interception`,
            `sentinel_${mgr}() {`,
            `  sentinel install ${mgr} "$@" && \\`,
            `  command ${mgr} "$@"`,
            `}`,
            `alias ${mgr}='sentinel_${mgr}'`
        ].join('\n');
    }).join('\n\n');
}

function generatePowerShellAliases() {
    return SUPPORTED_MANAGERS.map(mgr => {
        return [
            `# Sentinel Guard: ${mgr} interception`,
            `function ${mgr} {`,
            `  sentinel install ${mgr} $args`,
            `  if ($LASTEXITCODE -eq 0) { & "${mgr}.cmd" $args }`,
            `}`
        ].join('\n');
    }).join('\n\n');
}

const SENTINEL_GUARD_BLOCK_START = '# ====== SENTINEL GUARD START ======';
const SENTINEL_GUARD_BLOCK_END   = '# ====== SENTINEL GUARD END ======';

function enableGuard() {
    const profilePath = getShellProfilePath();
    const isWindows = process.platform === 'win32';
    const aliases = isWindows ? generatePowerShellAliases() : generateUnixAliases();
    const guardBlock = `\n${SENTINEL_GUARD_BLOCK_START}\n${aliases}\n${SENTINEL_GUARD_BLOCK_END}\n`;

    let existing = '';
    try { existing = fs.readFileSync(profilePath, 'utf8'); } catch (e) {}

    if (existing.includes(SENTINEL_GUARD_BLOCK_START)) {
        return { success: false, reason: 'Guard is already enabled.', profilePath };
    }

    const dir = path.dirname(profilePath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(profilePath, existing + guardBlock);
    
    return { success: true, profilePath, managers: SUPPORTED_MANAGERS };
}

function disableGuard() {
    const profilePath = getShellProfilePath();
    let existing = '';
    try { existing = fs.readFileSync(profilePath, 'utf8'); } catch (e) {
        return { success: false, reason: 'Shell profile not found.' };
    }

    const startIdx = existing.indexOf(SENTINEL_GUARD_BLOCK_START);
    const endIdx   = existing.indexOf(SENTINEL_GUARD_BLOCK_END);
    
    if (startIdx === -1) return { success: false, reason: 'Guard is not enabled.' };
    
    const cleaned = existing.slice(0, startIdx) + existing.slice(endIdx + SENTINEL_GUARD_BLOCK_END.length);
    fs.writeFileSync(profilePath, cleaned.replace(/\n{3,}/g, '\n\n'));
    return { success: true, profilePath };
}

function isGuardEnabled() {
    try {
        const profilePath = getShellProfilePath();
        const content = fs.readFileSync(profilePath, 'utf8');
        return content.includes(SENTINEL_GUARD_BLOCK_START);
    } catch (e) { return false; }
}

module.exports = { enableGuard, disableGuard, isGuardEnabled, getShellProfilePath, SUPPORTED_MANAGERS };
