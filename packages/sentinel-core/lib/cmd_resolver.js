/**
 * Sentinel: Platform-Aware Command Resolver
 * 
 * Resolves the correct executable for a package manager command
 * across Windows (.cmd wrappers), macOS, and Linux.
 * 
 * Problem: On Windows, `npm` is actually `npm.cmd`. Using spawn()
 * with shell:false fails because it can't find the executable.
 * Using shell:true introduces injection risk when args aren't escaped.
 * 
 * Solution: Resolve the .cmd wrapper explicitly on Windows,
 * keep shell:false for security, and escape args properly.
 */

'use strict';

const path = require('path');

// Windows CMD wrappers for common package managers
const WIN_CMD_WRAPPERS = {
    npm:    'npm.cmd',
    npx:    'npx.cmd',
    yarn:   'yarn.cmd',
    pnpm:   'pnpm.cmd',
    pip:    'pip.exe',
    pip3:   'pip3.exe',
    poetry: 'poetry.exe',
    uv:     'uv.exe',
    cargo:  'cargo.exe',
    docker: 'docker.exe'
};

const isWindows = process.platform === 'win32';

/**
 * Resolve the platform-correct executable name for a package manager.
 * @param {string} cmd - Base command name (e.g. 'npm', 'pip')
 * @returns {string} - Platform-correct executable
 */
function resolveCmd(cmd) {
    if (!isWindows) return cmd;
    return WIN_CMD_WRAPPERS[cmd.toLowerCase()] || cmd;
}

/**
 * Sanitize args for use with shell:false.
 * Strips shell metacharacters to prevent injection even in edge cases.
 * @param {string[]} args
 * @returns {string[]}
 */
function sanitizeArgs(args) {
    return args.map(arg => {
        // Allow: alphanumeric, dots, hyphens, underscores, slashes, @, :, =, +
        // This covers package names, versions, flags, and image refs
        const safe = String(arg).replace(/[^a-zA-Z0-9.\-_/@:=+^~*]/g, '');
        return safe;
    });
}

/**
 * Build a safe spawn configuration for a package manager command.
 * 
 * @param {string} manager - Package manager (npm, pip, docker, etc.)
 * @param {string[]} args - Arguments to pass
 * @returns {{ cmd: string, args: string[], options: object }}
 */
function buildSpawnConfig(manager, args = []) {
    const cmd = resolveCmd(manager);
    const safeArgs = sanitizeArgs(args);
    return {
        cmd,
        args: safeArgs,
        options: {
            stdio: 'inherit',
            shell: false  // Never use shell — security boundary
        }
    };
}

module.exports = { resolveCmd, sanitizeArgs, buildSpawnConfig, isWindows };
