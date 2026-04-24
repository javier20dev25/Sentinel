const fs = require('fs');
const path = require('path');
const os = require('os');

/**
 * Symlink Maze Generator (Phase 9.5)
 * Creates complex symlink structures, including the "Symlink Bomb".
 */
async function generateSymlinks(targetDir) {
    if (!fs.existsSync(targetDir)) fs.mkdirSync(targetDir, { recursive: true });

    // 1. Double Circular Loop (a -> b -> a)
    const dirA = path.join(targetDir, 'circ_a');
    const dirB = path.join(targetDir, 'circ_b');
    if (!fs.existsSync(dirA)) fs.mkdirSync(dirA);
    if (!fs.existsSync(dirB)) fs.mkdirSync(dirB);
    
    try {
        fs.symlinkSync('../circ_b', path.join(dirA, 'to_b'), 'dir');
        fs.symlinkSync('../circ_a', path.join(dirB, 'to_a'), 'dir');
    } catch(e) {}

    // 2. The Symlink Bomb (a -> b -> c ... -> a)
    let prevDir = targetDir;
    const bombPath = path.join(targetDir, 'bomb');
    if (!fs.existsSync(bombPath)) fs.mkdirSync(bombPath);

    const alphabet = 'abcdefghijklmnopqrstuvwxyz'.split('');
    const bombDirs = [];
    
    for (const char of alphabet) {
        const d = path.join(bombPath, char);
        if (!fs.existsSync(d)) fs.mkdirSync(d);
        bombDirs.push(d);
    }
    
    for (let i = 0; i < bombDirs.length; i++) {
        const next = bombDirs[(i + 1) % bombDirs.length];
        try {
            fs.symlinkSync(next, path.join(bombDirs[i], 'next'), 'dir');
        } catch(e) {}
    }

    // 3. Root Escape Attempts
    const escapeDir = path.join(targetDir, 'escapes');
    if (!fs.existsSync(escapeDir)) fs.mkdirSync(escapeDir);
    
    try {
        // Point to home directory (outside root)
        fs.symlinkSync(os.homedir(), path.join(escapeDir, 'home_escape'), 'dir');
        // Point to a system file
        const targetFile = process.platform === 'win32' ? 'C:\\Windows\\System32\\drivers\\etc\\hosts' : '/etc/passwd';
        fs.symlinkSync(targetFile, path.join(escapeDir, 'system_file_escape'), 'file');
    } catch(e) {}

    return 'Maze Generated';
}

if (require.main === module) {
    const target = process.argv[2] || './tests/fixtures/symlinks';
    generateSymlinks(target).then(res => console.log(`[SYMLINK] ${res} in ${target}`));
}

module.exports = generateSymlinks;
