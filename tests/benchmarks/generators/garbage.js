const fs = require('fs');
const path = require('path');
const SeededRandom = require('./utils');

/**
 * Garbage Bin Generator (Phase 9.5)
 * Creates 5000 deterministic files with varying sizes and extensions.
 */
async function generateGarbage(targetDir) {
    const rng = new SeededRandom(1337);
    const extensions = ['.js', '.ts', '.json', '.txt', '.md', '.log', '.bin', '.bak', '.tmp', '.weird'];
    
    const distribution = [
        { count: 4000, min: 1, max: 5120 },      // Small (1B - 5KB)
        { count: 800, min: 5120, max: 524288 },  // Medium (5KB - 512KB)
        { count: 200, min: 524288, max: 10485760 } // Large (512KB - 10MB)
    ];

    if (!fs.existsSync(targetDir)) fs.mkdirSync(targetDir, { recursive: true });

    let totalCreated = 0;
    
    for (const tier of distribution) {
        for (let i = 0; i < tier.count; i++) {
            const ext = rng.pick(extensions);
            const filename = `garbage_${totalCreated}${ext}`;
            const size = rng.range(tier.min, tier.max);
            const filePath = path.join(targetDir, filename);
            
            // PERFORMANCE FIX: Don't loop byte-by-byte for 10MB files.
            const content = Buffer.alloc(size);
            const chunk = Buffer.from(Array.from({length: Math.min(size, 1024)}, () => rng.range(0, 255)));
            for (let offset = 0; offset < size; offset += chunk.length) {
                chunk.copy(content, offset, 0, Math.min(chunk.length, size - offset));
            }
            
            fs.writeFileSync(filePath, content);
            totalCreated++;
        }
    }
    
    return totalCreated;
}

if (require.main === module) {
    const target = process.argv[2] || './tests/fixtures/garbage';
    generateGarbage(target).then(count => console.log(`[GARBAGE] Generated ${count} files in ${target}`));
}

module.exports = generateGarbage;
