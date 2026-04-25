const scanner = require('../src/ui/backend/scanner/index');
const path = require('path');
const fs = require('fs');

async function auditLockfile() {
    const authors = ['javier20dev25', 'Javier Astaroth'];
    const repoPath = 'c:\\Users\\sleyt\\sentinel-local';
    
    // Scan only package-lock.json at root
    const content = fs.readFileSync(path.join(repoPath, 'package-lock.json'), 'utf8');
    const scan = await scanner.scanFile('package-lock.json', content, null, { forensics: true });
    
    // Manually add forensics since scanFile doesn't do it (index.js does it in scanDirectory)
    const ForensicAudit = require('../src/ui/backend/scanner/forensics');
    const alerts = [];
    
    for (const a of scan.alerts) {
        const forensicData = ForensicAudit.blame(repoPath, 'package-lock.json', a.line_number);
        if (!forensicData.error && authors.includes(forensicData.author)) {
            alerts.push({ ...a, forensics: forensicData });
        }
    }

    console.log(`Audited package-lock.json. Found ${alerts.length} alerts attributed to user.`);
    
    alerts.slice(0, 5).forEach(a => {
        console.log(`[ALERT] Line ${a.line_number}: ${a.type} -> ${a.description}`);
    });
}

auditLockfile();
