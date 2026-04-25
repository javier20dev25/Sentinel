const scanner = require('../src/ui/backend/scanner/index');
const path = require('path');

async function debugAuthors() {
    const repoPath = 'c:\\Users\\sleyt\\sentinel-local';
    const results = await scanner.scanDirectory(repoPath, null, 2, { profile: 'DEFAULT', forensics: true });
    
    const authors = new Set();
    results.rawAlerts.forEach(a => {
        if (a.forensics) authors.add(a.forensics.author);
    });
    
    console.log("Authors found with alerts:", Array.from(authors));
}

debugAuthors();
