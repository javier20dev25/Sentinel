/**
 * Sentinel: Finding Extractor for Web Verification (v1.0)
 * 
 * Extracts exact findings from lab targets to prepare for CVE/Web lookup.
 */

'use strict';

const scanner = require('../src/ui/backend/scanner/index');
const path = require('path');
const fs = require('fs');

const TARGETS = [
    { name: 'Juice Shop', path: 'c:\\Users\\sleyt\\sentinel-lab\\juice-shop' },
    { name: 'Axios', path: 'c:\\Users\\sleyt\\sentinel-lab\\npm-samples\\axios_source' },
    { name: 'Chalk', path: 'c:\\Users\\sleyt\\sentinel-lab\\npm-samples\\chalk_source' },
    { name: 'Fineract', path: 'c:\\Users\\sleyt\\sentinel-lab\\fineract' }
];

async function extractFindings() {
    const allFindings = [];

    for (const target of TARGETS) {
        if (!fs.existsSync(target.path)) continue;
        
        const results = await scanner.scanDirectory(target.path, null, 2, { profile: 'DEFAULT' });
        
        results.rawAlerts.slice(0, 5).forEach(a => {
            allFindings.push({
                target: target.name,
                file: a._file,
                rule: a.type,
                description: a.description
            });
        });
    }

    console.log(JSON.stringify(allFindings, null, 2));
}

extractFindings();
