/**
 * Sentinel: Adversarial Mutation Lab (v1.0)
 * 
 * Objective: Generate semantic mutations of existing threats.
 */

'use strict';

const fs = require('fs');
const path = require('path');

const BASE_CORPUS_DIR = path.join(__dirname, '..', 'scripts', 'redteam_corpus', 'malicious');
const MUTATED_DIR = path.join(__dirname, '..', 'scripts', 'redteam_corpus', 'mutated');

const MUTATIONS = {
    'OBFUSCATION_BASE64': (signals) => signals.map(s => s === 'NETWORK' ? 'OBFUSCATION' : s),
    'SUPPLY_CHAIN_POSTINSTALL': (signals) => [...signals, 'SUPPLY_CHAIN_TAMPERING'],
    'DYNAMIC_EXEC': (signals) => signals.map(s => s === 'EXECUTION' ? 'EVASION' : s),
    'DATA_EXFIL_STEALTH': (signals) => [...signals, 'ENCODING']
};

function mutateAll() {
    if (!fs.existsSync(MUTATED_DIR)) fs.mkdirSync(MUTATED_DIR, { recursive: true });

    const baseFiles = fs.readdirSync(BASE_CORPUS_DIR).filter(f => f.endsWith('.json'));
    let count = 0;

    for (const file of baseFiles) {
        const base = JSON.parse(fs.readFileSync(path.join(BASE_CORPUS_DIR, file), 'utf8'));
        
        for (const [name, mutator] of Object.entries(MUTATIONS)) {
            const mutated = {
                ...base,
                id: `${base.id}_mut_${name.toLowerCase()}`,
                signals: mutator(base.signals),
                mutation_type: name,
                base_case: base.id
            };
            
            fs.writeFileSync(path.join(MUTATED_DIR, `${mutated.id}.json`), JSON.stringify(mutated, null, 2));
            count++;
        }
    }

    console.log(`\n=== MUTATION LAB COMPLETE: ${count} VARIANTS GENERATED ===`);
}

mutateAll();
