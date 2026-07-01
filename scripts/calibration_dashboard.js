/**
 * Sentinel: Calibration & Observability Dashboard (v1.0)
 * 
 * Aggregates observations.jsonl to provide statistical insights 
 * across different repository profiles.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { PATHS } = require('../packages/sentinel-worker/core/scanner/data_paths');

function loadObservations() {
    if (!fs.existsSync(PATHS.OBSERVATIONS)) return [];
    return fs.readFileSync(PATHS.OBSERVATIONS, 'utf8')
        .split('\n')
        .filter(l => l.trim())
        .map(l => JSON.parse(l));
}

function loadLabels() {
    if (!fs.existsSync(PATHS.LABELS)) return {};
    const labels = {};
    const lines = fs.readFileSync(PATHS.LABELS, 'utf8').split('\n');
    for (const line of lines) {
        if (!line.trim()) continue;
        const record = JSON.parse(line);
        labels[record.fingerprint] = record.label;
    }
    return labels;
}

function runDashboard() {
    const observations = loadObservations();
    const labels = loadLabels();

    if (observations.length === 0) {
        console.log("⚠️ No observations found. Run shadow traffic first.");
        return;
    }

    const profiles = {};
    let globalStats = { total: 0, pass: 0, review: 0, block: 0, fp: 0 };

    // Group by profile
    for (const obs of observations) {
        const p = obs.repo_profile || 'unknown';
        if (!profiles[p]) {
            profiles[p] = {
                total: 0, pass: 0, review: 0, block: 0, fp: 0,
                rawSum: 0, effectiveSum: 0,
                repos: new Set()
            };
        }
        
        const st = profiles[p];
        st.total++;
        st.rawSum += obs.raw_impact;
        st.effectiveSum += obs.effective_impact;
        st.repos.add(obs.repo);

        if (obs.verdict === 'PASS') st.pass++;
        else if (obs.verdict.startsWith('REVIEW')) st.review++;
        else if (obs.verdict === 'BLOCK' || obs.verdict === 'SECURITY_HOLD') st.block++;

        if (labels[obs.fingerprint] === 'FALSE_POSITIVE') {
            st.fp++;
            globalStats.fp++;
        }

        globalStats.total++;
        if (obs.verdict === 'PASS') globalStats.pass++;
        else if (obs.verdict.startsWith('REVIEW')) globalStats.review++;
        else if (obs.verdict === 'BLOCK' || obs.verdict === 'SECURITY_HOLD') globalStats.block++;
    }

    console.log("\n========================================================");
    console.log("🛡️  SENTINEL OBSERVABILITY DASHBOARD");
    console.log("========================================================\n");

    for (const [profileName, st] of Object.entries(profiles)) {
        const passPct = ((st.pass / st.total) * 100).toFixed(1);
        const reviewPct = ((st.review / st.total) * 100).toFixed(1);
        const blockPct = ((st.block / st.total) * 100).toFixed(1);
        const alertDensity = (((st.review + st.block) / st.total) * 100).toFixed(1);
        const fpRate = st.total > 0 ? ((st.fp / st.total) * 100).toFixed(1) : 0;
        
        const avgRaw = (st.rawSum / st.total);
        const avgEff = (st.effectiveSum / st.total);
        const dampeningDiff = (avgRaw - avgEff).toFixed(1);
        const dampeningRatio = avgRaw > 0 ? ((1 - (avgEff / avgRaw)) * 100).toFixed(1) : '0.0';

        console.log(`📂 PROFILE: \x1b[36m${profileName.toUpperCase()}\x1b[0m (${st.repos.size} repos)`);
        console.log(`   Traffic      : ${st.total} evaluations`);
        console.log(`   Verdict Dist : \x1b[32mPASS: ${passPct}%\x1b[0m | \x1b[33mREVIEW: ${reviewPct}%\x1b[0m | \x1b[31mBLOCK: ${blockPct}%\x1b[0m`);
        console.log(`   Alert Density: ${alertDensity}% of PRs flagged`);
        console.log(`   Known FP Rate: ${fpRate}% (based on HITL labels)`);
        console.log(`   Impact Delta : Raw ${avgRaw.toFixed(1)} ➔ Effective ${avgEff.toFixed(1)}`);
        console.log(`   Dampening    : \x1b[35m${dampeningRatio}%\x1b[0m (Avg -${dampeningDiff} pts)`);
        console.log("--------------------------------------------------------");
    }

    console.log("\n🌐 GLOBAL METRICS");
    console.log(`   Total PRs Evaluated : ${globalStats.total}`);
    console.log(`   Global Alert Density: ${(((globalStats.review + globalStats.block) / globalStats.total) * 100).toFixed(1)}%`);
    console.log(`   Global FP Rate      : ${((globalStats.fp / globalStats.total) * 100).toFixed(1)}%`);
    console.log("========================================================\n");
}

runDashboard();
