const http = require('http');
const https = require('https');

async function triggerWebhook(repo, prNumber) {
    return new Promise((resolve) => {
        const payload = JSON.stringify({
            action: "opened",
            pull_request: { number: prNumber },
            repository: { full_name: repo },
            sender: { login: "test_shadow_bot" }
        });

        const options = {
            hostname: 'localhost',
            port: 3001,
            path: '/webhook/github',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(payload),
                'x-github-delivery': `test-event-${prNumber}`
            }
        };

        const req = http.request(options, (res) => {
            res.on('data', () => {}); // Consume data
            res.on('end', resolve);
        });

        req.on('error', (e) => {
            console.error(`Error triggering webhook for ${repo}#${prNumber}: ${e.message}`);
            resolve();
        });

        req.write(payload);
        req.end();
    });
}

async function getRecentPRs(repo, count) {
    return new Promise((resolve, reject) => {
        const options = {
            hostname: 'api.github.com',
            path: `/repos/${repo}/pulls?state=closed&per_page=${count}`,
            method: 'GET',
            headers: { 'User-Agent': 'Test-Bot/1.0' }
        };

        const req = https.request(options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                if (res.statusCode === 200) {
                    const prs = JSON.parse(data).map(pr => pr.number);
                    resolve(prs);
                } else {
                    reject(new Error(`GitHub API Error: ${res.statusCode} ${data}`));
                }
            });
        });
        req.on('error', reject);
        req.end();
    });
}

async function run() {
    console.log("🚀 Starting Shadow Mode Batch A (Chaos Batch)...");
    
    const targetRepos = [
        'expressjs/express',
        'facebook/react',
        'vercel/next.js',
        'vitejs/vite',
        'nodejs/node',
        'supabase/supabase'
    ];
    
    // Batch A: 4 PRs per repo to test for crashes/deadlocks/timeouts
    const PR_COUNT_PER_REPO = 4;

    for (const repo of targetRepos) {
        console.log(`\n📂 [CHAOS] Processing repository: ${repo}`);
        try {
            const prs = await getRecentPRs(repo, PR_COUNT_PER_REPO);
            console.log(`[${repo}] Found PRs: ${prs.join(', ')}`);

            // Concurrency Control: Max 3 concurrent PRs per repo
            const CONCURRENCY = 3;
            for (let i = 0; i < prs.length; i += CONCURRENCY) {
                const batch = prs.slice(i, i + CONCURRENCY);
                console.log(`[${repo}] Ingesting batch: ${batch.join(', ')}`);
                
                await Promise.all(batch.map(pr => triggerWebhook(repo, pr)));
                
                // Delay between batches to let workers breathe
                await new Promise(r => setTimeout(r, 2000));
            }

        } catch (e) {
            console.error(`[${repo}] Chaos batch failed:`, e.message);
        }
    }

    console.log("\n✅ Chaos Batch A queued! Review logs for timeouts or worker crashes.");
}

run();
