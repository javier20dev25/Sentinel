// Mock Data from the DB Simulator

const MOCK_DATA = {
    overview: {
        totalEvents: 619,
        avgRisk: 0.64,
        criticalEvents: 87
    },
    topThreats: [
        { category: "Prototype Pollution", count: 60 },
        { category: "Credential Leak", count: 50 },
        { category: "Obfuscation", count: 50 },
        { category: "Supply Chain", count: 47 }
    ],
    riskTrend: {
        labels: ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
        data: [0.3, 0.45, 0.4, 0.8, 0.65, 0.5, 0.64]
    },
    repos: [
        { hash: "usr1_repo_a_hash", events: 142, avgRisk: 0.85, level: "critical" },
        { hash: "usr1_repo_b_hash", events: 89, avgRisk: 0.65, level: "high" },
        { hash: "usr1_repo_c_hash", events: 45, avgRisk: 0.45, level: "medium" },
        { hash: "usr1_repo_d_hash", events: 12, avgRisk: 0.15, level: "low" }
    ]
};

// Initialize Dashboard
document.addEventListener("DOMContentLoaded", () => {
    // 1. Overview
    document.getElementById('val-total').innerText = MOCK_DATA.overview.totalEvents;
    document.getElementById('val-risk').innerText = MOCK_DATA.overview.avgRisk.toFixed(2);
    document.getElementById('val-critical').innerText = MOCK_DATA.overview.criticalEvents;

    // 2. Top Threats Chart
    const ctxThreats = document.getElementById('topThreatsChart').getContext('2d');
    new Chart(ctxThreats, {
        type: 'bar',
        data: {
            labels: MOCK_DATA.topThreats.map(t => t.category),
            datasets: [{
                label: 'Event Count',
                data: MOCK_DATA.topThreats.map(t => t.count),
                backgroundColor: 'rgba(54, 162, 235, 0.7)',
                borderColor: 'rgba(54, 162, 235, 1)',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            scales: { y: { beginAtZero: true } },
            plugins: { legend: { display: false } }
        }
    });

    // 3. Risk Trend Chart
    const ctxTrend = document.getElementById('riskTrendChart').getContext('2d');
    new Chart(ctxTrend, {
        type: 'line',
        data: {
            labels: MOCK_DATA.riskTrend.labels,
            datasets: [{
                label: 'Avg Risk Score',
                data: MOCK_DATA.riskTrend.data,
                fill: true,
                backgroundColor: 'rgba(255, 99, 132, 0.2)',
                borderColor: 'rgba(255, 99, 132, 1)',
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            scales: { y: { min: 0, max: 1 } }
        }
    });

    // 4. Repo Table
    const tbody = document.getElementById('repo-table-body');
    MOCK_DATA.repos.forEach(repo => {
        const tr = document.createElement('tr');
        
        let badgeColor = '';
        if (repo.level === 'critical') badgeColor = 'critical';
        else if (repo.level === 'high') badgeColor = 'high';
        else if (repo.level === 'medium') badgeColor = 'medium';
        else badgeColor = 'low';

        tr.innerHTML = `
            <td><code>${repo.hash}</code></td>
            <td>${repo.events}</td>
            <td>${repo.avgRisk.toFixed(2)}</td>
            <td><span class="badge ${badgeColor}">${repo.level.toUpperCase()}</span></td>
        `;
        tbody.appendChild(tr);
    });
});
