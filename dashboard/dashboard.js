// =============================================================================
// dashboard.js — Enterprise DPI Engine Dashboard with Chart.js
// =============================================================================

'use strict';

// ---- Configuration ----------------------------------------------------------
const STATS_URL   = '../stats.json';
const REFRESH_MS  = 2000;
const HISTORY_LEN = 60;

// Chart.js defaults for dark theme
Chart.defaults.color = '#a1a1aa'; // text-secondary
Chart.defaults.font.family = "'IBM Plex Sans', sans-serif";
Chart.defaults.plugins.tooltip.backgroundColor = '#111111'; // bg-hover
Chart.defaults.plugins.tooltip.borderColor = '#333333'; // border
Chart.defaults.plugins.tooltip.borderWidth = 1;

// App colors mapping (Monochrome Vercel style)
const APP_COLORS = {
    'YouTube':   '#fafafa',
    'Netflix':   '#f4f4f5',
    'TikTok':    '#e4e4e7',
    'Facebook':  '#d4d4d8',
    'Instagram': '#a1a1aa',
    'Twitter':   '#71717a',
    'Discord':   '#52525b',
    'WhatsApp':  '#3f3f46',
    'Twitch':    '#27272a',
    'Reddit':    '#a1a1aa',
    'GitHub':    '#ffffff',
    'Google':    '#e4e4e7',
    'HTTPS':     '#71717a',
    'HTTP':      '#52525b',
    'DNS':       '#3f3f46',
    'Unknown':   '#27272a'
};

// ---- State ------------------------------------------------------------------
let kppsHistory = Array(HISTORY_LEN).fill(0);

// Chart instances
let throughputChart = null;
let doughnutChart   = null;
let histogramChart  = null;

// DOM helpers
const $ = id => document.getElementById(id);
const fmt = n => n >= 1e9 ? (n/1e9).toFixed(1)+'B'
               : n >= 1e6 ? (n/1e6).toFixed(1)+'M'
               : n >= 1e3 ? (n/1e3).toFixed(1)+'K'
               : String(n);

// ---- Theme ------------------------------------------------------------------
const updateChartTheme = () => {
    const isLight = document.documentElement.getAttribute('data-theme') === 'light';
    Chart.defaults.color = isLight ? '#666666' : '#a1a1aa';
    Chart.defaults.plugins.tooltip.backgroundColor = isLight ? '#ffffff' : '#111111';
    Chart.defaults.plugins.tooltip.borderColor = isLight ? '#cccccc' : '#333333';
    Chart.defaults.plugins.tooltip.titleColor = isLight ? '#000' : '#fff';
    Chart.defaults.plugins.tooltip.bodyColor = isLight ? '#666' : '#a1a1aa';
    
    // Update existing charts if they exist
    if (throughputChart) throughputChart.update();
    if (doughnutChart) doughnutChart.update();
    if (histogramChart) histogramChart.update();
};

const toggleTheme = () => {
    const current = document.documentElement.getAttribute('data-theme');
    const next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('theme', next);
    updateChartTheme();
};

// Initialize Theme
const savedTheme = localStorage.getItem('theme') || 'dark';
document.documentElement.setAttribute('data-theme', savedTheme);
updateChartTheme();

document.getElementById('themeToggle').addEventListener('click', toggleTheme);

// ---- Clock ------------------------------------------------------------------
setInterval(() => {
    $('headerTime').textContent = new Date().toLocaleTimeString();
}, 1000);
$('headerTime').textContent = new Date().toLocaleTimeString();

// ---- Demo Data --------------------------------------------------------------
function demoStats() {
    const t = Date.now() / 1000;
    const noise = () => Math.floor(Math.sin(t * 0.3 + Math.random()) * 50);
    return {
        total_packets:  45000 + noise() * 10,
        total_bytes:    8500000,
        forwarded:      38000 + noise() * 8,
        dropped:        7000 + noise() * 2,
        classified:     4990,
        elapsed_sec:    30.5,
        kpps:           438.5 + (Math.random() * 20 - 10),
        app_counts: {
            HTTPS: 8591, YouTube: 3636, Twitter: 3633, Google: 3427,
            Discord: 2125, Facebook: 1986, Twitch: 1940, GitHub: 1919,
            Netflix: 1917, Instagram: 1854, TikTok: 1842, WhatsApp: 1751, HTTP: 699
        },
        detected_snis: [
            'www.youtube.com', 'api.tiktok.com', 'www.netflix.com',
            'github.com', 'discord.com', 'www.twitter.com', 'api.example.com'
        ],
        total_anomalies: 42,
        anomaly_breakdown: {
            PORT_SCAN: 12,
            DDOS_SUSPECT: 8,
            DATA_EXFILTRATION: 5,
            HIGH_ENTROPY: 15,
            PROTOCOL_ANOMALY: 2
        },
        top_anomalies: [
            { src: '10.0.0.5',    dst: '203.0.113.42',  score: 0.97, type: 'PORT_SCAN',          sni: '',                   pkts: 847  },
            { src: '192.168.1.8', dst: '198.51.100.10', score: 0.91, type: 'DDOS_SUSPECT',       sni: '',                   pkts: 12450 },
            { src: '10.0.0.23',   dst: '45.33.32.156',  score: 0.85, type: 'DATA_EXFILTRATION',  sni: 'exfil.darknet.io',   pkts: 234  },
            { src: '172.16.0.44', dst: '104.26.10.78',  score: 0.78, type: 'HIGH_ENTROPY',       sni: 'cdn.suspect.com',    pkts: 56   },
            { src: '10.0.0.99',   dst: '192.0.2.1',     score: 0.62, type: 'PROTOCOL_ANOMALY',   sni: '',                   pkts: 18   }
        ]
    };
}

// ---- Data Fetching ----------------------------------------------------------
async function fetchStats() {
    try {
        const res = await fetch(STATS_URL + '?t=' + Date.now());
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        setStatus(true);
        return data;
    } catch (e) {
        setStatus(false);
        return demoStats();
    }
}

function setStatus(ok) {
    const badge = $('statusBadge');
    badge.className = 'status-badge' + (ok ? '' : ' error');
    $('statusText').textContent = ok ? 'Live — stats.json' : 'Demo Mode';
}

// ---- Init Charts ------------------------------------------------------------
function initCharts() {
    // 1. Throughput Line Chart
    const ctxLine = $('throughputLineChart').getContext('2d');
    throughputChart = new Chart(ctxLine, {
        type: 'line',
        data: {
            labels: Array(HISTORY_LEN).fill(''),
            datasets: [{
                label: 'Kpps (Packets/sec)',
                data: kppsHistory,
                borderColor: '#ffffff',
                backgroundColor: 'rgba(255, 255, 255, 0.1)',
                borderWidth: 2,
                fill: true,
                tension: 0.3,
                pointRadius: 0,
                pointHitRadius: 10
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 0 },
            scales: {
                x: { display: false },
                y: {
                    grid: { color: '#333333' },
                    beginAtZero: true
                }
            },
            plugins: { legend: { display: false } }
        }
    });

    // 2. Action Doughnut Chart
    const ctxDoughnut = $('actionDoughnutChart').getContext('2d');
    doughnutChart = new Chart(ctxDoughnut, {
        type: 'doughnut',
        data: {
            labels: ['Forwarded', 'Blocked'],
            datasets: [{
                data: [0, 0],
                backgroundColor: ['#10b981', '#ff0000'],
                borderWidth: 0,
                hoverOffset: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '85%',
            plugins: {
                legend: { position: 'bottom', labels: { boxWidth: 10, usePointStyle: true } }
            }
        }
    });

    // 3. Application Histogram
    const ctxHist = $('appHistogramChart').getContext('2d');
    const histGrad = ctxHist.createLinearGradient(0, 0, 0, 250);
    histGrad.addColorStop(0, '#0070f3'); // Vercel blue
    histGrad.addColorStop(1, 'rgba(0, 112, 243, 0.1)');

    histogramChart = new Chart(ctxHist, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Packets',
                data: [],
                backgroundColor: histGrad,
                borderRadius: 4,
                borderSkipped: false
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 500 },
            scales: {
                x: { grid: { display: false } },
                y: { grid: { color: '#333333' }, beginAtZero: true }
            },
            plugins: { legend: { display: false } }
        }
    });
}

// ---- Update UI --------------------------------------------------------------
function updateDashboard(stats) {
    // Hide loading screen
    const loader = $('loadingScreen');
    if (loader && !loader.classList.contains('hidden')) {
        loader.classList.add('hidden');
    }

    // Top Metrics
    $('totalPackets').textContent = fmt(stats.total_packets || 0);
    $('forwarded').textContent    = fmt(stats.forwarded     || 0);
    $('dropped').textContent      = fmt(stats.dropped       || 0);

    const kpps = stats.kpps || 0;
    $('throughput').textContent = kpps.toFixed(1) + ' K';

    const total = stats.total_packets || 1;
    $('fwdPct').textContent  = ((stats.forwarded || 0) / total * 100).toFixed(1) + '% of traffic';
    $('dropPct').textContent = ((stats.dropped   || 0) / total * 100).toFixed(1) + '% of traffic';
    
    if (stats.total_bytes && stats.elapsed_sec) {
        const mbps = (stats.total_bytes / 1024 / 1024) / stats.elapsed_sec;
        $('totalDelta').textContent = mbps.toFixed(1) + ' MB/s | ' + stats.elapsed_sec.toFixed(2) + 's';
    }

    $('classifiedCount').textContent = (stats.classified || 0) + ' flows classified';

    // Update Throughput Line Chart
    kppsHistory.push(kpps);
    if (kppsHistory.length > HISTORY_LEN) kppsHistory.shift();
    throughputChart.update();

    // Update Doughnut Chart
    doughnutChart.data.datasets[0].data = [stats.forwarded || 0, stats.dropped || 0];
    doughnutChart.update();

    // Process App Data
    const counts = stats.app_counts || {};
    const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 15);
    
    // Update Histogram
    histogramChart.data.labels = entries.map(e => e[0]);
    histogramChart.data.datasets[0].data = entries.map(e => e[1]);
    histogramChart.update();

    // Update Protocol Table
    const BLOCKED_APPS = new Set(['YouTube', 'TikTok']); // Example policy
    const tbody = $('protoTableBody');
    if (entries.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="loading-msg">No data</td></tr>';
    } else {
        tbody.innerHTML = entries.map(([app, count]) => {
            const pct = (count / total * 100).toFixed(1);
            const blocked = BLOCKED_APPS.has(app);
            const color = APP_COLORS[app] || '#cbd5e1';
            const pill = blocked 
                ? '<span class="status-pill status-blocked">BLOCKED</span>'
                : '<span class="status-pill status-allowed">ALLOWED</span>';
            
            return `<tr>
                <td style="color:var(--text-primary); font-weight:500;">${app}</td>
                <td style="font-family:var(--font-mono)">${fmt(count)}</td>
                <td>${pct}%</td>
                <td>${pill}</td>
            </tr>`;
        }).join('');
    }

    // Update SNI List
    const snis = stats.detected_snis || [];
    $('sniCount').textContent = snis.length + ' domains';
    const sniContainer = $('sniList');
    if (snis.length === 0) {
        sniContainer.innerHTML = '<div class="loading-msg">No domains detected</div>';
    } else {
        sniContainer.innerHTML = snis.map(sni => `
            <div class="list-item">
                <div class="list-item-main" title="${sni}">${sni}</div>
                <div class="list-item-sub">TLS SNI</div>
            </div>
        `).join('');
    }

    // ---- Anomaly Detection ----
    const totalAnomalies = stats.total_anomalies || 0;
    $('anomalyCount').textContent = fmt(totalAnomalies);

    // Footer: show dominant anomaly type
    const breakdown = stats.anomaly_breakdown || {};
    const breakdownEntries = Object.entries(breakdown).sort((a, b) => b[1] - a[1]);
    if (breakdownEntries.length > 0) {
        const [topType, topCount] = breakdownEntries[0];
        $('anomalyType').textContent = topType.replace(/_/g, ' ').toLowerCase() + ' (' + topCount + ' hits)';
    } else {
        $('anomalyType').textContent = 'no anomalies';
    }

    // Badge
    $('anomalyBadge').textContent = totalAnomalies + ' anomal' + (totalAnomalies === 1 ? 'y' : 'ies');

    // Anomaly Table
    const anomalies = stats.top_anomalies || [];
    const anomalyTbody = $('anomalyTableBody');
    if (anomalies.length === 0) {
        anomalyTbody.innerHTML = '<tr><td colspan="6" class="loading-msg">No anomalies detected</td></tr>';
    } else {
        anomalyTbody.innerHTML = anomalies.map(a => {
            const scorePct = (a.score * 100).toFixed(0) + '%';
            const typeLabel = a.type.replace(/_/g, ' ');
            const sniDisplay = a.sni || '—';
            return `<tr>
                <td style="font-family:var(--font-mono);color:var(--text-primary)">${a.src}</td>
                <td style="font-family:var(--font-mono);color:var(--text-primary)">${a.dst}</td>
                <td><span class="anomaly-score">${scorePct}</span></td>
                <td><span class="status-pill status-anomaly">${typeLabel}</span></td>
                <td style="font-family:var(--font-mono)">${sniDisplay}</td>
                <td style="font-family:var(--font-mono)">${fmt(a.pkts)}</td>
            </tr>`;
        }).join('');
    }

    // Update Thread Stats (Mock LB/FP distribution for visual)
    const threadPanel = $('threadStats');
    const fwd = stats.forwarded || 0, drp = stats.dropped || 0;
    const dispatched = fwd + drp;
    threadPanel.innerHTML = `
        <div style="font-size:11px;color:var(--text-muted);margin-bottom:8px;text-transform:uppercase;">Load Balancers</div>
        <div class="list-item"><div class="list-item-main">LB 0</div><div class="list-item-sub">${fmt(Math.floor(dispatched * 0.55))} pkts</div></div>
        <div class="list-item"><div class="list-item-main">LB 1</div><div class="list-item-sub">${fmt(Math.floor(dispatched * 0.45))} pkts</div></div>
        
        <div style="font-size:11px;color:var(--text-muted);margin:12px 0 8px;text-transform:uppercase;">Fast Paths</div>
        <div class="list-item"><div class="list-item-main">FP 0</div><div class="list-item-sub">${fmt(Math.floor((stats.total_packets||0) * 0.28))} pkts</div></div>
        <div class="list-item"><div class="list-item-main">FP 1</div><div class="list-item-sub">${fmt(Math.floor((stats.total_packets||0) * 0.27))} pkts</div></div>
        <div class="list-item"><div class="list-item-main">FP 2</div><div class="list-item-sub">${fmt(Math.floor((stats.total_packets||0) * 0.24))} pkts</div></div>
        <div class="list-item"><div class="list-item-main">FP 3</div><div class="list-item-sub">${fmt(Math.floor((stats.total_packets||0) * 0.21))} pkts</div></div>
    `;
}

// ---- Main Loop --------------------------------------------------------------
async function refresh() {
    const stats = await fetchStats();
    updateDashboard(stats);
}

window.addEventListener('load', () => {
    initCharts();
    refresh();
    setInterval(refresh, REFRESH_MS);
});
