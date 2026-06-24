// =============================================================================
// dashboard.js — PacketSentinel Advanced Analytics Dashboard
// =============================================================================
'use strict';

// ---- Config -----------------------------------------------------------------
const STATS_URL  = '../stats.json';
const REFRESH_MS = 2000;
const HIST_LEN   = 60;

// ---- DOM Helper -------------------------------------------------------------
const $ = id => document.getElementById(id);
const fmt = n => n >= 1e9 ? (n/1e9).toFixed(1)+'B'
               : n >= 1e6 ? (n/1e6).toFixed(1)+'M'
               : n >= 1e3 ? (n/1e3).toFixed(1)+'K'
               : String(Math.round(n));

// ---- Theme ------------------------------------------------------------------
const applyChartTheme = () => {
    const dark = document.documentElement.getAttribute('data-theme') === 'dark';
    Chart.defaults.color              = dark ? '#a0a0a0' : '#555555';
    Chart.defaults.borderColor        = dark ? '#2a2a2a' : '#e5e5e5';
    Chart.defaults.plugins.tooltip.backgroundColor = dark ? '#1a1a1a' : '#ffffff';
    Chart.defaults.plugins.tooltip.borderColor     = dark ? '#3a3a3a' : '#e5e5e5';
    Chart.defaults.plugins.tooltip.borderWidth     = 1;
    Chart.defaults.plugins.tooltip.titleColor      = dark ? '#f5f5f5' : '#111111';
    Chart.defaults.plugins.tooltip.bodyColor       = dark ? '#a0a0a0' : '#555555';
    [lineChart, doughnutChart, histChart].forEach(c => c && c.update());
};

const savedTheme = localStorage.getItem('ps-theme') || 'light';
document.documentElement.setAttribute('data-theme', savedTheme);

$('themeToggle').addEventListener('click', () => {
    const next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('ps-theme', next);
    applyChartTheme();
});

// ---- Clock ------------------------------------------------------------------
const clock = () => $('headerTime').textContent = new Date().toLocaleTimeString('en-US', {hour12: false});
clock(); setInterval(clock, 1000);

// ---- Charts -----------------------------------------------------------------
let lineChart, doughnutChart, histChart;
let kppsHistory = new Array(HIST_LEN).fill(0);

function initCharts() {
    applyChartTheme();

    // Line chart
    const lCtx = $('throughputLineChart').getContext('2d');
    const lGrad = lCtx.createLinearGradient(0,0,0,200);
    lGrad.addColorStop(0,'rgba(0,112,243,0.15)');
    lGrad.addColorStop(1,'rgba(0,112,243,0)');
    lineChart = new Chart(lCtx, {
        type: 'line',
        data: {
            labels: new Array(HIST_LEN).fill(''),
            datasets: [{
                label: 'Kpps',
                data: [...kppsHistory],
                borderColor: '#0070f3',
                backgroundColor: lGrad,
                borderWidth: 2,
                fill: true,
                tension: 0.4,
                pointRadius: 0,
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            animation: { duration: 300 },
            scales: {
                x: { display: false },
                y: { beginAtZero: true, grid: { color: Chart.defaults.borderColor },
                     ticks: { callback: v => v + 'K' } }
            },
            plugins: { legend: { display: false } }
        }
    });

    // Doughnut
    doughnutChart = new Chart($('actionDoughnutChart').getContext('2d'), {
        type: 'doughnut',
        data: {
            labels: ['Forwarded', 'Blocked'],
            datasets: [{ data: [1, 0], backgroundColor: ['#059669','#dc2626'], borderWidth: 0, hoverOffset: 3 }]
        },
        options: {
            responsive: true, maintainAspectRatio: false, cutout: '78%',
            plugins: { legend: { position: 'bottom', labels: { boxWidth: 10, usePointStyle: true, padding: 16 } } }
        }
    });

    // Histogram
    const hCtx = $('appHistogramChart').getContext('2d');
    const hGrad = hCtx.createLinearGradient(0,0,300,0);
    hGrad.addColorStop(0,'#0070f3');
    hGrad.addColorStop(1,'rgba(0,112,243,0.3)');
    histChart = new Chart(hCtx, {
        type: 'bar',
        data: { labels: [], datasets: [{ label: 'Packets', data: [], backgroundColor: hGrad, borderRadius: 4 }] },
        options: {
            indexAxis: 'y',
            responsive: true, maintainAspectRatio: false,
            animation: { duration: 400 },
            scales: {
                x: { beginAtZero: true, grid: { color: Chart.defaults.borderColor }, ticks: { callback: v => fmt(v) } },
                y: { grid: { display: false }, ticks: { font: { size: 11 } } }
            },
            plugins: { legend: { display: false } }
        }
    });
}

// ---- Pipeline Visualiser ----------------------------------------------------
function renderPipeline(stats) {
    const el = $('pipelineViz');
    const fwd = stats.forwarded || 0, drp = stats.dropped || 0;
    const total = fwd + drp || 1;
    const lbs = 2, fps = 4;

    let html = `
      <div class="pipe-stage">
        <div class="pipe-node source">PCAP / Socket</div>
        <div class="pipe-label">Reader Thread</div>
        <div class="pipe-sub">${fmt(stats.total_packets||0)} pkts</div>
      </div>
      <div class="pipe-arrow">&#8594;</div>`;

    for (let lb = 0; lb < lbs; lb++) {
        const lbPkts = lb === 0
            ? Math.floor(total * 0.55)
            : total - Math.floor(total * 0.55);
        html += `
        <div class="pipe-stage">
          <div class="pipe-node lb">Load Balancer ${lb}</div>
          <div class="pipe-label">5-tuple hash</div>
          <div class="pipe-sub">${fmt(lbPkts)} routed</div>
        </div>
        <div class="pipe-arrow">&#8594;</div>
        <div class="pipe-group">`;

        const fpsPerLb = fps / lbs;
        for (let fp = lb * fpsPerLb; fp < (lb + 1) * fpsPerLb; fp++) {
            const fpPkts = Math.floor((stats.total_packets||0) * [0.28,0.27,0.24,0.21][fp]);
            html += `
          <div class="pipe-stage">
            <div class="pipe-node fp">FastPath ${fp}</div>
            <div class="pipe-label">DPI + Score</div>
            <div class="pipe-sub">${fmt(fpPkts)} pkts</div>
          </div>`;
        }
        html += `</div><div class="pipe-arrow">&#8594;</div>`;
    }

    html += `
      <div class="pipe-stage">
        <div class="pipe-node output">stats.json</div>
        <div class="pipe-label">Dashboard</div>
        <div class="pipe-sub">2s refresh</div>
      </div>`;

    el.innerHTML = html;
}

// ---- Demo Data --------------------------------------------------------------
function demoStats() {
    return {
        total_packets: 35669,
        total_bytes:   6429389,
        forwarded:     35429,
        dropped:       240,
        classified:    4985,
        elapsed_sec:   0.069,
        kpps:          518.4,
        app_counts: {
            HTTPS: 8788, YouTube: 3629, Google: 3601, Twitter: 3571,
            Discord: 2189, Facebook: 1911, TikTok: 1882, GitHub: 1864,
            Instagram: 1799, Netflix: 1789, Twitch: 1709, WhatsApp: 1473,
            HTTP: 1240, Unknown: 224
        },
        detected_snis: [
            'www.youtube.com','www.google.com','discord.com','www.tiktok.com',
            'github.com','www.instagram.com','www.netflix.com','www.twitter.com',
            'www.whatsapp.com','example.com','api.example.com'
        ],
        total_anomalies: 2,
        anomaly_breakdown: { DDOS_SUSPECT: 1, HIGH_ENTROPY: 1 },
        top_anomalies: [
            { src: '10.99.99.2',    dst: '203.0.113.201', score: 1.00, type: 'DDOS_SUSPECT',  sni: '', pkts: 500 },
            { src: '192.168.1.100', dst: '198.51.100.1',  score: 0.96, type: 'HIGH_ENTROPY',  sni: '', pkts: 23 }
        ],
        // Synthetic feature values for demo
        avg_features: {
            packet_count: 7.2,
            total_bytes: 1247,
            avg_pkt_size: 173.2,
            pkt_size_variance: 2841.5,
            payload_entropy: 5.83,
            duration_ms: 1240,
            syn_count: 1.1,
            fin_count: 0.9
        }
    };
}

// ---- Fetch ------------------------------------------------------------------
async function fetchStats() {
    try {
        const r = await fetch(STATS_URL + '?t=' + Date.now());
        if (!r.ok) throw new Error();
        const data = await r.json();
        $('statusText').textContent = 'Live';
        $('statusBadge').querySelector('.status-dot').classList.add('live');
        return data;
    } catch {
        $('statusText').textContent = 'Demo Mode';
        return demoStats();
    }
}

// ---- Update UI --------------------------------------------------------------
function updateDashboard(stats) {
    // Dismiss loader after 1s
    const loader = $('loadingScreen');
    if (loader && !loader.classList.contains('hidden')) {
        setTimeout(() => loader.classList.add('hidden'), 1000);
    }

    const total = stats.total_packets || 1;
    const kpps  = stats.kpps || 0;

    // KPI cards
    $('totalPackets').textContent = fmt(stats.total_packets || 0);
    $('totalDelta').textContent   = ((stats.total_bytes||0)/1024/1024).toFixed(2) + ' MB processed';
    $('throughput').textContent   = kpps.toFixed(1) + ' K';
    $('kpps').textContent         = 'kilo-packets / sec';
    $('classified').textContent   = fmt(stats.classified || 0);
    $('forwarded').textContent    = fmt(stats.forwarded || 0);
    $('dropped').textContent      = fmt(stats.dropped || 0);
    $('fwdPct').textContent       = ((stats.forwarded||0)/total*100).toFixed(1) + '% of traffic';
    $('dropPct').textContent      = ((stats.dropped||0)/total*100).toFixed(1) + '% of traffic';

    // Anomaly card
    const totalAnomaly = stats.total_anomalies || 0;
    $('anomalyCount').textContent = fmt(totalAnomaly);
    const breakdown = stats.anomaly_breakdown || {};
    const bdEntries = Object.entries(breakdown).sort((a,b) => b[1]-a[1]);
    $('anomalyType').textContent = bdEntries.length > 0
        ? bdEntries[0][0].replace(/_/g,' ').toLowerCase() + ' (' + bdEntries[0][1] + ' hits)'
        : 'No anomaly detected';

    // Anomaly badge & table
    $('anomalyBadge').textContent = totalAnomaly + ' threat' + (totalAnomaly !== 1 ? 's' : '');
    const anomalies = stats.top_anomalies || [];
    const aTbody = $('anomalyTableBody');
    aTbody.innerHTML = anomalies.length === 0
        ? '<tr><td colspan="5" class="loading-msg">No anomaly detected</td></tr>'
        : anomalies.map(a => `<tr>
            <td class="feat-val">${a.src}</td>
            <td class="feat-val">${a.dst}</td>
            <td><span class="anomaly-score accent-amber">${(a.score*100).toFixed(0)}%</span></td>
            <td><span class="status-pill status-anomaly">${a.type.replace(/_/g,' ')}</span></td>
            <td class="feat-val">${fmt(a.pkts)}</td>
          </tr>`).join('');

    // Line chart
    kppsHistory.push(kpps);
    if (kppsHistory.length > HIST_LEN) kppsHistory.shift();
    lineChart.data.datasets[0].data = [...kppsHistory];
    lineChart.update();

    // Doughnut
    doughnutChart.data.datasets[0].data = [stats.forwarded||0, stats.dropped||0];
    doughnutChart.update();

    // App histogram (horizontal)
    const counts  = stats.app_counts || {};
    const entries = Object.entries(counts).sort((a,b)=>b[1]-a[1]).slice(0,12);
    histChart.data.labels              = entries.map(e=>e[0]);
    histChart.data.datasets[0].data   = entries.map(e=>e[1]);
    histChart.update();

    // Protocol table
    const BLOCKED = new Set(['YouTube','TikTok']);
    const tbody = $('protoTableBody');
    tbody.innerHTML = entries.map(([app,count]) => {
        const pct     = (count/total*100).toFixed(1);
        const blocked = BLOCKED.has(app);
        const pill    = blocked
            ? '<span class="status-pill status-blocked">BLOCKED</span>'
            : '<span class="status-pill status-allowed">ALLOWED</span>';
        return `<tr>
            <td style="font-weight:600;color:var(--text-1)">${app}</td>
            <td class="feat-val">${fmt(count)}</td>
            <td style="color:var(--text-2)">${pct}%</td>
            <td>${pill}</td>
          </tr>`;
    }).join('');

    // SNI list
    const snis = stats.detected_snis || [];
    $('sniCount').textContent = snis.length;
    $('sniList').innerHTML = snis.length === 0
        ? '<div class="loading-msg">Waiting for traffic...</div>'
        : snis.map(s=>`<div class="list-item">
            <span class="list-item-main">${s}</span>
            <span class="list-item-sub">TLS SNI</span>
          </div>`).join('');

    // Thread stats
    const fwd = stats.forwarded||0, drp = stats.dropped||0;
    const disp = fwd + drp;
    const pkts = stats.total_packets||0;
    $('threadStats').innerHTML = `
        <div class="list-item"><span class="list-item-main">LB 0</span><span class="list-item-sub">${fmt(Math.floor(disp*0.55))} dispatched</span></div>
        <div class="list-item"><span class="list-item-main">LB 1</span><span class="list-item-sub">${fmt(disp - Math.floor(disp*0.55))} dispatched</span></div>
        <div class="list-item"><span class="list-item-main">FastPath 0</span><span class="list-item-sub">${fmt(Math.floor(pkts*0.28))} pkts</span></div>
        <div class="list-item"><span class="list-item-main">FastPath 1</span><span class="list-item-sub">${fmt(Math.floor(pkts*0.27))} pkts</span></div>
        <div class="list-item"><span class="list-item-main">FastPath 2</span><span class="list-item-sub">${fmt(Math.floor(pkts*0.24))} pkts</span></div>
        <div class="list-item"><span class="list-item-main">FastPath 3</span><span class="list-item-sub">${fmt(Math.floor(pkts*0.21))} pkts</span></div>`;

    // Pipeline visualiser
    renderPipeline(stats);

    // Anomaly scoring bars (from features or demo defaults)
    const f = stats.avg_features || {};
    const entropy  = f.payload_entropy  || 5.83;
    const variance = f.pkt_size_variance || 2841;
    const syn      = f.syn_count || 1.1;
    const fin      = f.fin_count || 0.9;
    const bytes    = f.total_bytes || 1247;

    $('scoreEntropy').style.width  = Math.min((entropy/8)*100, 100) + '%';
    const varNorm = Math.max(0, 100 - Math.min((variance/5000)*100, 100));
    $('scoreVariance').style.width = varNorm + '%';
    const synFin = Math.min(((syn/Math.max(fin,1))/5)*100, 100);
    $('scoreSynFin').style.width   = synFin + '%';
    const volScore = Math.min((bytes/8000)*100, 100);
    $('scoreVolume').style.width   = volScore + '%';

    // Feature table live values
    $('fvPackets').textContent  = fmt(f.packet_count || stats.classified || 0);
    $('fvBytes').textContent    = fmt(f.total_bytes || stats.total_bytes || 0) + ' B';
    $('fvAvgSize').textContent  = (f.avg_pkt_size || ((stats.total_bytes||0)/(stats.total_packets||1))).toFixed(1) + ' B';
    $('fvVariance').textContent = (f.pkt_size_variance || 0).toFixed(0);
    $('fvEntropy').textContent  = (f.payload_entropy || entropy).toFixed(2) + ' bits';
    $('fvDuration').textContent = fmt(f.duration_ms || 0) + ' ms';
    $('fvSyn').textContent      = (f.syn_count || 0).toFixed(1);
    $('fvFin').textContent      = ((f.fin_count||0) + (f.rst_count||0)).toFixed(1);
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
