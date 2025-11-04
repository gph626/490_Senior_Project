// Dashboard charts logic
(function(){
  function loadChartJs(cb){
    if (window.Chart) return cb();
    const s = document.createElement('script');
    s.src = 'https://cdn.jsdelivr.net/npm/chart.js';
    s.onload = cb;
    document.head.appendChild(s);
  }

  function init(){
    leaksChart();
    alertsChart();
    riskChart();
    loadCrawlRuns();
  }

  async function fetchJson(url){
    const res = await fetch(url);
    if(!res.ok) throw new Error('HTTP '+res.status);
    return res.json();
  }


  async function leaksChart(){
    const msg = document.getElementById('leaksChartMsg');
    if(!msg) return;
    msg.textContent = 'Loading leaks data...';
    try {
      const leaks = await fetchJson('/api/leaks?limit=100');
      if(!leaks.length){ msg.textContent='No leaks data available.'; return; }
      const sources={}; leaks.forEach(l=>{ const s=l.source||l.crawler||'Unknown'; sources[s]=(sources[s]||0)+1; });
      msg.textContent='';
      new Chart(document.getElementById('leaksChart'), { type:'bar', data:{ labels:Object.keys(sources), datasets:[{ label:'Leaks per Crawler', data:Object.values(sources), backgroundColor:'#a7001d', borderRadius:4 }] }, options:{ responsive:true }} );
    } catch(e){ msg.textContent='Error loading leaks data.'; }
  }

  async function alertsChart(){
    const msg=document.getElementById('alertsChartMsg');
    if(!msg) return;
    msg.textContent='Loading alerts data...';
    try {
      const alerts = await fetchJson('/api/alerts?limit=100');
      if(!alerts.length){ msg.textContent='No alerts data available.'; return; }
      const dateCounts={}; alerts.forEach(a=>{ const d=(a.date||a.timestamp||'').slice(0,10); if(d) dateCounts[d]=(dateCounts[d]||0)+1; });
      msg.textContent='';
      new Chart(document.getElementById('alertsChart'), { type:'line', data:{ labels:Object.keys(dateCounts), datasets:[{ label:'Critical Alerts Over Time', data:Object.values(dateCounts), borderColor:'rgba(255,99,132,.85)', backgroundColor:'rgba(255,99,132,.25)', tension:.3, fill:true, pointRadius:3 }] }, options:{ responsive:true }} );
    } catch(e){ msg.textContent='Error loading alerts data.'; }
  }

  async function riskChart(){
    const msg=document.getElementById('riskChartMsg');
    if(!msg) return;
    msg.textContent='Loading risk summary...';
    try {
      const summary = await fetchJson('/api/risk/summary');
      // Expect summary to have severity_counts and maybe other fields
      const sev = summary.severity_counts || summary; // fallback to legacy shape
      const order = ['critical','high','medium','low','zero severity','unknown'];
      const labels = order.filter(k => sev[k] !== undefined);
      const data = labels.map(l => sev[l]);
      if(!labels.length){ msg.textContent='No risk summary data available.'; return; }
      msg.textContent='';
      // Align colors with severity meaning (critical -> red, high -> orange, medium -> yellow, low -> teal, zero severity -> gray, unknown -> purple)
      const colorMap = {
        critical: 'rgba(255,99,132,.65)',
        high: 'rgba(255,140,0,.65)',
        medium: 'rgba(255,206,86,.65)',
        low: 'rgba(75,192,192,.65)',
        'zero severity': 'rgba(160,160,160,.65)',
        unknown: 'rgba(153,102,255,.65)'
      };
      const backgroundColor = labels.map(l => colorMap[l] || 'rgba(120,120,120,.5)');
      new Chart(document.getElementById('riskChart'), { type:'pie', data:{ labels, datasets:[{ data, backgroundColor }] }, options:{ responsive:true, plugins:{ legend:{ position:'bottom' }}} });
    } catch(e){ msg.textContent='Error loading risk summary.'; }
  }

  async function loadCrawlRuns() {
    const msg = document.getElementById('crawlRunsMsg');
    const tableBody = document.querySelector('#crawlRunsTable tbody');
    if (!msg || !tableBody) return; // Section not on this page

    msg.textContent = 'Loading crawl runs...';
    tableBody.innerHTML = '';

    try {
      const runs = await fetchJson('/api/crawl_runs');
      if (!runs.length) {
        msg.textContent = 'No crawl runs yet.';
        return;
      }

      msg.textContent = '';
      runs.forEach(run => {
        const tr = document.createElement('tr');

        const finished = run.finished_at
          ? new Date(run.finished_at).toLocaleString()
          : '-';

        tr.innerHTML = `
          <td>${run.id}</td>
          <td>${run.source}</td>
          <td>${run.status}</td>
          <td>${new Date(run.started_at).toLocaleString()}</td>
          <td>${finished}</td>
        `;
        tableBody.appendChild(tr);
      });
    } catch (e) {
      msg.textContent = 'Error loading crawl runs.';
    }
  }


  document.addEventListener('DOMContentLoaded',()=>{
    loadChartJs(()=>{
      if(window.Chart){
        Chart.defaults.color='#FFFFFF';
        Chart.defaults.font.family='Montserrat, Arial, sans-serif';
        Chart.defaults.plugins.legend.labels.color='#FFFFFF';
        Chart.defaults.plugins.tooltip.titleColor='#FFFFFF';
        Chart.defaults.plugins.tooltip.bodyColor='#FFFFFF';
        Chart.defaults.plugins.tooltip.backgroundColor='rgba(0,0,0,0.75)';
        Chart.defaults.borderColor='rgba(255,255,255,0.15)';
      }
      init();
    });
  });
})();
