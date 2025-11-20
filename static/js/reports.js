// Reports page charts logic (reusing dashboard chart functions)
(function(){
  // Global date range state
  let currentDateRange = 'weekly';
  let customStartDate = null;
  let customEndDate = null;
  
  // Chart instances
  let alertsChartInstance = null;
  let riskTrendChartInstance = null;
  let severityTrendChartInstance = null;

  function loadChartJs(cb){
    if (window.Chart) return cb();
    const s = document.createElement('script');
    s.src = 'https://cdn.jsdelivr.net/npm/chart.js';
    s.onload = cb;
    document.head.appendChild(s);
  }

  function init(){
    initTabs();
    setupDateRangeFilter();
    leaksChart();
    alertsChart();
    riskChart();
    riskTrendChart();
    severityTrendChart();
    setupTopAssetsToggle();
    topAssetsChart();
    alertResponseChart();
    leakStatusChart();
    attendedLeaksList();
  }

  // Date Range Filter Setup
  function setupDateRangeFilter(){
    const dateRangeBtns = document.querySelectorAll('.date-range-btn');
    const customDateDiv = document.getElementById('customDateRange');
    const applyBtn = document.getElementById('applyCustomRange');
    
    dateRangeBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        const range = btn.dataset.range;
        
        // Update button styles
        dateRangeBtns.forEach(b => {
          b.style.background = '#333';
          b.style.borderColor = '#555';
          b.classList.remove('active');
        });
        btn.style.background = '#4A90E2';
        btn.style.borderColor = '#4A90E2';
        btn.classList.add('active');
        
        if(range === 'custom'){
          customDateDiv.style.display = 'flex';
        } else {
          customDateDiv.style.display = 'none';
          currentDateRange = range;
          customStartDate = null;
          customEndDate = null;
          refreshTimeBasedCharts();
        }
      });
    });
    
    if(applyBtn){
      applyBtn.addEventListener('click', () => {
        const start = document.getElementById('customStartDate').value;
        const end = document.getElementById('customEndDate').value;
        
        if(start && end){
          customStartDate = start;
          customEndDate = end;
          currentDateRange = 'custom';
          refreshTimeBasedCharts();
        } else {
          alert('Please select both start and end dates');
        }
      });
    }
  }

  function refreshTimeBasedCharts(){
    alertsChart();
    riskTrendChart();
    severityTrendChart();
  }

  function getDateRangeParams(){
    if(currentDateRange === 'custom' && customStartDate && customEndDate){
      return `range=custom&start=${customStartDate}&end=${customEndDate}`;
    }
    return `range=${currentDateRange}`;
  }

  function getDateRangeDisplay(){
    if(currentDateRange === 'custom' && customStartDate && customEndDate){
      return `Custom: ${customStartDate} to ${customEndDate}`;
    }
    return currentDateRange.charAt(0).toUpperCase() + currentDateRange.slice(1);
  }

  // Tab switching
  function initTabs() {
    const tabButtons = document.querySelectorAll('.tab-button');
    const tabContents = document.querySelectorAll('.tab-content');
    
    tabButtons.forEach(button => {
      button.addEventListener('click', () => {
        // Remove active class from all
        tabButtons.forEach(btn => btn.classList.remove('active'));
        tabContents.forEach(content => content.classList.remove('active'));
        
        // Add active to clicked
        button.classList.add('active');
        const tabId = button.dataset.tab + '-tab';
        document.getElementById(tabId)?.classList.add('active');
      });
    });
  }

  // Maintain chart instance so we can destroy before re-creating
  let topAssetsChartInstance = null;
  let topAssetsMode = 'type'; // 'type' or 'asset'

  function setupTopAssetsToggle(){
    const btnType = document.getElementById('topAssetsToggleType');
    const btnAsset = document.getElementById('topAssetsToggleAsset');
    if(!btnType || !btnAsset) return;
    btnType.addEventListener('click', ()=>{
      topAssetsMode = 'type';
      btnType.style.background = '#333'; btnType.style.color='#fff';
      btnAsset.style.background = 'transparent'; btnAsset.style.color='#ddd';
      topAssetsChart();
    });
    btnAsset.addEventListener('click', ()=>{
      topAssetsMode = 'asset';
      btnAsset.style.background = '#333'; btnAsset.style.color='#fff';
      btnType.style.background = 'transparent'; btnType.style.color='#ddd';
      topAssetsChart();
    });
  }

  // Format a date string or ISO timestamp to MM-DD-YY (e.g. 11-05-25)
  function formatDateLabel(dateStr){
    if(!dateStr) return '';
    // Try parsing as a Date first
    const d = new Date(dateStr);
    if(!isNaN(d.getTime())){
      const mm = String(d.getMonth()+1).padStart(2,'0');
      const dd = String(d.getDate()).padStart(2,'0');
      const yy = String(d.getFullYear()).slice(-2);
      return `${mm}-${dd}-${yy}`;
    }
    // Fallback for simple YYYY-MM-DD strings
    const m = String(dateStr).match(/(\d{4})-(\d{2})-(\d{2})/);
    if(m){ return `${m[2]}-${m[3]}-${m[1].slice(-2)}`; }
    return String(dateStr);
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
    const dateInfo=document.getElementById('alertsDateInfo');
    if(!msg) return;
    msg.textContent='Loading alerts data...';
    if(dateInfo) dateInfo.textContent = `Range: ${getDateRangeDisplay()}`;
    try {
      const params = getDateRangeParams();
      const alerts = await fetchJson(`/api/alerts?limit=100&${params}`);
      if(!alerts.length){ msg.textContent='No alerts data available.'; return; }
      const dateCounts = {};
      alerts.forEach(a => {
        const raw = (a.date || a.timestamp || '');
        const d = String(raw).slice(0,10);
        if(d) dateCounts[d] = (dateCounts[d] || 0) + 1;
      });
      // Sort dates ascending
      const dates = Object.keys(dateCounts).sort();
      const labels = dates.map(formatDateLabel);
      const data = dates.map(d => dateCounts[d]);
      msg.textContent = '';
      
      // Destroy existing chart instance
      if(alertsChartInstance){ 
        try{ alertsChartInstance.destroy(); }catch(e){} 
        alertsChartInstance = null;
      }
      
      alertsChartInstance = new Chart(document.getElementById('alertsChart'), {
        type: 'line',
        data: {
          labels: labels,
          datasets: [{
            label: 'Critical Alerts Over Time',
            data: data,
            borderColor: 'rgba(255,99,132,.85)',
            backgroundColor: 'rgba(255,99,132,.25)',
            tension: .3,
            fill: true,
            pointRadius: 3
          }]
        },
        options: { responsive: true }
      });
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

  async function riskTrendChart(){
    const msg = document.getElementById('riskTrendMsg');
    const dateInfo = document.getElementById('riskTrendDateInfo');
    if(!msg) return;
    msg.textContent = 'Loading risk trend...';
    if(dateInfo) dateInfo.textContent = `Range: ${getDateRangeDisplay()}`;
    try {
      const params = getDateRangeParams();
      const series = await fetchJson(`/api/risk/time_series?${params}`);
      if(!Array.isArray(series) || !series.length){ msg.textContent='No time series data available.'; return; }
      const labels = series.map(s => formatDateLabel(s.date));
      const data = series.map(s => s.score);
      msg.textContent = '';
      
      // Destroy existing chart instance
      if(riskTrendChartInstance){ 
        try{ riskTrendChartInstance.destroy(); }catch(e){} 
        riskTrendChartInstance = null;
      }
      
      riskTrendChartInstance = new Chart(document.getElementById('riskTrendChart'), {
        type: 'line',
        data: {
          labels: labels,
          datasets: [{
            label: 'Overall Risk Score',
            data: data,
            borderColor: 'rgba(255,159,64,0.9)',
            backgroundColor: 'rgba(255,159,64,0.18)',
            tension: 0.25,
            fill: true,
            pointRadius: 2
          }]
        },
        options: {
          responsive: true,
          plugins: { legend: { display: false } },
          scales: {
            x: { display: true, ticks: { maxRotation: 0, autoSkip: true, maxTicksLimit: 10 } },
            y: { display: true, beginAtZero: true }
          }
        }
      });
    } catch(e){ msg.textContent='Error loading risk trend.'; }
  }

  async function severityTrendChart(){
    const msg = document.getElementById('severityTrendMsg');
    const dateInfo = document.getElementById('severityTrendDateInfo');
    if(!msg) return;
    msg.textContent = 'Loading severity time series...';
    if(dateInfo) dateInfo.textContent = `Range: ${getDateRangeDisplay()}`;
    try {
      const params = getDateRangeParams();
      const series = await fetchJson(`/api/risk/severity_time_series?${params}`);
      if(!Array.isArray(series) || !series.length){ msg.textContent='No severity time series data available.'; return; }

      const dates = series.map(s => s.date);
      const labels = dates.map(formatDateLabel);

      // Severities in stacking order
      const keys = ['critical','high','medium','low','unknown'];
      const colors = {
        critical: 'rgba(255,99,132,0.85)',
        high: 'rgba(255,140,0,0.85)',
        medium: 'rgba(255,206,86,0.85)',
        low: 'rgba(75,192,192,0.85)',
        unknown: 'rgba(153,102,255,0.85)'
      };

      const datasets = keys.map(k => ({
        label: k.charAt(0).toUpperCase() + k.slice(1),
        data: series.map(s => Number(s[k] || 0)),
        borderColor: colors[k],
        backgroundColor: colors[k].replace(/0\.85\)/, '0.25)'),
        tension: 0.3,
        fill: true
      }));

      msg.textContent = '';
      
      // Destroy existing chart instance
      if(severityTrendChartInstance){ 
        try{ severityTrendChartInstance.destroy(); }catch(e){} 
        severityTrendChartInstance = null;
      }
      
      severityTrendChartInstance = new Chart(document.getElementById('severityTrendChart'), {
        type: 'line',
        data: { labels, datasets },
        options: {
          responsive: true,
          plugins: { legend: { position: 'bottom' } },
          scales: {
            x: { stacked: true },
            y: { stacked: true, beginAtZero: true }
          }
        }
      });
    } catch (e){
      msg.textContent = 'Error loading severity time series.';
    }
  }

  async function topAssetsChart(){
    const msg = document.getElementById('topAssetsMsg');
    if(!msg) return;
    msg.textContent = 'Loading top assets...';
    try {
      const assets = await fetchJson('/api/risk/top_assets?limit=10');
      if(!Array.isArray(assets) || !assets.length){ msg.textContent='No asset risk data available.'; return; }
      msg.textContent = '';
      // Destroy previous instance if present
      if(topAssetsChartInstance){ try{ topAssetsChartInstance.destroy(); }catch(e){} topAssetsChartInstance=null; }

      if(topAssetsMode === 'type'){
        // Aggregate by asset type (count of leaks per type)
        const typeCounts = {};
        assets.forEach(a => {
          const t = (a.type || 'unknown');
          typeCounts[t] = (typeCounts[t] || 0) + (Number(a.leak_count || 0));
        });
        // Sort types by count desc
        const sorted = Object.entries(typeCounts).sort((a,b) => b[1] - a[1]);
        const labels = sorted.map(([t]) => t);
        const data = sorted.map(([t,c]) => c);
        topAssetsChartInstance = new Chart(document.getElementById('topAssetsChart'), {
          type: 'bar',
          data: { labels: labels, datasets: [{ label: 'Leak Count by Asset Type', data: data, backgroundColor: 'rgba(167,0,29,0.85)' }] },
          options: { indexAxis: 'y', responsive: true, scales: { x: { beginAtZero: true } }, plugins: { legend: { display: false } } }
        });
      } else {
        // By asset: show top individual assets (value may be hashed for sensitive types)
        const labels = assets.map(a => `${a.type}:${a.value}`);
        const data = assets.map(a => Number(a.leak_count || 0));
        topAssetsChartInstance = new Chart(document.getElementById('topAssetsChart'), {
          type: 'bar',
          data: { labels: labels, datasets: [{ label: 'Leak Count by Asset', data: data, backgroundColor: 'rgba(167,0,29,0.85)' }] },
          options: { indexAxis: 'y', responsive: true, scales: { x: { beginAtZero: true } }, plugins: { legend: { display: false } } }
        });
      }
    } catch (e){ msg.textContent='Error loading top assets.'; }
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
