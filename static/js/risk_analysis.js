// Risk analysis page logic
(function(){
  async function loadRisk(){
    const status = document.getElementById('riskStatus');
    if(!status) return;
    status.textContent = 'Loading…';
    try {
      const res = await fetch('/api/risk/summary');
      const data = await res.json();
      renderSeverityDist(data.severity_counts || {});
      renderAssetRisk(data.assets || []);
      status.textContent = 'Indexed leaks: ' + (data.total_leaks_indexed || 0);
    } catch(e){
      status.textContent = 'Error: ' + e.message;
    }
  }

  function renderSeverityDist(counts){
    const tbody = document.querySelector('#sevDist tbody');
    if(!tbody) return;
    const order = ['critical','high','medium','low','zero severity','unknown'];
    const rows = order.filter(s => counts[s] !== undefined).map(sev => `<tr><td>${sev}</td><td>${counts[sev]}</td></tr>`).join('');
    tbody.innerHTML = rows || '<tr><td colspan="2" class="muted">No data</td></tr>';
  }

  function renderAssetRisk(list){
    const tbody = document.getElementById('asset-risk-body');
    if(!tbody) return;
    if(!list.length){
      tbody.innerHTML = '<tr><td colspan="4" class="muted">No watchlist assets yet.</td></tr>';
      return;
    }
    tbody.innerHTML = list.map(a => {
      const riskClass = a.risk === 'high' ? 'critical' : (a.risk === 'medium' ? 'high' : (a.risk === 'low' ? 'medium' : ''));
      return `<tr>
        <td>${a.type}</td>
        <td><span class="truncate" title="${a.value}">${a.value}</span></td>
        <td><span class="badge ${riskClass}">${a.risk}</span></td>
        <td>${a.leak_count}</td>
      </tr>`;
    }).join('');
  }

  document.addEventListener('DOMContentLoaded', ()=>{
    document.getElementById('refreshRisk')?.addEventListener('click', loadRisk);
    loadRisk();
  });
})();
