// Alerts page logic
(function(){
  async function loadAlerts(){
    const status = document.getElementById('alertsStatus');
    if(!status) return;
    status.textContent = 'Loading…';
    try {
      const res = await fetch('/api/alerts?limit=100');
      const data = await res.json();
      renderAlerts(Array.isArray(data)? data: []);
      status.textContent = data.length ? data.length + ' critical alerts' : 'No critical alerts';
    } catch(e){
      status.textContent = 'Error: ' + e.message;
    }
  }

  function renderAlerts(items){
    const tbody = document.querySelector('#alertsTable tbody');
    if(!tbody) return;
    if(!items.length){
      tbody.innerHTML = '<tr><td colspan="4" class="muted">No critical alerts yet.</td></tr>';
      return;
    }
    tbody.innerHTML = items.map(a => {
      const sev = (a.severity || 'unknown').toLowerCase();
      const sevClass = sev === 'critical' ? 'critical' : '';
      const ts = a.timestamp ? new Date(a.timestamp).toLocaleString() : '';
      const ents = a.entities || {};
      const show = (arr, label) => Array.isArray(arr) && arr.length ? `<span style="margin-right:4px;" class="badge">${label}: ${arr.slice(0,3).join(', ')}${arr.length>3?'…':''}</span>`: '';
      const entHtml = show(ents.emails, 'emails') + show(ents.domains, 'domains') + show(ents.ips, 'ips');
      return `<tr>
          <td><span class="badge ${sevClass}">${a.severity}</span></td>
          <td class="nowrap">${ts}</td>
          <td>${a.source || ''}</td>
          <td><div style="font-weight:600;">${(a.title||'(no title)')}</div><div class="muted" style="font-size:12px;">${entHtml || '—'}</div></td>
      </tr>`;
    }).join('');
  }

  document.addEventListener('DOMContentLoaded', ()=>{
    document.getElementById('refreshAlerts')?.addEventListener('click', loadAlerts);
    loadAlerts();
  });
})();
