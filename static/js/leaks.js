// Leaks page logic
(function(){
  function renderLeaks(items){
    const tbody = document.querySelector('#leaks-table tbody');
    if (!Array.isArray(items) || items.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="muted">No leaks yet.</td></tr>';
      return;
    }
    const rows = items.map(it => {
  const sev = (it.severity || 'zero severity').toLowerCase();
      const sevClass = ['low','medium','high','critical'].includes(sev) ? sev : '';
      const title = it.title || '(no title)';
      const ts = it.timestamp ? new Date(it.timestamp).toLocaleString() : '';
      const norm = it.normalized || {};
      const ents = norm.entities || {};
      const showList = (arr, max=3) => {
        if (!Array.isArray(arr) || arr.length === 0) return '';
        const items = arr.slice(0, max);
        const more = arr.length > max ? ` <span class="muted">+${arr.length-max} more</span>` : '';
        return items.map(v => `<span class="badge" style="background:#2a2f36; color:#cfd7e6; margin-right:4px;">${v}</span>`).join('') + more;
      };
      // Labeled, compact entities summary using badges
      const labeled = [];
      if (Array.isArray(ents.emails) && ents.emails.length) labeled.push(`<span class="muted">emails:</span> ${showList(ents.emails, 2)}`);
      if (Array.isArray(ents.domains) && ents.domains.length) labeled.push(`<span class="muted">domains:</span> ${showList(ents.domains, 2)}`);
      if (Array.isArray(ents.ips) && ents.ips.length) labeled.push(`<span class="muted">ips:</span> ${showList(ents.ips, 2)}`);
      if (Array.isArray(ents.btc_wallets) && ents.btc_wallets.length) labeled.push(`<span class="muted">btc:</span> ${showList(ents.btc_wallets, 2)}`);
      const parseMaybeJson = (v) => {
        if (!v) return [];
        try { const arr = typeof v === 'string' ? JSON.parse(v) : v; return Array.isArray(arr) ? arr : []; } catch { return []; }
      };
      const ssns = parseMaybeJson(it.ssn);
      const names = parseMaybeJson(it.names);
      const phones = parseMaybeJson(it.phone_numbers);
      const addrs = parseMaybeJson(it.physical_addresses);
      const pwds = parseMaybeJson(it.passwords);
      if (ssns.length) labeled.push(`<span class="muted">ssns:</span> ${showList(ssns, 2)}`);
      if (names.length) labeled.push(`<span class="muted">names:</span> ${showList(names, 2)}`);
      if (phones.length) labeled.push(`<span class="muted">phones:</span> ${showList(phones, 2)}`);
      if (addrs.length) labeled.push(`<span class="muted">addresses:</span> ${showList(addrs, 1)}`);
      if (pwds.length) labeled.push(`<span class="muted">passwords:</span> ${showList(pwds, 1)}`);
      const entsHtml = labeled.join(' ');
      return `<tr>
                <td>${it.source || ''}</td>
                <td><span class="truncate" title="${title.replaceAll('"','&quot;')}">${title}</span></td>
                <td style="max-width:460px">${entsHtml || '<span class="muted">—</span>'}</td>
                <td><span class="badge ${sevClass}">${it.severity || 'unknown'}</span></td>
                <td class="nowrap">${ts}</td>
                <td class="nowrap"><button data-id="${it.id}" class="delLeak" style="padding:4px 8px; border:none; border-radius:6px; cursor:pointer;">Delete</button></td>
              </tr>`;
    }).join('');
    tbody.innerHTML = rows;
    // bind delete buttons
    document.querySelectorAll('.delLeak').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.getAttribute('data-id');
        try {
          const res = await fetch('/api/leaks/' + id, { method: 'DELETE', headers: { 'X-API-Key': API_KEY } });
          if (!res.ok){
            const err = await res.json().catch(()=>({}));
            alert('Delete failed: ' + (err.message || res.status));
            return;
          }
          // remove from local list and re-render
          ALL_LEAKS = (ALL_LEAKS || []).filter(x => x.id != id);
          applyAndRender();
        } catch(e){
          alert('Delete failed: ' + e.message);
        }
      });
    });
  }

  let ALL_LEAKS = [];

  function matchesFilters(item){
    const sevSel = (document.getElementById('sevFilter').value || '').toLowerCase();
    const inc = (document.getElementById('incKeys').value || '').toLowerCase().split(',').map(s => s.trim()).filter(Boolean);
    const exc = (document.getElementById('excKeys').value || '').toLowerCase().split(',').map(s => s.trim()).filter(Boolean);
    const wantEmails = document.getElementById('entEmails').checked;
    const wantDomains = document.getElementById('entDomains').checked;
    const wantIPs = document.getElementById('entIPs').checked;
    const wantBTC = document.getElementById('entBTC').checked;
    // Add new filters for ssn, passwords, names, phone, address
    // (Add checkboxes in the UI if needed)
    const title = (item.title || '').toLowerCase();
    const content = (item.content || item.data || '').toLowerCase();
    const norm = item.normalized || {};
    const ents = norm.entities || {};
    const hay = title + ' ' + content;
    if (inc.length && !inc.some(k => hay.includes(k))) return false;
    if (exc.length && exc.some(k => hay.includes(k))) return false;
    const hasEmails = Array.isArray(ents.emails) && ents.emails.length > 0;
    const hasDomains = Array.isArray(ents.domains) && ents.domains.length > 0;
    const hasIPs = Array.isArray(ents.ips) && ents.ips.length > 0;
    const hasBTC = Array.isArray(ents.btc_wallets) && ents.btc_wallets.length > 0;
    // Add checks for new fields
    const hasSSN = !!item.ssn;
    const hasPasswords = !!item.passwords;
    const hasNames = !!item.names;
    const hasPhone = !!item.phone_numbers;
    const hasAddress = !!item.physical_addresses;
    const anyOn = wantEmails || wantDomains || wantIPs || wantBTC /* || wantSSN || wantPasswords || wantNames || wantPhone || wantAddress */;
    if (anyOn){
      const ok = (wantEmails && hasEmails) || (wantDomains && hasDomains) || (wantIPs && hasIPs) || (wantBTC && hasBTC);
      if (!ok) return false;
    }
    if (sevSel){
      const itemSev = (item.severity || 'unknown').toLowerCase();
      if (itemSev !== sevSel) return false;
    }
    return true;
  }



  async function loadLeaks(){
    const res = await fetch('/api/leaks?limit=100', { headers: { 'X-API-Key': API_KEY } });
    ALL_LEAKS = await res.json();
    applyAndRender();
  }

  function applyAndRender(){
    const filtered = (ALL_LEAKS || []).filter(matchesFilters);
    renderLeaks(filtered);
  }


  const API_KEY = localStorage.getItem('api_key') || "";



  async function runPastebin(){
    const runStatus = document.getElementById('runStatus');
    runStatus.textContent = 'Running…';
    const limit = parseInt(document.getElementById('pasteLimit').value || '10', 10);
    try {
      const res = await fetch('/api/crawlers/pastebin/run', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': API_KEY
        },
        body: JSON.stringify({ limit })
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Error');
      runStatus.textContent = `Done. Inserted: ${data.inserted}`;
      await loadLeaks();
    } catch (e){
      runStatus.textContent = 'Error: ' + e.message;
    }
  }

  async function runTor(){
    const status = document.getElementById('torStatus');
    status.textContent = 'Running…';
    const port = (document.getElementById('torPort').value || '').trim();
    try {
      const h = await fetch(`/api/proxy/tor/health?port=${encodeURIComponent(port||'9150')}`);
      const hj = await h.json();
      if (!hj.ok){
        status.textContent = `Tor proxy not reachable on 127.0.0.1:${hj.port}. Start Tor Browser (port 9150) or tor.exe (set port accordingly).`;
        return;
      }
    } catch(e){
      status.textContent = 'Tor health check failed: ' + e.message;
      return;
    }
    try {
      const res = await fetch('/api/crawlers/tor/run', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': API_KEY
        },
        body: JSON.stringify({ port: port || undefined })
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Error');
      status.textContent = data.fetched ? `Done. (${data.url})` : 'No content fetched.';
      await loadLeaks();
    } catch (e){
      status.textContent = 'Error: ' + e.message;
    }
  }

  async function runI2P(){
    const status = document.getElementById('i2pStatus');
    status.textContent = 'Running…';
    const url = (document.getElementById('i2pUrl').value || '').trim();
    const port = (document.getElementById('i2pPort').value || '').trim();
    try {
      const h = await fetch(`/api/proxy/i2p/health?port=${encodeURIComponent(port||'4444')}`);
      const hj = await h.json();
      if (!hj.ok){
        const res = await fetch('/api/crawlers/i2p/run', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-API-Key': API_KEY
          },
          body: JSON.stringify({ mock: true, port: port || undefined, url: url || undefined })
        });


        const data = await res.json();
        if (!res.ok) throw new Error(data.message || 'Error');
        status.textContent = data.mocked ? 'Inserted mock leak (no I2P proxy)' : 'Done.';
        await loadLeaks();
        return;
      }
    } catch(e){
      status.textContent = 'I2P health check failed: ' + e.message;
      return;
    }
    if (!url){ status.textContent = 'URL required (proxy is available)'; return; }
    try {
      const res = await fetch('/api/crawlers/i2p/run', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': API_KEY
        },
        body: JSON.stringify({ mock: true, port: port || undefined, url: url || undefined })
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Error');
      status.textContent = data.mocked ? 'Inserted mock leak' : (data.fetched ? 'Done.' : 'No content fetched.');
      await loadLeaks();
    } catch (e){
      status.textContent = 'Error: ' + e.message;
    }
  }


  async function runGithub(){
    const status = document.getElementById('githubStatus');
    status.textContent = 'Running…';
    const limit = parseInt(document.getElementById('githubLimit').value || '5', 10);
    try {
      const res = await fetch('/api/crawlers/github/run', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': API_KEY
        },
        body: JSON.stringify({ limit })
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Error');
      status.textContent = `Done. Inserted: ${data.inserted}`;
      await loadLeaks();
    } catch (e){
      status.textContent = 'Error: ' + e.message;
    }
  }


async function runFreenet(){
  const status = document.getElementById('freenetStatus');
  status.textContent = 'Running…';
  const limit = parseInt(document.getElementById('freenetLimit').value || '5', 10);
  const wantMock = document.getElementById('freenetMock').checked;

  // quick health ping
  let proxyOK = false;
  try {
    const h = await fetch('/api/proxy/freenet/health');
    const hj = await h.json();
    proxyOK = !!hj.ok;
  } catch(e){
    // swallow; we’ll decide based on wantMock
  }

  const payload = {
    limit,
    mock: wantMock && !proxyOK
  };

  try {
    const res = await fetch('/api/crawlers/freenet/run', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': API_KEY
      },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Error');
    status.textContent = `Done. Inserted: ${data.inserted}${payload.mock ? ' (mock)' : ''}`;
    await loadLeaks();
  } catch (e){
    status.textContent = 'Error: ' + e.message;
  }
}


  async function loadAssets(){
    const res = await fetch('/api/assets', { headers: { 'X-API-Key': API_KEY } });
    const items = await res.json();
    const tbody = document.querySelector('#assets-table tbody');
    if (!Array.isArray(items) || items.length === 0){
      tbody.innerHTML = '<tr><td colspan="4" class="muted">No items yet.</td></tr>';
      return;
    }
    tbody.innerHTML = items.map(a => `
      <tr>
        <td>${a.type}</td>
        <td><span class="truncate" title="${a.value}">${a.value}</span></td>
        <td class="nowrap">${a.created_at ? new Date(a.created_at).toLocaleString() : ''}</td>
        <td><button data-id="${a.id}" class="delAsset" style="padding:4px 8px; border:none; border-radius:6px; cursor:pointer;">Delete</button></td>
      </tr>
    `).join('');
    document.querySelectorAll('.delAsset').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.getAttribute('data-id');
        await fetch('/api/assets/' + id, { method: 'DELETE', headers: { 'X-API-Key': API_KEY } });
        await loadAssets();
      });
    });
  }

  async function addAsset(){
    const type = (document.getElementById('assetType').value || '').trim();
    const value = (document.getElementById('assetValue').value || '').trim();
    const status = document.getElementById('assetStatus');
    status.textContent = '';
    if (!type || !value){
      status.textContent = 'Type and value required';
      return;
    }
    const res = await fetch('/api/assets', {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-API-Key': API_KEY },
      body: JSON.stringify({ type, value })
    });
    if (!res.ok){
      const err = await res.json().catch(() => ({}));
      status.textContent = err.message || 'Error';
      return;
    }
    document.getElementById('assetValue').value = '';
    await loadAssets();
    status.textContent = 'Saved';
  }

  document.addEventListener('DOMContentLoaded', () => {
    loadLeaks();
    document.getElementById('runPastebinBtn')?.addEventListener('click', runPastebin);
    document.getElementById('runTorBtn')?.addEventListener('click', runTor);
    document.getElementById('runI2PBtn')?.addEventListener('click', runI2P);
    document.getElementById('applyFilters')?.addEventListener('click', applyAndRender);
    loadAssets();
    document.getElementById('addAsset')?.addEventListener('click', addAsset);
    document.getElementById('runGithubBtn')?.addEventListener('click', runGithub);
    document.getElementById('runFreenetBtn')?.addEventListener('click', runFreenet);
  });
})();
