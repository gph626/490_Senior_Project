// Leaks page logic
(function(){
  const PAGE_SIZE = 20;
  let CURRENT_PAGE = 1;
  let FILTERED = [];
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
      const src = (it.source || '').toLowerCase();
      const srcLabel = (it.source || '').toUpperCase();
      // Alert status badge
      const alerted = it.alerted === 1;
      const alertBadge = alerted 
        ? '<span class="badge" style="background:#28a745; color:#fff;">✓ Sent</span>'
        : '<span class="badge" style="background:#6c757d; color:#fff;">⏳ Pending</span>';
      return `<tr class="leak-row" data-id="${it.id}">
                <td><span class="chip chip-${src}">${srcLabel}</span></td>
                <td><span class="wrap-title" title="${title.replaceAll('"','&quot;')}">${title}</span></td>
                <td style="max-width:380px">${entsHtml || '<span class=\"muted\">—</span>'}</td>
                <td><span class="badge ${sevClass}">${it.severity || 'unknown'}</span></td>
                <td class="nowrap">${alertBadge}</td>
                <td class="nowrap"><button data-id="${it.id}" class="delLeak" style="padding:4px 8px; border:none; border-radius:6px; cursor:pointer;">Delete</button></td>
              </tr>`;
    }).join('');
    tbody.innerHTML = rows;
    // bind delete buttons
    document.querySelectorAll('.delLeak').forEach(btn => {
      btn.addEventListener('click', async () => {
        event?.stopPropagation?.();
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

    // row click -> open modal
    tbody.querySelectorAll('tr.leak-row').forEach(tr => {
      tr.addEventListener('click', (ev) => {
        if (ev.target.closest('button')) return; // ignore button clicks
        const id = Number(tr.getAttribute('data-id'));
        const item = (ALL_LEAKS || []).find(x => x.id === id);
        if (item) openLeakModal(item);
      });
    });
  }

  let ALL_LEAKS = [];

  function matchesFilters(item){
    const sevSel = (document.getElementById('sevFilter').value || '').toLowerCase();
    const srcSel = (document.getElementById('srcFilter').value || '').toLowerCase();
    if (sevSel){
      const itemSev = (item.severity || 'unknown').toLowerCase();
      if (itemSev !== sevSel) return false;
    }
    if (srcSel){
      const src = (item.source || '').toLowerCase();
      if (src !== srcSel) return false;
    }
    return true;
  }



  async function loadLeaks(){
    const res = await fetch('/api/leaks?limit=100', { headers: { 'X-API-Key': API_KEY } });
    ALL_LEAKS = await res.json();
    applyAndRender();
  }

  function applyAndRender(resetPage=false){
    FILTERED = (ALL_LEAKS || []).filter(matchesFilters);
    const total = FILTERED.length;
    const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
    if (resetPage) CURRENT_PAGE = 1;
    if (CURRENT_PAGE > totalPages) CURRENT_PAGE = totalPages;
    if (CURRENT_PAGE < 1) CURRENT_PAGE = 1;
    const startIdx = (CURRENT_PAGE - 1) * PAGE_SIZE;
    const endIdx = Math.min(startIdx + PAGE_SIZE, total);
    const pageItems = FILTERED.slice(startIdx, endIdx);
    renderLeaks(pageItems);
    // update pager
    const info = document.getElementById('pageInfo');
    if (info){
      if (total === 0) info.textContent = 'Showing 0 of 0';
      else info.textContent = `Showing ${startIdx+1}–${endIdx} of ${total}`;
    }
    const prev = document.getElementById('prevPage');
    const next = document.getElementById('nextPage');
    if (prev) prev.disabled = CURRENT_PAGE <= 1;
    if (next) next.disabled = CURRENT_PAGE >= totalPages || total === 0;
  }


  const API_KEY = localStorage.getItem('api_key') || "";



  async function runPastebin(){
    const runStatus = document.getElementById('runStatus');
    runStatus.textContent = 'Running…';
    try {
      const res = await fetch('/api/crawlers/pastebin/run', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': API_KEY
        },
        body: JSON.stringify({})  // Use defaults from config
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
    try {
      const res = await fetch('/api/crawlers/github/run', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': API_KEY
        },
        body: JSON.stringify({})  // Use defaults from config
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Error');
      status.textContent = `Done. Inserted: ${data.inserted}`;
      await loadLeaks();
    } catch (e){
      status.textContent = 'Error: ' + e.message;
    }
  }


  // Removed assets/watchlist management - now handled in config page


  document.addEventListener('DOMContentLoaded', () => {
    loadLeaks();
    // Removed tab switching - no longer using tabs on leaks page
    document.getElementById('runPastebinBtn')?.addEventListener('click', runPastebin);
    document.getElementById('runTorBtn')?.addEventListener('click', runTor);
    document.getElementById('runI2PBtn')?.addEventListener('click', runI2P);
    document.getElementById('applyFilters')?.addEventListener('click', () => applyAndRender(true));
    document.getElementById('prevPage')?.addEventListener('click', () => { CURRENT_PAGE -= 1; applyAndRender(false); });
    document.getElementById('nextPage')?.addEventListener('click', () => { CURRENT_PAGE += 1; applyAndRender(false); });
    // Removed watchlist/assets code - now managed in config page
    document.getElementById('runGithubBtn')?.addEventListener('click', runGithub);
    document.getElementById('insertMockLeaksBtn')?.addEventListener('click', async () => {
      const status = document.getElementById('mockInsertStatus');
      status.textContent = 'Inserting…';
      try {
        const res = await fetch('/api/leaks/mock', {
          method: 'POST',
          headers: { 'X-API-Key': API_KEY }
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.message || 'Error');
        status.textContent = `Inserted: ${data.inserted}${data.duplicates ? ` (dupes: ${data.duplicates})` : ''}`;
        await loadLeaks();
      } catch (e){
        status.textContent = 'Error: ' + e.message;
      }
    });

    // Modal close controls
    document.getElementById('leakModalClose')?.addEventListener('click', closeLeakModal);
    document.getElementById('leakModal')?.addEventListener('click', (e) => {
      if (e.target.id === 'leakModal') closeLeakModal();
    });
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') closeLeakModal();
    });
  });

  function openLeakModal(item){
    const modal = document.getElementById('leakModal');
    const body = document.getElementById('leakModalBody');
    if (!modal || !body) return;
    const norm = item.normalized || {};
    const ents = norm.entities || {};
    const parseMaybeJson = (v) => {
      if (!v) return [];
      try{ const arr = typeof v === 'string' ? JSON.parse(v) : v; return Array.isArray(arr) ? arr : []; }catch{ return []; }
    };
    const full = {
      emails: ents.emails || [],
      domains: ents.domains || [],
      ips: ents.ips || [],
      btc_wallets: ents.btc_wallets || [],
      ssns: parseMaybeJson(item.ssn),
      names: parseMaybeJson(item.names),
      phone_numbers: parseMaybeJson(item.phone_numbers),
      physical_addresses: parseMaybeJson(item.physical_addresses),
      passwords: parseMaybeJson(item.passwords),
    };
    const list = (label, arr) => arr && arr.length
      ? `<div style="margin-bottom:6px;"><span class=\"muted\" style=\"text-transform:uppercase;\">${label}:</span><div>${arr.map(x=>`<span class=\"badge\" style=\"background:#2a2f36; color:#cfd7e6; margin:2px 4px 2px 0;\">${x}</span>`).join('')}</div></div>`
      : '';
    const src = (item.source||'').toLowerCase();
    const sev = (item.severity || 'unknown').toLowerCase();
    body.innerHTML = `
      <div style="display:flex; align-items:center; gap:10px; margin-bottom:10px;">
        <span class="chip chip-${src}">${(item.source||'').toUpperCase()}</span>
        <span class="badge ${['low','medium','high','critical'].includes(sev)?sev:''}">${item.severity||'unknown'}</span>
      </div>
      <div style="margin-bottom:10px; font-weight:700;">${(item.title||'(no title)')}</div>
      ${list('emails', full.emails)}
      ${list('domains', full.domains)}
      ${list('ips', full.ips)}
      ${list('btc', full.btc_wallets)}
      ${list('ssns', full.ssns)}
      ${list('names', full.names)}
      ${list('phones', full.phone_numbers)}
      ${list('addresses', full.physical_addresses)}
      ${list('passwords', full.passwords)}
    `;
    modal.style.display = 'flex';
  }

  function closeLeakModal(){
    const modal = document.getElementById('leakModal');
    if (modal) modal.style.display = 'none';
  }
})();
