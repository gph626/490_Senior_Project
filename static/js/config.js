// Config page logic
(function(){
  const API_KEY = localStorage.getItem('api_key') || '';

  // Tab switching
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const target = btn.getAttribute('data-tab');
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById(target)?.classList.add('active');
    });
  });

  // Load current configuration
  async function loadConfig(){
    const status = document.getElementById('configStatus');
    status.textContent = 'Loading configuration...';
    status.style.color = '#666';

    try {
      // Get current user's org_id (defaulting to 123 for now)
      const orgId = localStorage.getItem('org_id') || '123';
      const res = await fetch(`/v1/config/org/${orgId}`, {
        headers: { 'X-API-Key': API_KEY }
      });

      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      
      const config = await res.json();
      populateForm(config);
      status.textContent = 'Configuration loaded';
      status.style.color = '#4CAF50';
      setTimeout(() => { status.textContent = ''; }, 3000);
    } catch(e){
      status.textContent = 'Error loading config: ' + e.message;
      status.style.color = '#f44336';
    }
  }

  // Populate form fields with config data
  function populateForm(config){
    const watchlist = config.watchlist || {};
    const sources = config.sources || {};
    const alerts = config.alerts || {};

    // Watchlist
    document.getElementById('watchlistDomains').value = (watchlist.domains || []).join(', ');
    document.getElementById('watchlistEmails').value = (watchlist.emails || []).join(', ');
    document.getElementById('watchlistKeywords').value = (watchlist.keywords || []).join(', ');

    // Pastebin
    const pastebin = sources.pastebin || {};
    document.getElementById('pastebinLimit').value = pastebin.limit || 5;
    document.getElementById('pastebinRateLimit').value = pastebin.rate_limit_ms || 500;
    document.getElementById('pastebinTimeout').value = pastebin.timeout_sec || 15;

    // Tor
    const tor = sources.tor || {};
    document.getElementById('torPort').value = tor.socks_port || 9050;
    document.getElementById('torTimeout').value = tor.timeout_sec || 40;
    document.getElementById('torKeywords').value = (tor.keywords || []).join(', ');

    // I2P
    const i2p = sources.i2p || {};
    document.getElementById('i2pHost').value = i2p.proxy_host || '127.0.0.1';
    document.getElementById('i2pPort').value = i2p.proxy_port || 4444;
    document.getElementById('i2pTimeout').value = i2p.timeout_sec || 40;
    document.getElementById('i2pKeywords').value = (i2p.keywords || []).join(', ');

    // GitHub
    const github = sources.github || {};
    document.getElementById('githubToken').value = github.token || '';
    document.getElementById('githubLimit').value = github.limit || 10;
    document.getElementById('githubTimeout').value = github.timeout_sec || 20;
    document.getElementById('githubKeywords').value = (github.keywords || []).join(', ');

    // Alerts
    document.getElementById('alertsEnabled').checked = alerts.enabled !== false;
    document.getElementById('alertThreshold').value = alerts.threshold || 'critical';
    document.getElementById('alertEmail').value = alerts.email || '';
    document.getElementById('alertWebhook').value = alerts.webhook || '';
    document.getElementById('alertInterval').value = alerts.check_interval_min || 15;
  }

  // Save configuration
  async function saveConfig(){
    const status = document.getElementById('configStatus');
    status.textContent = 'Saving configuration...';
    status.style.color = '#666';

    try {
      const config = {
        watchlist: {
          domains: document.getElementById('watchlistDomains').value.split(',').map(s => s.trim()).filter(Boolean),
          emails: document.getElementById('watchlistEmails').value.split(',').map(s => s.trim()).filter(Boolean),
          keywords: document.getElementById('watchlistKeywords').value.split(',').map(s => s.trim()).filter(Boolean)
        },
        sources: {
          pastebin: {
            limit: parseInt(document.getElementById('pastebinLimit').value) || 5,
            rate_limit_ms: parseInt(document.getElementById('pastebinRateLimit').value) || 500,
            timeout_sec: parseInt(document.getElementById('pastebinTimeout').value) || 15
          },
          tor: {
            socks_port: parseInt(document.getElementById('torPort').value) || 9050,
            timeout_sec: parseInt(document.getElementById('torTimeout').value) || 40,
            keywords: document.getElementById('torKeywords').value.split(',').map(s => s.trim()).filter(Boolean)
          },
          i2p: {
            proxy_host: document.getElementById('i2pHost').value || '127.0.0.1',
            proxy_port: parseInt(document.getElementById('i2pPort').value) || 4444,
            timeout_sec: parseInt(document.getElementById('i2pTimeout').value) || 40,
            keywords: document.getElementById('i2pKeywords').value.split(',').map(s => s.trim()).filter(Boolean)
          },
          github: {
            token: document.getElementById('githubToken').value || '',
            limit: parseInt(document.getElementById('githubLimit').value) || 10,
            timeout_sec: parseInt(document.getElementById('githubTimeout').value) || 20,
            keywords: document.getElementById('githubKeywords').value.split(',').map(s => s.trim()).filter(Boolean)
          }
        },
        alerts: {
          enabled: document.getElementById('alertsEnabled').checked,
          threshold: document.getElementById('alertThreshold').value,
          email: document.getElementById('alertEmail').value,
          webhook: document.getElementById('alertWebhook').value,
          check_interval_min: parseInt(document.getElementById('alertInterval').value) || 15
        }
      };

      const orgId = localStorage.getItem('org_id') || '123';
      const res = await fetch(`/v1/config/org/${orgId}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': API_KEY
        },
        body: JSON.stringify(config)
      });

      if (!res.ok) throw new Error(`HTTP ${res.status}`);

      status.textContent = 'Configuration saved successfully!';
      status.style.color = '#4CAF50';
      setTimeout(() => { status.textContent = ''; }, 3000);
    } catch(e){
      status.textContent = 'Error saving config: ' + e.message;
      status.style.color = '#f44336';
    }
  }

  // Reset to defaults
  async function resetConfig(){
    if (!confirm('Reset all settings to defaults? This will discard any custom configuration.')) {
      return;
    }

    const status = document.getElementById('configStatus');
    status.textContent = 'Resetting to defaults...';
    status.style.color = '#666';

    try {
      const orgId = localStorage.getItem('org_id') || '123';
      const res = await fetch(`/v1/config/org/${orgId}/reset`, {
        method: 'POST',
        headers: { 'X-API-Key': API_KEY }
      });

      if (!res.ok) throw new Error(`HTTP ${res.status}`);

      // Reload config after reset
      await loadConfig();
      status.textContent = 'Configuration reset to defaults';
      status.style.color = '#4CAF50';
      setTimeout(() => { status.textContent = ''; }, 3000);
    } catch(e){
      status.textContent = 'Error resetting config: ' + e.message;
      status.style.color = '#f44336';
    }
  }

  // Event listeners
  document.addEventListener('DOMContentLoaded', () => {
    loadConfig();
    document.getElementById('saveConfigBtn')?.addEventListener('click', saveConfig);
    document.getElementById('resetConfigBtn')?.addEventListener('click', resetConfig);
  });
})();
