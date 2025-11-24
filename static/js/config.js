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

    // Watchlist - All entity types
    document.getElementById('watchlistDomains').value = (watchlist.domains || []).join(', ');
    document.getElementById('watchlistEmails').value = (watchlist.emails || []).join(', ');
    document.getElementById('watchlistIPs').value = (watchlist.ips || []).join(', ');
    document.getElementById('watchlistBTC').value = (watchlist.btc_wallets || []).join(', ');
    document.getElementById('watchlistNames').value = (watchlist.names || []).join(', ');
    document.getElementById('watchlistKeywords').value = (watchlist.keywords || []).join(', ');
    
    // Sensitive watchlist fields (hashed in DB, show placeholder if entries exist)
    const ssnCount = (watchlist.ssns || []).length;
    const pwdCount = (watchlist.passwords || []).length;
    const phoneCount = (watchlist.phone_numbers || []).length;
    const addrCount = (watchlist.physical_addresses || []).length;
    
    document.getElementById('watchlistSSNs').placeholder = ssnCount > 0 
      ? `🔒 ${ssnCount} SSN(s) stored (hashed) - enter new values to replace or "CLEAR" to remove`
      : '123-45-6789, 987-65-4321';
    document.getElementById('watchlistPasswords').placeholder = pwdCount > 0 
      ? `🔒 ${pwdCount} password(s) stored (hashed) - enter new values to replace or "CLEAR" to remove`
      : 'password123, MySecurePass!';
    document.getElementById('watchlistPhones').placeholder = phoneCount > 0 
      ? `🔒 ${phoneCount} phone(s) stored (hashed) - enter new values to replace or "CLEAR" to remove`
      : '555-123-4567, (555) 987-6543';
    document.getElementById('watchlistAddresses').placeholder = addrCount > 0 
      ? `🔒 ${addrCount} address(es) stored (hashed) - enter new values to replace or "CLEAR" to remove`
      : '123 Main St, Anytown, CA 12345';
    
    // Leave fields empty (user must re-enter to update)
    document.getElementById('watchlistSSNs').value = '';
    document.getElementById('watchlistPasswords').value = '';
    document.getElementById('watchlistPhones').value = '';
    document.getElementById('watchlistAddresses').value = '';

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
    
    // Save alerts enabled state to localStorage for timer visibility
    localStorage.setItem('alerts_enabled', alerts.enabled !== false ? 'true' : 'false');
    localStorage.setItem('notification_mode', 'batch');
  }

  // Save configuration
  async function saveConfig(){
    const status = document.getElementById('configStatus');
    status.textContent = 'Saving configuration...';
    status.style.color = '#666';

    try {
      // Helper to split and clean comma-separated values
      const splitClean = (value) => value.split(',').map(s => s.trim()).filter(Boolean);
      
      // Get current config to preserve existing hashed values
      const orgId = localStorage.getItem('org_id') || '123';
      const currentRes = await fetch(`/v1/config/org/${orgId}`, {
        headers: { 'X-API-Key': API_KEY }
      });
      const currentConfig = await currentRes.json();
      const currentWatchlist = currentConfig.watchlist || {};
      
      // Build watchlist - only include sensitive fields if user entered new values
      const watchlist = {
        // Non-sensitive entities
        domains: splitClean(document.getElementById('watchlistDomains').value),
        emails: splitClean(document.getElementById('watchlistEmails').value),
        ips: splitClean(document.getElementById('watchlistIPs').value),
        btc_wallets: splitClean(document.getElementById('watchlistBTC').value),
        names: splitClean(document.getElementById('watchlistNames').value),
        keywords: splitClean(document.getElementById('watchlistKeywords').value)
      };
      
      // Sensitive entities - only send if user entered values, otherwise preserve existing
      const ssnInput = document.getElementById('watchlistSSNs').value.trim();
      const pwdInput = document.getElementById('watchlistPasswords').value.trim();
      const phoneInput = document.getElementById('watchlistPhones').value.trim();
      const addrInput = document.getElementById('watchlistAddresses').value.trim();
      
      // Check for special "CLEAR" keyword to allow removal
      watchlist.ssns = ssnInput === 'CLEAR' ? [] : (ssnInput ? splitClean(ssnInput) : currentWatchlist.ssns || []);
      watchlist.passwords = pwdInput === 'CLEAR' ? [] : (pwdInput ? splitClean(pwdInput) : currentWatchlist.passwords || []);
      watchlist.phone_numbers = phoneInput === 'CLEAR' ? [] : (phoneInput ? splitClean(phoneInput) : currentWatchlist.phone_numbers || []);
      watchlist.physical_addresses = addrInput === 'CLEAR' ? [] : (addrInput ? splitClean(addrInput) : currentWatchlist.physical_addresses || []);
      
      const config = {
        watchlist: watchlist,
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
          notification_mode: 'batch',  // Always use batch mode
          email: document.getElementById('alertEmail').value,
          webhook: document.getElementById('alertWebhook').value,
          check_interval_min: parseInt(document.getElementById('alertInterval').value) || 15
        }
      };

      const res = await fetch(`/v1/config/org/${orgId}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': API_KEY
        },
        body: JSON.stringify(config)
      });

      if (!res.ok) throw new Error(`HTTP ${res.status}`);

      // Save alerts enabled state and mode to localStorage for timer visibility
      const alertsEnabled = document.getElementById('alertsEnabled').checked;
      localStorage.setItem('alerts_enabled', alertsEnabled ? 'true' : 'false');
      localStorage.setItem('notification_mode', 'batch');

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
