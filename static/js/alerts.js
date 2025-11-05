// Alerts page logic with tabs
(function(){
  const ORG_ID = 123; // Default org ID

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
        
        // Load data for active tab
        if (button.dataset.tab === 'critical') {
          loadAlerts();
        } else if (button.dataset.tab === 'history') {
          loadHistory();
        } else if (button.dataset.tab === 'settings') {
          loadAlertSettings();
        }
      });
    });
  }

  // Load critical alerts
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

  // Load alert history
  async function loadHistory(){
    const status = document.getElementById('historyStatus');
    if(!status) return;
    status.textContent = 'Loading…';
    try {
      const res = await fetch('/api/alerts/history');
      const data = await res.json();
      renderHistory(Array.isArray(data)? data: []);
      status.textContent = data.length ? data.length + ' alerts sent' : 'No alert history';
    } catch(e){
      status.textContent = 'Error: ' + e.message;
    }
  }

  function renderHistory(items){
    const tbody = document.querySelector('#historyTable tbody');
    if(!tbody) return;
    if(!items.length){
      tbody.innerHTML = '<tr><td colspan="6" class="muted">No alert history yet.</td></tr>';
      return;
    }
    tbody.innerHTML = items.map(h => {
      const statusClass = h.status === 'sent' ? 'success' : (h.status === 'failed' ? 'critical' : '');
      const sentAt = h.sent_at ? new Date(h.sent_at).toLocaleString() : '';
      return `<tr>
          <td><span class="chip">${h.alert_type}</span></td>
          <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis;">${h.destination}</td>
          <td><span class="badge ${statusClass}">${h.status}</span></td>
          <td class="nowrap">${sentAt}</td>
          <td>${h.leak_id}</td>
          <td class="muted" style="font-size: 11px;">${h.error_message || '—'}</td>
      </tr>`;
    }).join('');
  }

  // Load alert settings
  async function loadAlertSettings(){
    const status = document.getElementById('settingsStatus');
    if(!status) return;
    
    status.style.display = 'block';
    status.style.background = '#23272F';
    status.style.color = '#9aa2ac';
    status.style.border = '1px solid #3D4754';
    status.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Loading settings...';
    
    try {
      const res = await fetch(`/v1/config/org/${ORG_ID}`);
      const config = await res.json();
      const alerts = config.alerts || {};
      
      document.getElementById('alertsEnabled').checked = alerts.enabled !== false;
      document.getElementById('webhookUrl').value = alerts.webhook || '';
      document.getElementById('alertEmail').value = alerts.email || '';
      document.getElementById('alertThreshold').value = alerts.threshold || 'critical';
      
      // Hide status after successful load
      status.style.display = 'none';
    } catch(e){
      status.style.background = '#3d1a1a';
      status.style.color = '#f44336';
      status.style.border = '1px solid #5a2d2d';
      status.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> Error loading settings: ${e.message}`;
    }
  }

  // Save alert settings
  async function saveAlertSettings(e){
    e.preventDefault();
    const status = document.getElementById('settingsStatus');
    
    // Show loading state
    status.style.display = 'block';
    status.style.background = '#23272F';
    status.style.color = '#9aa2ac';
    status.style.border = '1px solid #3D4754';
    status.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Saving configuration...';
    
    try {
      // Get current config
      const res = await fetch(`/v1/config/org/${ORG_ID}`);
      const config = await res.json();
      
      // Update alerts section
      config.alerts = {
        enabled: document.getElementById('alertsEnabled').checked,
        webhook: document.getElementById('webhookUrl').value,
        email: document.getElementById('alertEmail').value,
        threshold: document.getElementById('alertThreshold').value,
        check_interval_min: config.alerts?.check_interval_min || 15
      };
      
      // Save
      const saveRes = await fetch(`/v1/config/org/${ORG_ID}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config)
      });
      
      if (saveRes.ok) {
        status.style.background = '#1a3d1a';
        status.style.color = '#4CAF50';
        status.style.border = '1px solid #2d5a2d';
        status.innerHTML = '<i class="fa-solid fa-circle-check"></i> Configuration saved successfully!';
        setTimeout(() => {
          status.style.display = 'none';
        }, 5000);
      } else {
        throw new Error('Failed to save');
      }
    } catch(e){
      status.style.background = '#3d1a1a';
      status.style.color = '#f44336';
      status.style.border = '1px solid #5a2d2d';
      status.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> Error: ${e.message}`;
    }
  }

  // Test webhook
  async function testWebhook(){
    const status = document.getElementById('settingsStatus');
    const webhookUrl = document.getElementById('webhookUrl').value;
    
    if (!webhookUrl) {
      status.style.display = 'block';
      status.style.background = '#3d1a1a';
      status.style.color = '#f44336';
      status.style.border = '1px solid #5a2d2d';
      status.innerHTML = '<i class="fa-solid fa-circle-exclamation"></i> Please enter a webhook URL first';
      setTimeout(() => { status.style.display = 'none'; }, 3000);
      return;
    }
    
    status.style.display = 'block';
    status.style.background = '#23272F';
    status.style.color = '#9aa2ac';
    status.style.border = '1px solid #3D4754';
    status.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Sending test webhook...';
    
    try {
      // Check if it's a Discord webhook
      const isDiscord = webhookUrl.toLowerCase().includes('discord.com/api/webhooks');
      
      let payload;
      if (isDiscord) {
        // Discord-specific format with embeds
        payload = {
          username: 'DarkWidow Alert',
          embeds: [{
            title: '🧪 Test Webhook - DarkWidow',
            description: 'This is a test message from your DarkWidow security platform. If you see this, your webhook is configured correctly!',
            color: 3447003, // Blue color for test
            fields: [
              { name: 'Status', value: 'Test Successful', inline: true },
              { name: 'Source', value: 'Manual Test', inline: true }
            ],
            timestamp: new Date().toISOString(),
            footer: {
              text: 'DarkWidow Security Platform'
            }
          }]
        };
      } else {
        // Generic webhook format
        payload = {
          leak_id: 0,
          severity: 100,
          title: 'Test Alert',
          source: 'test',
          timestamp: new Date().toISOString(),
          alert_type: 'test'
        };
      }
      
      const response = await fetch(webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      
      if (response.ok) {
        status.style.background = '#1a3d1a';
        status.style.color = '#4CAF50';
        status.style.border = '1px solid #2d5a2d';
        status.innerHTML = '<i class="fa-solid fa-circle-check"></i> Test webhook sent successfully! Check your Discord/Slack channel.';
      } else {
        status.style.background = '#3d2a1a';
        status.style.color = '#FF9800';
        status.style.border = '1px solid #5a4d2d';
        status.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i> Webhook responded with status ${response.status}`;
      }
    } catch(e){
      status.style.background = '#3d1a1a';
      status.style.color = '#f44336';
      status.style.border = '1px solid #5a2d2d';
      status.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> Webhook test failed: ${e.message}`;
    }
    
    // Hide after 8 seconds
    setTimeout(() => {
      status.style.display = 'none';
    }, 8000);
  }

  document.addEventListener('DOMContentLoaded', ()=>{
    initTabs();
    
    // Critical alerts tab
    document.getElementById('refreshAlerts')?.addEventListener('click', loadAlerts);
    
    // History tab
    document.getElementById('refreshHistory')?.addEventListener('click', loadHistory);
    
    // Settings tab
    document.getElementById('alertSettingsForm')?.addEventListener('submit', saveAlertSettings);
    document.getElementById('testWebhook')?.addEventListener('click', testWebhook);
    
    // Load initial tab content
    loadAlerts();
  });
})();
