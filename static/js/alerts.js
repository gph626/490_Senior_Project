// Alerts page logic with tabs
(function(){
  const ORG_ID = 123; // Default org ID
  const API_KEY = localStorage.getItem('api_key') || '';

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
      tbody.innerHTML = '<tr><td colspan="4" class="muted" style="text-align: center; padding: 40px;">No critical alerts yet.</td></tr>';
      return;
    }
    tbody.innerHTML = items.map(a => {
      const sev = (a.severity || 'unknown').toLowerCase();
      const sevBadgeClass = `severity-badge severity-${sev}`;
      const ts = a.timestamp ? new Date(a.timestamp).toLocaleString() : '';
      const ents = a.entities || {};
      const show = (arr, label) => Array.isArray(arr) && arr.length ? `<span style="margin-right:8px; padding: 2px 8px; background: #3D4754; border-radius: 4px; font-size: 11px;">${label}: ${arr.slice(0,2).join(', ')}${arr.length>2?'...':''}</span>`: '';
      const entHtml = show(ents.emails, '📧') + show(ents.domains, '🌐') + show(ents.ips, '🔌');
      return `<tr style="border-bottom: 1px solid #3D4754;">
          <td><span class="${sevBadgeClass}">${a.severity}</span></td>
          <td class="nowrap" style="color: #9aa2ac;">${ts}</td>
          <td style="color: #9aa2ac;">${a.source || ''}</td>
          <td><div style="font-weight:600; color: #ECECEC; margin-bottom: 6px;">${(a.title||'(no title)')}</div><div style="font-size:12px;">${entHtml || '<span class="muted">No entities extracted</span>'}</div></td>
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
      tbody.innerHTML = '<tr><td colspan="6" class="muted" style="text-align: center; padding: 40px;">No alert history yet.</td></tr>';
      return;
    }
    tbody.innerHTML = items.map(h => {
      const statusBadgeClass = `status-badge status-${h.status}`;
      const sentAt = h.sent_at ? new Date(h.sent_at).toLocaleString() : '';
      const typeIcon = h.alert_type === 'webhook' ? '🔗' : '📧';
      return `<tr style="border-bottom: 1px solid #3D4754;">
          <td><span style="padding: 4px 10px; background: #3D4754; border-radius: 4px; font-size: 12px;">${typeIcon} ${h.alert_type}</span></td>
          <td><span class="${statusBadgeClass}">${h.status.toUpperCase()}</span></td>
          <td class="nowrap" style="color: #9aa2ac;">${sentAt}</td>
          <td style="color: #9aa2ac;">${h.leak_id || '—'}</td>
          <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis; color: #9aa2ac; font-size: 12px;">${h.destination || '—'}</td>
          <td class="muted" style="font-size: 11px; color: ${h.error_message ? '#f44336' : '#4CAF50'};">${h.error_message || 'Success'}</td>
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
      const res = await fetch(`/v1/config/org/${ORG_ID}`, {
        headers: { 'X-API-Key': API_KEY }
      });
      const config = await res.json();
      const alerts = config.alerts || {};
      
      document.getElementById('alertsEnabled').checked = alerts.enabled !== false;
      document.getElementById('webhookUrl').value = alerts.webhook || '';
      document.getElementById('alertEmail').value = alerts.email || '';
      document.getElementById('alertThreshold').value = alerts.threshold || 'critical';
      document.getElementById('notificationMode').value = alerts.notification_mode || 'immediate';
      document.getElementById('checkInterval').value = alerts.check_interval_min || 15;
      
      // Show/hide batch interval based on mode
      updateBatchIntervalVisibility();
      
      // Hide status after successful load
      status.style.display = 'none';
    } catch(e){
      status.style.background = '#3d1a1a';
      status.style.color = '#f44336';
      status.style.border = '1px solid #5a2d2d';
      status.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> Error loading settings: ${e.message}`;
    }
  }
  
  // Show/hide batch interval section based on notification mode
  function updateBatchIntervalVisibility() {
    const mode = document.getElementById('notificationMode').value;
    const section = document.getElementById('batchIntervalSection');
    // Only show for batch mode (periodic)
    if (mode === 'batch') {
      section.style.display = 'block';
    } else {
      section.style.display = 'none';
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
      const res = await fetch(`/v1/config/org/${ORG_ID}`, {
        headers: { 'X-API-Key': API_KEY }
      });
      const config = await res.json();
      
      // Update alerts section
      config.alerts = {
        enabled: document.getElementById('alertsEnabled').checked,
        webhook: document.getElementById('webhookUrl').value,
        email: document.getElementById('alertEmail').value,
        threshold: document.getElementById('alertThreshold').value,
        notification_mode: document.getElementById('notificationMode').value,
        check_interval_min: parseInt(document.getElementById('checkInterval').value) || 15
      };
      
      // Save
      const saveRes = await fetch(`/v1/config/org/${ORG_ID}`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'X-API-Key': API_KEY
        },
        body: JSON.stringify(config)
      });
      
      if (saveRes.ok) {
        status.style.background = '#1a3d1a';
        status.style.color = '#4CAF50';
        status.style.border = '1px solid #2d5a2d';
        status.innerHTML = '<i class="fa-solid fa-circle-check"></i> Configuration saved successfully!';
        
        // Save notification mode to localStorage for timer visibility
        const notificationMode = document.getElementById('notificationMode').value;
        localStorage.setItem('notification_mode', notificationMode);
        
        // Reset timer with new interval
        const newInterval = parseInt(document.getElementById('checkInterval').value) || 15;
        if (window.AlertTimer) {
          window.AlertTimer.updateInterval(newInterval);
        }
        
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
  
  // Test batch webhook
  async function testBatchWebhook() {
    const status = document.getElementById('settingsStatus');
    if (!status) return;
    
    status.style.display = 'block';
    status.style.background = '#23272F';
    status.style.color = '#9aa2ac';
    status.style.border = '1px solid #3D4754';
    status.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Sending batch webhook test...';
    
    try {
      const response = await fetch('/api/alerts/send_batch', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'X-API-Key': API_KEY
        }
      });
      
      const result = await response.json();
      
      if (response.ok && result.status === 'sent') {
        status.style.background = '#1a3d1a';
        status.style.color = '#4CAF50';
        status.style.border = '1px solid #2d5a2d';
        status.innerHTML = `<i class="fa-solid fa-circle-check"></i> Batch webhook sent! Found ${result.leaks_count || 0} leak(s). Check your channel.`;
      } else if (result.status === 'no new leaks to report' || result.status === 'no notable leaks (only low/info)') {
        status.style.background = '#3d2a1a';
        status.style.color = '#FF9800';
        status.style.border = '1px solid #5a4d2d';
        status.innerHTML = `<i class="fa-solid fa-circle-info"></i> ${result.status}`;
      } else {
        status.style.background = '#3d1a1a';
        status.style.color = '#f44336';
        status.style.border = '1px solid #5a2d2d';
        status.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> Error: ${result.error || 'Unknown error'}`;
      }
    } catch(e){
      status.style.background = '#3d1a1a';
      status.style.color = '#f44336';
      status.style.border = '1px solid #5a2d2d';
      status.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> Batch test failed: ${e.message}`;
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
    document.getElementById('testBatchWebhook')?.addEventListener('click', testBatchWebhook);
    document.getElementById('notificationMode')?.addEventListener('change', updateBatchIntervalVisibility);
    
    // Load initial tab content
    loadAlerts();
  });
})();
