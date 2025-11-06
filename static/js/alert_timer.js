// Alert Timer - Countdown to next batch webhook
(function(){
  let timerInterval = null;
  let nextAlertTime = null;
  let checkIntervalMin = 15;
  
  // Get stored timer state from localStorage
  function loadTimerState() {
    const stored = localStorage.getItem('alert_timer_state');
    if (stored) {
      try {
        const state = JSON.parse(stored);
        nextAlertTime = new Date(state.nextAlertTime);
        checkIntervalMin = state.checkIntervalMin || 15;
        
        // If stored time is in the past, reset
        if (nextAlertTime < new Date()) {
          resetTimer();
        }
      } catch(e) {
        resetTimer();
      }
    } else {
      resetTimer();
    }
  }
  
  // Save timer state to localStorage
  function saveTimerState() {
    if (nextAlertTime) {
      localStorage.setItem('alert_timer_state', JSON.stringify({
        nextAlertTime: nextAlertTime.toISOString(),
        checkIntervalMin: checkIntervalMin
      }));
    }
  }
  
  // Reset timer to current time + interval
  function resetTimer(newIntervalMin) {
    if (newIntervalMin !== undefined) {
      checkIntervalMin = newIntervalMin;
    }
    nextAlertTime = new Date(Date.now() + checkIntervalMin * 60 * 1000);
    saveTimerState();
    updateDisplay();
  }
  
  // Format time remaining as "5m 23s" or "1h 15m"
  function formatTimeRemaining(ms) {
    if (ms <= 0) return '0s';
    
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    
    if (hours > 0) {
      return `${hours}h ${minutes % 60}m`;
    } else if (minutes > 0) {
      return `${minutes}m ${seconds % 60}s`;
    } else {
      return `${seconds}s`;
    }
  }
  
  // Update all timer displays on the page
  function updateDisplay() {
    const elements = document.querySelectorAll('.alert-timer');
    if (!elements.length) return;
    
    // Check if timer should be visible based on notification mode
    const notificationMode = localStorage.getItem('notification_mode') || 'immediate';
    
    elements.forEach(el => {
      // Hide timer if mode is not batch (only show for periodic batch mode)
      if (notificationMode !== 'batch') {
        el.style.display = 'none';
        return;
      }
      
      el.style.display = 'block';
      const now = new Date();
      const remaining = nextAlertTime ? nextAlertTime - now : 0;
      
      if (remaining > 0) {
        el.innerHTML = `
          <i class="fa-solid fa-clock"></i> 
          Next batch alert in: <strong>${formatTimeRemaining(remaining)}</strong>
        `;
        el.style.color = '#9aa2ac';
      } else {
        el.innerHTML = `
          <i class="fa-solid fa-clock"></i> 
          Next batch alert: <strong>Due now</strong>
        `;
        el.style.color = '#FF9800';
      }
    });
  }
  
  // Start the countdown timer
  function startTimer() {
    if (timerInterval) {
      clearInterval(timerInterval);
    }
    
    loadTimerState();
    updateDisplay();
    
    // Update every second
    timerInterval = setInterval(() => {
      updateDisplay();
      
      // Check if time expired
      const now = new Date();
      if (nextAlertTime && now >= nextAlertTime) {
        // Timer expired - trigger batch webhook if in batch mode
        const notificationMode = localStorage.getItem('notification_mode') || 'immediate';
        if (notificationMode === 'batch') {
          sendBatchWebhook();
        }
        // Reset for next interval
        resetTimer();
      }
    }, 1000);
  }
  
  // Send batch webhook alert
  async function sendBatchWebhook() {
    console.log('Timer expired - sending batch webhook...');
    const apiKey = localStorage.getItem('api_key') || '';
    
    try {
      const res = await fetch('/api/alerts/send_batch', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': apiKey
        }
      });
      
      if (!res.ok) {
        const err = await res.json().catch(() => ({error: 'Unknown error'}));
        console.error('Batch webhook failed:', err.error || res.status);
        // Show notification if on alerts page
        const statusEl = document.getElementById('batchStatus');
        if (statusEl) {
          statusEl.textContent = 'Auto-alert failed: ' + (err.error || res.status);
          statusEl.style.color = '#f44336';
          setTimeout(() => { statusEl.textContent = ''; }, 5000);
        }
      } else {
        const data = await res.json();
        console.log('Batch webhook sent:', data);
        // Show success notification if on alerts page
        const statusEl = document.getElementById('batchStatus');
        if (statusEl) {
          statusEl.textContent = data.status || 'Batch alert sent successfully';
          statusEl.style.color = '#4CAF50';
          setTimeout(() => { statusEl.textContent = ''; }, 3000);
        }
      }
    } catch(e) {
      console.error('Error sending batch webhook:', e);
    }
  }
  
  // Stop the timer
  function stopTimer() {
    if (timerInterval) {
      clearInterval(timerInterval);
      timerInterval = null;
    }
  }
  
  // Public API
  window.AlertTimer = {
    start: startTimer,
    stop: stopTimer,
    reset: resetTimer,
    updateInterval: function(newIntervalMin) {
      resetTimer(newIntervalMin);
    }
  };
  
  // Auto-start when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', startTimer);
  } else {
    startTimer();
  }
})();
