/* Enhanced Professional Dashboard */
document.addEventListener('DOMContentLoaded', ()=>{

  // Initialize dashboard
  initDashboard();
  
  // Tab management
  const tabs = document.querySelectorAll('.tab-btn');
  function showTab(n){
    document.querySelectorAll('.tab').forEach(t=>t.classList.add('hidden'));
    document.getElementById('tab-'+n).classList.remove('hidden');
    tabs.forEach(b=>b.classList.remove('active'));
    document.querySelector('.tab-btn[data-tab="'+n+'"]').classList.add('active');
    
    // Refresh data when switching to certain tabs
    if (n === 'home') loadOverview();
    if (n === 'docker') loadScanReports();
    if (n === 'van') loadVan();
    if (n === 'alerts') loadAlerts();
  }
  
  tabs.forEach(t=>t.addEventListener('click', ()=> showTab(t.dataset.tab)));
  showTab('home');

  // Dashboard initialization
  function initDashboard() {
    console.log('🚀 Initializing DevSecOps Dashboard...');
    updateDashboardStats();
    setInterval(updateDashboardStats, 30000); // Update every 30 seconds
  }

  // Helper functions
  async function jget(u){ 
    try{ 
      const r=await fetch(u); 
      return await r.json(); 
    } catch(e){ 
      console.error('API Error:', e);
      return null; 
    } 
  }
  
  function makeNvdLink(cve){ 
    return cve ? `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}` : '#'; 
  }

  function formatDate(dateString) {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  }

  // Dashboard Stats
  async function updateDashboardStats() {
    const overview = await jget('/api/overview');
    if (!overview) return;

    // Update stats grid
    const statsContainer = document.getElementById('statsGrid');
    if (statsContainer) {
      statsContainer.innerHTML = `
        <div class="stat-card">
          <div class="stat-number">${overview.alerts_count || 0}</div>
          <div class="stat-label">Active Alerts</div>
        </div>
        <div class="stat-card">
          <div class="stat-number">${overview.van ? (Object.values(overview.van).filter(v => v.ok === false).length) : 0}</div>
          <div class="stat-label">Host Issues</div>
        </div>
        <div class="stat-card">
          <div class="stat-number">${overview.last_scan ? '1' : '0'}</div>
          <div class="stat-label">Recent Scans</div>
        </div>
        <div class="stat-card">
          <div class="stat-number" style="font-size: 1.5rem;">${overview.host || 'N/A'}</div>
          <div class="stat-label">Server</div>
        </div>
      `;
    }
  }

  // Overview Page
  async function loadOverview(){
    const el = document.getElementById('overviewArea');
    el.innerHTML = `
      <div class="stats-grid" id="statsGrid">
        <div class="loading"></div>
      </div>
      <div class="card">
        <h3>📊 System Overview</h3>
        <div style="text-align: center; padding: 2rem;">
          <div class="loading"></div>
          <p>Loading system information...</p>
        </div>
      </div>
    `;
    
    const j = await jget('/api/overview');
    if (!j) {
      el.innerHTML = '<div class="alert">Failed to load overview</div>';
      return;
    }

    el.innerHTML = `
      <div class="stats-grid" id="statsGrid">
        <div class="stat-card">
          <div class="stat-number">${j.alerts_count || 0}</div>
          <div class="stat-label">Active Alerts</div>
        </div>
        <div class="stat-card">
          <div class="stat-number">${j.van ? (Object.values(j.van).filter(v => v.ok === false).length) : 0}</div>
          <div class="stat-label">Host Issues</div>
        </div>
        <div class="stat-card">
          <div class="stat-number">${j.last_scan ? '1' : '0'}</div>
          <div class="stat-label">Recent Scans</div>
        </div>
        <div class="stat-card">
          <div class="stat-number" style="font-size: 1.5rem;">${j.host || 'N/A'}</div>
          <div class="stat-label">Server</div>
        </div>
      </div>
      
      <div class="split">
        <div class="card">
          <h3>🖥️ Host Information</h3>
          ${j.van && j.van.host_os ? `
            <table class="data-table">
              <tr><td><strong>Platform</strong></td><td>${j.van.host_os.platform}</td></tr>
              <tr><td><strong>Hostname</strong></td><td>${j.van.host_os.hostname}</td></tr>
              <tr><td><strong>Architecture</strong></td><td>${j.van.host_os.arch}</td></tr>
              <tr><td><strong>CPU Cores</strong></td><td>${j.van.host_os.cpus}</td></tr>
            </table>
          ` : '<p>No host data available</p>'}
        </div>
        
        <div class="card">
          <h3>🔍 Last Scan</h3>
          ${j.last_scan ? `
            <table class="data-table">
              <tr><td><strong>Image</strong></td><td>${j.last_scan.image}</td></tr>
              <tr><td><strong>Scanned At</strong></td><td>${formatDate(j.last_scan.scanned_at)}</td></tr>
              <tr><td><strong>Trivy Status</strong></td><td><span class="${j.last_scan.trivy_ok ? 'ok' : 'alert'}">${j.last_scan.trivy_ok ? 'Success' : 'Failed'}</span></td></tr>
              <tr><td><strong>Grype Status</strong></td><td><span class="${j.last_scan.grype_ok ? 'ok' : 'alert'}">${j.last_scan.grype_ok ? 'Success' : 'Failed'}</span></td></tr>
            </table>
          ` : '<p>No scans performed yet</p>'}
        </div>
      </div>
    `;
  }

  // Docker Scan Page
  document.getElementById('scanImageBtn').addEventListener('click', async ()=>{
    const img = document.getElementById('imageInput').value.trim();
    if(!img) {
      showNotification('Please enter a Docker image name', 'warning');
      return;
    }
    
    const statusEl = document.getElementById('scanStatus');
    statusEl.innerHTML = '<div class="loading"></div> Scanning image (this may take a few minutes)...';
    
    try {
      const r = await fetch('/api/scan/docker',{
        method: 'POST', 
        headers: {'Content-Type': 'application/json'}, 
        body: JSON.stringify({image: img})
      });
      const j = await r.json();
      
      if (j.ok) {
        statusEl.innerHTML = '<span class="ok">✅ Scan started successfully! Loading results...</span>';
        setTimeout(loadScanReports, 2000);
      } else {
        statusEl.innerHTML = `<span class="alert">❌ Scan failed: ${j.error || 'Unknown error'}</span>`;
      }
    } catch (error) {
      statusEl.innerHTML = `<span class="alert">❌ Scan request failed: ${error.message}</span>`;
    }
  });

  async function loadScanReports(){
    // Show loading states
    document.querySelector('#trivyTable tbody').innerHTML = '<tr><td colspan="5" style="text-align: center;"><div class="loading"></div> Loading Trivy results...</td></tr>';
    document.querySelector('#grypeTable tbody').innerHTML = '<tr><td colspan="4" style="text-align: center;"><div class="loading"></div> Loading Grype results...</td></tr>';

    const tr = await jget('/api/scan/trivy-report');
    const gr = await jget('/api/scan/grype-report');
    
    fillTrivyTable(tr);
    fillGrypeTable(gr);
  }

  function fillTrivyTable(tr){
    const tbody = document.querySelector('#trivyTable tbody');
    if(!tr || !tr.Results){ 
      tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--secondary);">No Trivy results available</td></tr>'; 
      return; 
    }
    
    const filter = document.getElementById('trivySeverity').value || 'ALL';
    let vulnerabilities = [];
    
    tr.Results.forEach(r => {
      (r.Vulnerabilities || []).forEach(v => {
        vulnerabilities.push({...v, Target: r.Target});
      });
    });

    // Sort by severity
    vulnerabilities.sort((a, b) => {
      const severityOrder = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4};
      return severityOrder[a.Severity] - severityOrder[b.Severity];
    });

    tbody.innerHTML = '';
    
    if (vulnerabilities.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--success);">✅ No vulnerabilities found!</td></tr>';
      return;
    }

    vulnerabilities.forEach(v => {
      if(filter !== 'ALL' && v.Severity && v.Severity.toUpperCase() !== filter) return;
      
      const severityClass = `severity-${(v.Severity || 'unknown').toLowerCase()}`;
      const trEl = document.createElement('tr');
      trEl.innerHTML = `
        <td><strong>${v.Target || 'Unknown'}</strong></td>
        <td>${v.PkgName || v.Package || 'Unknown'}</td>
        <td><span class="severity-badge ${severityClass}">${v.Severity || 'UNKNOWN'}</span></td>
        <td>
          <a target="_blank" href="${makeNvdLink(v.VulnerabilityID)}" style="color: var(--primary); text-decoration: none;">
            ${v.VulnerabilityID || 'N/A'}
          </a>
        </td>
        <td title="${(v.Title || '').replace(/"/g,'')}">${(v.Title || '').slice(0,100)}${(v.Title || '').length > 100 ? '...' : ''}</td>
      `;
      tbody.appendChild(trEl);
    });
  }

  function fillGrypeTable(gr){
    const tbody = document.querySelector('#grypeTable tbody');
    if(!gr || !gr.matches){ 
      tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--secondary);">No Grype results available</td></tr>'; 
      return; 
    }
    
    const filter = document.getElementById('grypeSeverity').value || 'ALL';
    
    // Sort by severity
    gr.matches.sort((a, b) => {
      const severityOrder = {Critical: 0, High: 1, Medium: 2, Low: 3, Unknown: 4};
      return severityOrder[a.severity] - severityOrder[b.severity];
    });

    tbody.innerHTML = '';
    
    if (gr.matches.length === 0) {
      tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--success);">✅ No vulnerabilities found!</td></tr>';
      return;
    }

    gr.matches.forEach(m => {
      const sev = (m.severity || 'Unknown');
      if(filter !== 'ALL' && sev.toUpperCase() !== filter.toUpperCase()) return;
      
      const severityClass = `severity-${sev.toLowerCase()}`;
      const cve = (m.vulnerability || (m.match && m.match.vulnerability) || (m.vulnerability && m.vulnerability.id)) || '';
      const trEl = document.createElement('tr');
      trEl.innerHTML = `
        <td><strong>${(m.artifact && m.artifact.name) || (m.package && m.package.name) || 'Unknown'}</strong></td>
        <td><span class="severity-badge ${severityClass}">${sev}</span></td>
        <td>
          <a target="_blank" href="${makeNvdLink(cve)}" style="color: var(--primary); text-decoration: none;">
            ${cve || 'N/A'}
          </a>
        </td>
        <td title="${(m.advisory || '').toString().slice(0,400)}">
          ${(m.advisory || '').toString().slice(0,80)}${(m.advisory || '').toString().length > 80 ? '...' : ''}
        </td>
      `;
      tbody.appendChild(trEl);
    });
  }

  document.getElementById('trivySeverity').addEventListener('change', loadScanReports);
  document.getElementById('grypeSeverity').addEventListener('change', loadScanReports);
  document.getElementById('refreshScanSummary').addEventListener('click', loadScanReports);

  // VAN Page
  async function loadVan(){
    const tbody = document.querySelector('#vanTable tbody');
    tbody.innerHTML = '<tr><td colspan="3" style="text-align: center;"><div class="loading"></div> Loading host monitoring data...</td></tr>';
    
    const j = await jget('/api/van');
    if(!j || !j.results){ 
      tbody.innerHTML = '<tr><td colspan="3" style="text-align: center; color: var(--secondary);">No monitoring data available</td></tr>'; 
      return; 
    }
    
    tbody.innerHTML = '';
    const map = j.results;
    
    Object.keys(map).forEach(k=>{
      const v = map[k];
      const status = (v.ok || v.ok === undefined) ? 
        '<span class="ok">Healthy</span>' : 
        '<span class="alert">Attention Required</span>';
      
      const tr = document.createElement('tr');
      
      // Create user-friendly display
      let details = '';
      if (k === 'apt_update') {
        details = v.ok ? 
          `System updated ${Math.floor(v.age_seconds/3600)} hours ago` :
          'System updates required';
      } else if (k === 'ddos') {
        details = `${v.total_connections} connections (threshold: ${v.threshold})`;
      } else if (k === 'cpu') {
        details = `Load: ${v.load1} | Usage: ${v.cpu_percent_approx}% (threshold: ${v.threshold}%)`;
      } else if (k === 'disk') {
        details = `Usage: ${v.percent}% ${v.ok ? '' : '⚠️'}`;
      } else if (k === 'firewall') {
        details = v.ok ? 'Firewall is active' : 'Firewall is not active';
      } else {
        details = JSON.stringify(v, null, 2);
      }
      
      tr.innerHTML = `
        <td><strong>${getFriendlyName(k)}</strong></td>
        <td>${status}</td>
        <td>${details}</td>
      `;
      tbody.appendChild(tr);
    });
  }

  function getFriendlyName(key) {
    const names = {
      'apt_update': '🔄 System Updates',
      'host_os': '🖥️ Host Information', 
      'ddos': '🛡️ DDoS Protection',
      'cpu': '⚡ CPU Usage',
      'disk': '💾 Disk Space',
      'firewall': '🔥 Firewall Status'
    };
    return names[key] || key;
  }

  document.getElementById('refreshVan').addEventListener('click', loadVan);

  // DevSecOps Auto-Fix
  document.getElementById('devFixBtn').addEventListener('click', async () => {
    const img = document.getElementById('devImageInput').value.trim();
    const out = document.getElementById('devResult');
    if (!img) {
      showNotification('Please enter a Docker image name', 'warning');
      return;
    }

    out.innerHTML = '<div style="text-align: center;"><div class="loading"></div><br>🚀 Starting auto-fix process...</div>';

    try {
      const startRes = await fetch('/api/devsecops/fix-image', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ image: img })
      });
      const startData = await startRes.json();
      
      if (!startData.ok || !startData.taskId) {
        out.innerHTML = `<div style="color: var(--danger); text-align: center;">❌ Failed to start auto-fix</div>`;
        return;
      }

      const taskId = startData.taskId;
      out.innerHTML = '<div style="text-align: center;"><div class="loading"></div><br>⏳ Auto-fix in progress... This may take several minutes.</div>';

      const poll = async () => {
        const res = await fetch(`/api/devsecops/fix-result/${taskId}`);
        const j = await res.json();
        
        if (j.status === 'done' || j.status === 'error') {
          let resultHTML = '';
          if (j.status === 'done') {
            resultHTML = `
              <div style="color: var(--success); text-align: center; margin-bottom: 1rem;">
                <h3>✅ Auto-fix Completed Successfully!</h3>
              </div>
              <table class="data-table">
                <tr><td><strong>Original Image</strong></td><td>${j.image}</td></tr>
                <tr><td><strong>New Image</strong></td><td>${j.newImage || 'Not created'}</td></tr>
                <tr><td><strong>Completed At</strong></td><td>${formatDate(j.when)}</td></tr>
              </table>
            `;
          } else {
            resultHTML = `
              <div style="color: var(--danger); text-align: center; margin-bottom: 1rem;">
                <h3>❌ Auto-fix Failed</h3>
              </div>
              <div style="color: var(--danger);">Error: ${j.error || 'Unknown error'}</div>
            `;
          }

          // Add actions summary
          if (j.actions && j.actions.length > 0) {
            resultHTML += '<h4 style="margin-top: 1.5rem;">Actions Performed:</h4>';
            j.actions.forEach(action => {
              const icon = action.ok === false ? '❌' : '✅';
              resultHTML += `<div style="margin: 0.5rem 0;">${icon} ${action.action}</div>`;
            });
          }

          out.innerHTML = resultHTML;
        } else {
          setTimeout(poll, 3000);
        }
      };
      poll();
    } catch (err) {
      out.innerHTML = `<div style="color: var(--danger);">🔥 Request failed: ${err.message}</div>`;
    }
  });

  // Alerts Page
  async function loadAlerts(){
    const tbody = document.querySelector('#alertsTable tbody');
    tbody.innerHTML = '<tr><td colspan="7" style="text-align: center;"><div class="loading"></div> Loading alerts...</td></tr>';
    
    const j = await jget('/api/alerts');
    if(!j || !j.length){ 
      tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--success);">🎉 No active alerts! System is healthy.</td></tr>'; 
      return; 
    }
    
    tbody.innerHTML = '';
    j.forEach(a=>{
      const severityClass = `severity-${(a.severity || 'medium').toLowerCase()}`;
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><code>${a.id}</code></td>
        <td>${a.source || a.checker || 'Unknown'}</td>
        <td><span class="severity-badge ${severityClass}">${a.severity || 'MEDIUM'}</span></td>
        <td>${(a.summary || 'No description').slice(0,100)}${(a.summary || '').length > 100 ? '...' : ''}</td>
        <td>${formatDate(a.created_at)}</td>
        <td><span class="${a.status === 'open' ? 'alert' : 'ok'}">${a.status || 'open'}</span></td>
        <td><button class="btn" onclick="mitigateAlert('${a.id}')" style="padding: 0.5rem 1rem; font-size: 0.8rem;">Mitigate</button></td>
      `;
      tbody.appendChild(tr);
    });
  }
  
  window.mitigateAlert = async (id)=>{
    if (!confirm('Are you sure you want to mitigate this alert?')) return;
    
    const r = await fetch('/api/alerts/mitigate',{ 
      method: 'POST', 
      headers: {'Content-Type': 'application/json'}, 
      body: JSON.stringify({ id })
    });
    const j = await r.json();
    
    if (j.ok) {
      showNotification('Alert mitigated successfully!', 'success');
      loadAlerts();
    } else {
      showNotification('Failed to mitigate alert', 'error');
    }
  };
  
  document.getElementById('refreshAlerts').addEventListener('click', loadAlerts);

  // Chat Page
  const chatBox = document.getElementById('chatBox');
  function append(who, text){
    const d = document.createElement('div');
    d.className = who;
    d.innerHTML = `<b>${who}:</b> ${text}`;
    chatBox.appendChild(d);
    chatBox.scrollTop = chatBox.scrollHeight;
  }

  async function sendChat(){
    const txt = document.getElementById('chatInput').value.trim();
    if(!txt) return;
    
    append('You', txt);
    document.getElementById('chatInput').value = '';
    
    const r = await fetch('/api/chat', { 
      method: 'POST', 
      headers: {'Content-Type': 'application/json'}, 
      body: JSON.stringify({ message: txt })
    });
    const j = await r.json();
    append('Bot', j.reply || JSON.stringify(j));
  }
  
  document.getElementById('chatSend').addEventListener('click', sendChat);
  document.getElementById('chatInput').addEventListener('keypress', (e)=>{ 
    if(e.key==='Enter') sendChat(); 
  });

  // Notification system
  function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      padding: 1rem 1.5rem;
      border-radius: 12px;
      color: white;
      font-weight: 600;
      z-index: 10000;
      animation: slideInRight 0.3s ease;
      box-shadow: var(--shadow-lg);
    `;
    
    const colors = {
      success: 'var(--success)',
      error: 'var(--danger)', 
      warning: 'var(--warning)',
      info: 'var(--primary)'
    };
    
    notification.style.background = colors[type] || colors.info;
    notification.textContent = message;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
      notification.remove();
    }, 5000);
  }

  // Initial loads
  loadOverview();
  loadScanReports();
  loadVan();
  loadAlerts();
  
  // Add welcome message to chat
  setTimeout(() => {
    if (document.getElementById('tab-chat') && !document.getElementById('tab-chat').classList.contains('hidden')) {
      const chatBox = document.getElementById('chatBox');
      if (chatBox.children.length === 0) {
        const welcome = document.createElement('div');
        welcome.className = 'bot';
        welcome.innerHTML = `<b>Bot:</b> Hello! I'm your DevSecOps assistant. You can ask me to:<br>
        • "scan nginx:latest" - Scan a Docker image<br>
        • "show van" - Check server status<br>
        • "alerts" - View current alerts<br>
        How can I help you today?`;
        chatBox.appendChild(welcome);
      }
    }
  }, 1000);
});
