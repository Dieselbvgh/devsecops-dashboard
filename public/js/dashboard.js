/* UI glue for dashboard */
document.addEventListener('DOMContentLoaded', ()=>{

  // tabs
  const tabs = document.querySelectorAll('.tab-btn');
  function showTab(n){
    document.querySelectorAll('.tab').forEach(t=>t.classList.add('hidden'));
    document.getElementById('tab-'+n).classList.remove('hidden');
    tabs.forEach(b=>b.classList.remove('active'));
    document.querySelector('.tab-btn[data-tab="'+n+'"]').classList.add('active');
  }
  tabs.forEach(t=>t.addEventListener('click', ()=> showTab(t.dataset.tab)));
  showTab('home');

  // helpers
  async function jget(u){ try{ const r=await fetch(u); return await r.json(); } catch(e){ return null; } }
  function makeNvdLink(cve){ return cve ? `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}` : '#'; }

  // Overview
  async function loadOverview(){
    const el = document.getElementById('overviewArea');
    el.innerText = 'Loading...';
    const j = await jget('/api/overview');
    el.innerHTML = `<pre>${JSON.stringify(j,null,2)}</pre>`;
  }
  document.getElementById('refreshOverview').addEventListener('click', loadOverview);

  // Docker scan
  document.getElementById('scanImageBtn').addEventListener('click', async ()=>{
    const img = document.getElementById('imageInput').value.trim();
    if(!img) return alert('Enter image');
    document.getElementById('scanStatus').innerText = 'Scanning (may take >1m)...';
    const r = await fetch('/api/scan/docker',{method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({image:img})});
    const j = await r.json();
    document.getElementById('scanStatus').innerText = 'Scan started: ' + JSON.stringify(j).slice(0,200);
    await loadScanReports();
  });

  async function loadScanReports(){
    // trivy
    const tr = await jget('/api/scan/trivy-report');
    const gr = await jget('/api/scan/grype-report');
    fillTrivyTable(tr);
    fillGrypeTable(gr);
  }

  function fillTrivyTable(tr){
    const tbody = document.querySelector('#trivyTable tbody');
    tbody.innerHTML = '';
    if(!tr || !tr.Results){ tbody.innerHTML = '<tr><td colspan=5>No results</td></tr>'; return; }
    const filter = document.getElementById('trivySeverity').value || 'ALL';
    tr.Results.forEach(r=>{
      (r.Vulnerabilities||[]).forEach(v=>{
        if(filter!=='ALL' && v.Severity && v.Severity.toUpperCase()!==filter) return;
        const trEl = document.createElement('tr');
        trEl.innerHTML = `<td>${r.Target||''}</td><td>${v.PkgName||v.Package||''}</td><td>${v.Severity||''}</td>
          <td><a target="_blank" href="${makeNvdLink(v.VulnerabilityID)}">${v.VulnerabilityID||''}</a></td>
          <td title="${(v.Title||'').replace(/"/g,'') }">${(v.Title||'').slice(0,120)}</td>`;
        tbody.appendChild(trEl);
      });
    });
  }

  function fillGrypeTable(gr){
    const tbody = document.querySelector('#grypeTable tbody');
    tbody.innerHTML = '';
    if(!gr || !gr.matches){ tbody.innerHTML = '<tr><td colspan=4>No results</td></tr>'; return; }
    const filter = document.getElementById('grypeSeverity').value || 'ALL';
    gr.matches.forEach(m=>{
      const sev = (m.severity||'').toUpperCase();
      if(filter!=='ALL' && sev !== filter) return;
      const cve = (m.vulnerability || (m.match && m.match.vulnerability) || (m.vulnerability && m.vulnerability.id)) || '';
      const trEl = document.createElement('tr');
      trEl.innerHTML = `<td>${(m.artifact && (m.artifact.name||m.artifact.version)) || (m.package && m.package.name) || ''}</td>
        <td>${sev}</td>
        <td><a target="_blank" href="${makeNvdLink(cve)}">${cve||''}</a></td>
        <td title="${(m.advisory||'').toString().slice(0,400)}">${(m.advisory||'').toString().slice(0,120)}</td>`;
      tbody.appendChild(trEl);
    });
  }

  document.getElementById('trivySeverity').addEventListener('change', loadScanReports);
  document.getElementById('grypeSeverity').addEventListener('change', loadScanReports);
  document.getElementById('refreshScanSummary').addEventListener('click', loadScanReports);

  // VAN
  async function loadVan(){
    const j = await jget('/api/van');
    const tbody = document.querySelector('#vanTable tbody');
    tbody.innerHTML = '';
    if(!j || !j.results){ tbody.innerHTML = '<tr><td colspan=3>No data</td></tr>'; return; }
    const map = j.results;
    Object.keys(map).forEach(k=>{
      const v = map[k];
      const status = (v.ok || v.ok===undefined) ? '<span class="ok">OK</span>' : '<span class="alert">Alert</span>';
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${k}</td><td>${status}</td><td><pre>${JSON.stringify(v,null,2)}</pre></td>`;
      tbody.appendChild(tr);
    });
  }
  document.getElementById('refreshVan').addEventListener('click', loadVan);

// DevSecOps Auto-Fix
document.getElementById('devFixBtn').addEventListener('click', async () => {
  const img = document.getElementById('devImageInput').value.trim();
  const out = document.getElementById('devResult');
  if (!img) return alert('Enter image');

  out.textContent = `⏳ Requesting auto-fix for ${img} (this may take several minutes)...`;

  try {
    const startRes = await fetch('/api/devsecops/fix-image', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ image: img })
    });
    const startData = await startRes.json();
    if (!startData.ok || !startData.taskId) {
      out.textContent = `❌ Failed to start auto-fix:\n${JSON.stringify(startData, null, 2)}`;
      return;
    }

    const taskId = startData.taskId;
    out.textContent = `⏳ Auto-fix started (task ${taskId})... polling for result.`;

    const poll = async () => {
      const res = await fetch(`/api/devsecops/fix-result/${taskId}`);
      const j = await res.json();
      if (j.status === 'done' || j.status === 'error') {
        let summary = j.status === 'done' ? '✅ Auto-fix completed successfully!\n\n' : '❌ Auto-fix failed\n\n';
        summary += `🖼️ Image: ${j.image}\n`;
        summary += `🆕 New image: ${j.newImage || '(none)'}\n`;
        summary += `📄 Saved file: ${j.resultFile || '(none)'}\n`;
        summary += `🕒 When: ${j.when}\n\n`;
        if (Array.isArray(j.actions)) {
          summary += 'Actions:\n';
          j.actions.forEach(a => {
            const mark = a.ok === false ? '❌' : '✅';
            summary += `${mark} ${a.action}`;
            if (a.newImage) summary += ` → ${a.newImage}`;
            summary += '\n';
          });
        }
        if (j.error) summary += `\nError: ${j.error}`;
        out.textContent = summary;
      } else {
        out.textContent = `⏳ Auto-fix in progress... (task ${taskId})`;
        setTimeout(poll, 3000);
      }
    };
    poll();
  } catch (err) {
    out.textContent = `🔥 Request failed: ${err.message}`;
  }
});

  // Alerts page
  async function loadAlerts(){
    const j = await jget('/api/alerts');
    const tbody = document.querySelector('#alertsTable tbody');
    tbody.innerHTML = '';
    if(!j || !j.length){ tbody.innerHTML = '<tr><td colspan=7>No alerts</td></tr>'; return; }
    j.forEach(a=>{
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${a.id}</td><td>${a.source||a.checker||''}</td><td>${a.severity||''}</td>
        <td>${(a.summary||'').slice(0,120)}</td><td>${a.created_at||''}</td><td>${a.status||''}</td>
        <td><button onclick="mitigateAlert('${a.id}')">Mitigate</button></td>`;
      tbody.appendChild(tr);
    });
  }
  window.mitigateAlert = async (id)=>{
    const r = await fetch('/api/alerts/mitigate',{ method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ id })});
    const j = await r.json();
    alert('Mitigation done: ' + (j.ok ? 'OK' : JSON.stringify(j)));
    loadAlerts();
  };
  document.getElementById('refreshAlerts').addEventListener('click', loadAlerts);

  // Chat
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
    const r = await fetch('/api/chat', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ message: txt })});
    const j = await r.json();
    append('Bot', j.reply || JSON.stringify(j));
  }
  document.getElementById('chatSend').addEventListener('click', sendChat);
  document.getElementById('chatInput').addEventListener('keypress', (e)=>{ if(e.key==='Enter') sendChat(); });

  // initial loads
  loadOverview();
  loadScanReports();
  loadVan();
  loadAlerts();
});
