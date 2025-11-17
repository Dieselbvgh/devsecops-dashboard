/**
 * Enterprise DevSecOps Dashboard Backend
 */
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

const app = express();

// Security Middleware
app.use(helmet());
app.use(compression());
app.use(cors());
app.use(morgan('combined'));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

const PORT = Number(process.env.PORT || 5001);
const ENABLE_REAL_FIX = (process.env.ENABLE_REAL_FIX === 'true');
const DATA_DIR = path.join(__dirname, 'data');
const LOGS_DIR = path.join(__dirname, 'logs');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(LOGS_DIR)) fs.mkdirSync(LOGS_DIR, { recursive: true });

const TRIVY_PATH = path.join('/tmp','trivy_reports','trivy-last.json');
const GRYPE_PATH = path.join('/tmp','grype_reports','grype-last.json');
try { fs.mkdirSync(path.dirname(TRIVY_PATH), { recursive: true }); } catch(e){}
try { fs.mkdirSync(path.dirname(GRYPE_PATH), { recursive: true }); } catch(e){}

const ALERTS_FILE = path.join(DATA_DIR, 'alerts.json');
if (!fs.existsSync(ALERTS_FILE)) fs.writeFileSync(ALERTS_FILE, JSON.stringify([], null, 2));

function log(msg){
  const line = `[${new Date().toISOString()}] ${msg}\n`;
  fs.appendFileSync(path.join(LOGS_DIR,'server.log'), line);
  console.log(line.trim());
}
function safeExec(cmd, opts = {}) {
  return new Promise(resolve => {
    exec(cmd, Object.assign({ maxBuffer: 1024*1024*20, timeout: 1000*60*10 }, opts), (err, stdout, stderr) => {
      resolve({ ok: !err, code: err && err.code ? err.code : 0, stdout: (stdout||'').toString(), stderr: (stderr||'').toString() });
    });
  });
}
function readAlerts(){ try { return JSON.parse(fs.readFileSync(ALERTS_FILE,'utf8')); } catch(e){ return []; } }
function writeAlerts(a){ fs.writeFileSync(ALERTS_FILE, JSON.stringify(a,null,2)); }

function pushAlert(obj){
  const alerts = readAlerts();
  const a = Object.assign({ id: Date.now().toString(36)+'-'+Math.floor(Math.random()*9999), created_at: new Date().toISOString(), status:'open' }, obj);
  alerts.unshift(a);
  writeAlerts(alerts);
  log('ALERT: '+(a.id)+' '+(a.summary||''));
  return a;
}

// VAN checks
async function checkAptUpdate(){
  try {
    const stamp = '/var/lib/apt/periodic/update-success-stamp';
    if (fs.existsSync(stamp)){
      const st = fs.statSync(stamp);
      const age = Math.floor((Date.now() - st.mtimeMs)/1000);
      return { ok: age < 86400, path: stamp, age_seconds: age };
    } else return { ok:false, reason:'stamp-not-found' };
  } catch(e){ return { ok:false, reason:String(e)}; }
}

async function checkHostOS(){
  return { platform: os.platform(), release: os.release(), arch: os.arch(), cpus: os.cpus().length, hostname: os.hostname() };
}

async function checkDDoS(){
  try {
    const totalCmd = "ss -tn state established | sed -n '2,$p' | wc -l";
    const r = await safeExec(totalCmd);
    const total = parseInt((r.stdout||'0').trim()||'0',10);
    const threshold = Number(process.env.DDOS_THRESHOLD_TOTAL || 150);
    const ok = total < threshold;
    if (!ok) pushAlert({ source:'van', checker:'ddos', severity:'high', summary:`DDoS suspected: ${total} established connections` });
    return { ok, total_connections: total, threshold };
  } catch(e){ return { ok:false, error:String(e) }; }
}

async function checkCPU(){
  const load1 = os.loadavg()[0] || 0;
  const cores = Math.max(1, os.cpus().length);
  const cpuPercent = Math.round((load1/cores)*100);
  const threshold = Number(process.env.CPU_THRESHOLD_PERCENT || 80);
  const ok = cpuPercent < threshold;
  if (!ok) pushAlert({ source:'van', checker:'cpu', severity:'high', summary:`High CPU approx ${cpuPercent}%` });
  return { ok, load1, cores, cpu_percent_approx:cpuPercent, threshold };
}

async function checkDisk(){
  try {
    const r = await safeExec("df -h / | awk 'NR==2{print $5}'");
    const pct = parseInt((r.stdout||'0').replace('%','')||'0',10);
    const ok = pct < 85;
    if (!ok) pushAlert({ source:'van', checker:'disk', severity:'high', summary:`Disk usage ${pct}%` });
    return { ok, percent: pct };
  } catch(e){ return { ok:false, error:String(e) }; }
}

async function checkFirewall(){
  try {
    const r = await safeExec("sudo ufw status | grep -i active || true");
    const ok = (r.stdout||'').toLowerCase().includes('active');
    if (!ok) pushAlert({ source:'van', checker:'firewall', severity:'medium', summary:'Firewall not active' });
    return { ok, stdout: r.stdout || r.stderr };
  } catch(e){ return { ok:false, error:String(e) }; }
}

async function runAllVan(){
  const out = {
    apt_update: await checkAptUpdate(),
    host_os: await checkHostOS(),
    ddos: await checkDDoS(),
    cpu: await checkCPU(),
    disk: await checkDisk(),
    firewall: await checkFirewall(),
    timestamp: new Date().toISOString()
  };
  try { fs.writeFileSync(path.join(DATA_DIR,'van_cache.json'), JSON.stringify(out,null,2)); } catch(e){}
  return out;
}

app.get('/api/van', async (req,res) => {
  try {
    const r = await runAllVan();
    res.json({ ok:true, results: r });
  } catch(e){ res.status(500).json({ error: String(e) }); }
});

// Docker scans
app.post('/api/scan/docker', async (req, res) => {
  const image = req.body && req.body.image ? req.body.image.trim() : null;
  if (!image) return res.status(400).json({ error:'image required' });
  log(`Start scan for ${image}`);

  const trivyCmd = `trivy image --skip-update --quiet -f json -o ${TRIVY_PATH} ${image}`;
  const tr = await safeExec(trivyCmd);
  if (!tr.ok) log('trivy err: '+(tr.stderr||tr.stdout).slice(0,400));

  let gr = await safeExec(`grype ${image} -o json`);
  if (gr.ok && gr.stdout) {
    try { fs.writeFileSync(GRYPE_PATH, gr.stdout); } catch(e){ log('write grype out err:'+e); }
  } else {
    log('grype err: '+(gr.stderr||gr.stdout).slice(0,400));
  }

  const summary = { image, trivy_ok: tr.ok, grype_ok: gr.ok, scanned_at: new Date().toISOString() };
  try { fs.writeFileSync(path.join(DATA_DIR,'last_docker_scan.json'), JSON.stringify(summary,null,2)); } catch(e){}

  try {
    let crits = 0;
    if (fs.existsSync(TRIVY_PATH)){
      const tj = JSON.parse(fs.readFileSync(TRIVY_PATH,'utf8'));
      (tj.Results||[]).forEach(r => (r.Vulnerabilities||[]).forEach(v => { if ((v.Severity||'').toUpperCase()==='CRITICAL') crits++; }));
    }
    if (fs.existsSync(GRYPE_PATH)){
      const gj = JSON.parse(fs.readFileSync(GRYPE_PATH,'utf8'));
      (gj.matches||[]).forEach(m => { if ((m.severity||'').toUpperCase()==='critical') crits++; });
    }
    if (crits>0) pushAlert({ source:'docker-scan', checker:'vuln', severity:'high', summary:`${crits} critical vuln(s) in ${image}`, image });
  } catch(e){ log('alert parse err:'+e); }

  res.json({ ok:true, image, trivy: tr.ok, grype: gr.ok });
});

app.get('/api/scan/trivy-report', (req,res) => {
  if (!fs.existsSync(TRIVY_PATH)) return res.status(404).json({ found:false });
  try { return res.type('json').send(fs.readFileSync(TRIVY_PATH,'utf8')); } catch(e){ res.status(500).json({ error:String(e) }); }
});
app.get('/api/scan/grype-report', (req,res) => {
  if (!fs.existsSync(GRYPE_PATH)) return res.status(404).json({ found:false });
  try { return res.type('json').send(fs.readFileSync(GRYPE_PATH,'utf8')); } catch(e){ res.status(500).json({ error:String(e) }); }
});
app.get('/api/scan/last-summary', (req,res) => {
  const f = path.join(DATA_DIR,'last_docker_scan.json');
  if (!fs.existsSync(f)) return res.json({ ok:true, note:'no-scan' });
  res.json(JSON.parse(fs.readFileSync(f,'utf8')));
});

// DevSecOps auto-fix
const fixTasks = {};
app.post('/api/devsecops/fix-image', (req, res) => {
  const image = req.body?.image?.trim();
  if (!image) return res.status(400).json({ error: 'image required' });

  const taskId = `task-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
  fixTasks[taskId] = {
    image,
    actions: [],
    status: 'running',
    when: new Date().toISOString()
  };

  res.json({ ok: true, message: 'Auto-fix started', taskId });

  (async () => {
    const out = fixTasks[taskId];
    try {
      if (ENABLE_REAL_FIX) {
        const pull = await safeExec(`docker pull ${image}`);
        out.actions.push({ action: 'docker pull', ok: pull.ok });

        const cidRes = await safeExec(`docker create ${image}`);
        const cid = cidRes.ok ? cidRes.stdout.trim() : null;

        if (cid) {
          out.actions.push({ action: 'create container', id: cid });

          const execUp = await safeExec(
            `docker start ${cid} >/dev/null && docker exec ${cid} bash -c "apt-get update && apt-get upgrade -y"`,
            { timeout: 1000 * 60 * 10 }
          ).catch(() => ({ ok: false }));
          out.actions.push({ action: 'container apt upgrade', ok: execUp.ok });

          const newTag = `${image}-hardened-${Date.now()}`;
          const commit = await safeExec(`docker commit ${cid} ${newTag}`);
          out.actions.push({ action: 'docker commit', ok: commit.ok, newImage: newTag });
          out.newImage = newTag;

          await safeExec(`docker rm -f ${cid}`);
        } else {
          out.actions.push({ action: 'create container', ok: false, note: 'could not create container' });
        }

        const fileName = `fix-${Date.now()}.json`;
        fs.writeFileSync(path.join(DATA_DIR, fileName), JSON.stringify(out, null, 2));
        out.resultFile = fileName;
      }

      out.status = 'done';
    } catch (e) {
      out.status = 'error';
      out.error = String(e);
    }
  })();
});

app.get('/api/devsecops/fix-result/:taskId', (req, res) => {
  const taskId = req.params.taskId;
  const task = fixTasks[taskId];
  if (!task) return res.status(404).json({ error: 'Task not found' });
  res.json(task);
});

// Alerts + mitigation
app.get('/api/alerts', (req,res) => { res.json(readAlerts()); });

app.post('/api/alerts/mitigate', async (req,res) => {
  const { id } = req.body || {};
  const alerts = readAlerts();
  let a = null;
  if (id) a = alerts.find(x => x.id === id);
  else a = alerts[0];
  if (!a) return res.status(404).json({ error:'no alert found' });

  log('Mitigation requested for alert '+a.id+' real='+ENABLE_REAL_FIX);

  const results = [];
  try {
    if (a.checker === 'ddos') {
      if (ENABLE_REAL_FIX) {
        const uf = await safeExec('sudo ufw --force enable');
        results.push({ action:'ufw enable', ok: uf.ok, out: uf.stdout.slice(0,400) });
      } else results.push({ action:'suggest', note:'Enable ufw, add rate-limiting, investigate heavy IPs' });
    } else if (a.checker === 'cpu' || a.checker === 'load') {
      if (ENABLE_REAL_FIX) {
        const ps = await safeExec("ps -eo pid,comm,%cpu --sort=-%cpu | head -n 6");
        results.push({ action:'top-cpu', out: ps.stdout.slice(0,800) });
      } else results.push({ action:'suggest', note:'Investigate top CPU processes; consider restarting service or scaling resources' });
    } else if (a.source === 'docker-scan' || a.checker === 'vuln') {
      if (ENABLE_REAL_FIX) {
        const pull = await safeExec(`docker pull ${a.image || ''}`);
        results.push({ action:'docker pull', ok: pull.ok, out: (pull.stdout||'') });
      } else results.push({ action:'suggest', note:'Pull image and run trivy/grype; rebuild with patched base' });
    } else {
      results.push({ action:'noop', note:'No automated mitigation defined for this alert type' });
    }
  } catch(e){ results.push({ action:'error', error:String(e) }); }

  a.status = 'mitigated';
  a.mitigated_at = new Date().toISOString();
  a.mitigation = results;
  writeAlerts(alerts);

  res.json({ ok:true, alert: a, results });
});

// Chat endpoint
app.post('/api/chat', async (req,res) => {
  const text = (req.body && req.body.message) ? req.body.message.toString().trim() : '';
  if (!text) return res.json({ reply: "Say something — I'm listening." });
  const t = text.toLowerCase();

  if (/^(hi|hello|hey|salut|سلام|مرحبا)/i.test(t)) return res.json({ reply: "Hello! I'm your DevSecOps assistant. Ask me to 'scan <image>' or 'show van' or 'alerts'." });
  if (t.includes('how are you')) return res.json({ reply: "I'm a dashboard assistant — ready to scan and mitigate." });

  if (t.startsWith('scan ') || t.includes('scan image') || t.includes('scan')) {
    const m = t.match(/([a-z0-9\/\-\._:]+:[a-z0-9\-\._]+|[a-z0-9\/\-\._]+:[a-z0-9\-\._]+)/i);
    if (m && m[0]) {
      const image = m[0];
      (async ()=> {
        try {
          await safeExec(`trivy image --skip-update --quiet -f json -o ${TRIVY_PATH} ${image}`);
          const gr = await safeExec(`grype ${image} -o json`);
          if (gr.ok && gr.stdout) fs.writeFileSync(GRYPE_PATH, gr.stdout);
          pushAlert({ source:'docker-scan', checker:'scan', summary:`Scanned ${image} via chat`, image });
        } catch(e){ log('chat-scan err:'+e); }
      })();
      return res.json({ reply: `Started scan for ${image}. Use Docker Scan tab to see results.` });
    } else {
      return res.json({ reply: "Tell me the image name e.g. 'scan nginx:latest'." });
    }
  }

  if (t.includes('van')) {
    const v = await runAllVan();
    return res.json({ reply: "VAN snapshot: " + JSON.stringify(v).slice(0,500) });
  }
  if (t.includes('alerts')) {
    const alerts = readAlerts();
    return res.json({ reply: `There are ${alerts.length} alert(s).` });
  }

  return res.json({ reply: `I understood: "${text}". You can ask me to 'scan <image>', 'show van', or 'alerts'.` });
});

app.get('/api/overview', async (req,res) => {
  const van = await runAllVan().catch(()=>null);
  const scan = fs.existsSync(path.join(DATA_DIR,'last_docker_scan.json')) ? JSON.parse(fs.readFileSync(path.join(DATA_DIR,'last_docker_scan.json'),'utf8')) : null;
  res.json({ ok:true, host: os.hostname(), van, last_scan: scan, alerts_count: readAlerts().length });
});

app.get('/health', (req,res) => res.json({ ok:true }));

app.listen(PORT, () => {
  log('Server started on port '+PORT+' (ENABLE_REAL_FIX='+ENABLE_REAL_FIX+')');
  console.log('Open http://localhost:'+PORT);
});
