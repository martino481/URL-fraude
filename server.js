const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors());
app.use(express.json());

const db = new sqlite3.Database(path.join(__dirname, 'urlguard.db'), (err) => {
  if (err) console.error('DB error:', err);
  else console.log('SQLite connected');
});

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL, hostname TEXT NOT NULL, score INTEGER NOT NULL, verdict TEXT NOT NULL,
    heuristic_score INTEGER, visual_score INTEGER,
    whois_years INTEGER, whois_registrar TEXT, whois_country TEXT, whois_privacy INTEGER,
    factors TEXT, ai_summary TEXT, ai_signals TEXT, is_clone INTEGER DEFAULT 0,
    cloned_brand TEXT, screenshot_url TEXT,
    analyzed_at TEXT DEFAULT (datetime('now')), ip_hash TEXT)`);
  db.run(`CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL, hostname TEXT NOT NULL, reason TEXT NOT NULL, details TEXT,
    reported_at TEXT DEFAULT (datetime('now')), ip_hash TEXT, status TEXT DEFAULT 'pending')`);
  db.run(`CREATE TABLE IF NOT EXISTS community_verdicts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL, hostname TEXT NOT NULL, vote TEXT NOT NULL,
    reported_at TEXT DEFAULT (datetime('now')), ip_hash TEXT)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_analyses_hostname ON analyses(hostname)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_reports_hostname ON reports(hostname)`);
});

function hashIP(ip) {
  return crypto.createHash('sha256').update(ip + 'urlguard_salt').digest('hex').slice(0, 16);
}
function getHostname(url) {
  try { if (!url.startsWith('http')) url = 'https://' + url; return new URL(url).hostname.toLowerCase(); }
  catch { return null; }
}
function dbGet(sql, params = []) {
  return new Promise((res, rej) => db.get(sql, params, (e, r) => e ? rej(e) : res(r)));
}
function dbAll(sql, params = []) {
  return new Promise((res, rej) => db.all(sql, params, (e, r) => e ? rej(e) : res(r)));
}
function dbRun(sql, params = []) {
  return new Promise((res, rej) => db.run(sql, params, function(e) { e ? rej(e) : res({ lastID: this.lastID }); }));
}

app.get('/', (req, res) => res.json({ status: 'ok', service: 'URLGuard API', version: '1.0.0' }));

app.post('/api/analyses', async (req, res) => {
  try {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
    const { url, score, verdict, heuristic_score, visual_score, whois, factors, ai_summary, ai_signals, is_clone, cloned_brand, screenshot_url } = req.body;
    if (!url || score === undefined) return res.status(400).json({ error: 'url and score required' });
    const hostname = getHostname(url);
    if (!hostname) return res.status(400).json({ error: 'Invalid URL' });
    const result = await dbRun(
      `INSERT INTO analyses (url,hostname,score,verdict,heuristic_score,visual_score,whois_years,whois_registrar,whois_country,whois_privacy,factors,ai_summary,ai_signals,is_clone,cloned_brand,screenshot_url,ip_hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      [url,hostname,score,verdict,heuristic_score??null,visual_score??null,whois?.years??null,whois?.registrar??null,whois?.country??null,whois?.privacy?1:0,factors?JSON.stringify(factors):null,ai_summary??null,ai_signals?JSON.stringify(ai_signals):null,is_clone?1:0,cloned_brand??null,screenshot_url??null,hashIP(ip)]
    );
    res.json({ id: result.lastID, message: 'Analysis saved' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/analyses', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit)||20, 100);
    const offset = parseInt(req.query.offset)||0;
    let q = 'SELECT * FROM analyses WHERE 1=1'; const p = [];
    if (req.query.hostname) { q += ' AND hostname LIKE ?'; p.push(`%${req.query.hostname}%`); }
    if (req.query.verdict) { q += ' AND verdict = ?'; p.push(req.query.verdict); }
    q += ' ORDER BY analyzed_at DESC LIMIT ? OFFSET ?'; p.push(limit, offset);
    const rows = await dbAll(q, p);
    const total = (await dbGet('SELECT COUNT(*) as count FROM analyses')).count;
    res.json({ data: rows.map(r => ({...r, factors: r.factors?JSON.parse(r.factors):[], ai_signals: r.ai_signals?JSON.parse(r.ai_signals):[], whois:{years:r.whois_years,registrar:r.whois_registrar,country:r.whois_country,privacy:!!r.whois_privacy}})), total, limit, offset });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/analyses/:id', async (req, res) => {
  try {
    const row = await dbGet('SELECT * FROM analyses WHERE id = ?', [req.params.id]);
    if (!row) return res.status(404).json({ error: 'Not found' });
    res.json({...row, factors: row.factors?JSON.parse(row.factors):[], ai_signals: row.ai_signals?JSON.parse(row.ai_signals):[]});
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/domains/:hostname', async (req, res) => {
  try {
    const hostname = req.params.hostname.toLowerCase();
    const analyses = await dbAll('SELECT score,verdict,analyzed_at FROM analyses WHERE hostname=? ORDER BY analyzed_at DESC LIMIT 50', [hostname]);
    if (!analyses.length) return res.status(404).json({ error: 'No data for this domain' });
    const avgScore = Math.round(analyses.reduce((s,r) => s+r.score,0)/analyses.length);
    const verdictCounts = analyses.reduce((acc,r) => { acc[r.verdict]=(acc[r.verdict]||0)+1; return acc; }, {});
    const reports = await dbGet('SELECT COUNT(*) as count FROM reports WHERE hostname=?', [hostname]);
    const communityVotes = await dbAll('SELECT vote,COUNT(*) as count FROM community_verdicts WHERE hostname=? GROUP BY vote', [hostname]);
    res.json({ hostname, total_analyses:analyses.length, avg_score:avgScore, verdict_counts:verdictCounts, report_count:reports.count, community_votes:communityVotes, last_analyzed:analyses[0]?.analyzed_at });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/reports', async (req, res) => {
  try {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
    const { url, reason, details } = req.body;
    if (!url || !reason) return res.status(400).json({ error: 'url and reason required' });
    if (!['phishing','malware','scam','spam','fake_brand','other'].includes(reason)) return res.status(400).json({ error: 'Invalid reason' });
    const hostname = getHostname(url);
    if (!hostname) return res.status(400).json({ error: 'Invalid URL' });
    const ipHash = hashIP(ip);
    const existing = await dbGet(`SELECT id FROM reports WHERE hostname=? AND ip_hash=? AND reported_at>datetime('now','-24 hours')`, [hostname,ipHash]);
    if (existing) return res.status(429).json({ error: 'Already reported in last 24h' });
    const result = await dbRun('INSERT INTO reports (url,hostname,reason,details,ip_hash) VALUES (?,?,?,?,?)', [url,hostname,reason,details||null,ipHash]);
    res.json({ id: result.lastID, message: 'Report submitted. Thank you!' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/reports', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit)||20, 100);
    const rows = await dbAll('SELECT id,url,hostname,reason,details,reported_at,status FROM reports ORDER BY reported_at DESC LIMIT ?', [limit]);
    const total = (await dbGet('SELECT COUNT(*) as c FROM reports')).c;
    res.json({ data: rows, total });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/votes', async (req, res) => {
  try {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
    const { url, vote } = req.body;
    if (!url || !['safe','unsafe'].includes(vote)) return res.status(400).json({ error: 'url and vote (safe|unsafe) required' });
    const hostname = getHostname(url);
    if (!hostname) return res.status(400).json({ error: 'Invalid URL' });
    const ipHash = hashIP(ip);
    const existing = await dbGet(`SELECT id FROM community_verdicts WHERE hostname=? AND ip_hash=? AND reported_at>datetime('now','-7 days')`, [hostname,ipHash]);
    if (existing) return res.status(429).json({ error: 'Already voted for this domain' });
    await dbRun('INSERT INTO community_verdicts (url,hostname,vote,ip_hash) VALUES (?,?,?,?)', [url,hostname,vote,ipHash]);
    const votes = await dbAll('SELECT vote,COUNT(*) as count FROM community_verdicts WHERE hostname=? GROUP BY vote', [hostname]);
    res.json({ message: 'Vote recorded', votes });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/stats', async (req, res) => {
  try {
    const total = (await dbGet('SELECT COUNT(*) as c FROM analyses')).c;
    const today = (await dbGet(`SELECT COUNT(*) as c FROM analyses WHERE analyzed_at>date('now')`)).c;
    const verdicts = await dbAll('SELECT verdict,COUNT(*) as c FROM analyses GROUP BY verdict');
    const topDomains = await dbAll('SELECT hostname,COUNT(*) as count,AVG(score) as avg_score FROM analyses GROUP BY hostname ORDER BY count DESC LIMIT 10');
    const reports = (await dbGet('SELECT COUNT(*) as c FROM reports')).c;
    const avgRow = await dbGet('SELECT AVG(score) as avg FROM analyses');
    res.json({ total_analyses:total, analyses_today:today, total_reports:reports, avg_score:Math.round(avgRow?.avg||0), verdicts:verdicts.reduce((acc,r)=>{acc[r.verdict]=r.c;return acc;},{}), top_domains:topDomains.map(d=>({...d,avg_score:Math.round(d.avg_score)})) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.listen(PORT, () => console.log(`URLGuard API running on port ${PORT}`));
