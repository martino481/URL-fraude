const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors());
app.use(express.json());

// ─── DATABASE SETUP ───────────────────────────────────────────────────────────
const db = new Database(path.join(__dirname, 'urlguard.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    hostname TEXT NOT NULL,
    score INTEGER NOT NULL,
    verdict TEXT NOT NULL,
    heuristic_score INTEGER,
    visual_score INTEGER,
    whois_years INTEGER,
    whois_registrar TEXT,
    whois_country TEXT,
    whois_privacy INTEGER,
    factors TEXT,
    ai_summary TEXT,
    ai_signals TEXT,
    is_clone INTEGER DEFAULT 0,
    cloned_brand TEXT,
    screenshot_url TEXT,
    analyzed_at TEXT DEFAULT (datetime('now')),
    ip_hash TEXT
  );

  CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    hostname TEXT NOT NULL,
    reason TEXT NOT NULL,
    details TEXT,
    reported_at TEXT DEFAULT (datetime('now')),
    ip_hash TEXT,
    status TEXT DEFAULT 'pending'
  );

  CREATE TABLE IF NOT EXISTS community_verdicts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    hostname TEXT NOT NULL,
    vote TEXT NOT NULL,
    reported_at TEXT DEFAULT (datetime('now')),
    ip_hash TEXT
  );

  CREATE INDEX IF NOT EXISTS idx_analyses_hostname ON analyses(hostname);
  CREATE INDEX IF NOT EXISTS idx_analyses_analyzed_at ON analyses(analyzed_at);
  CREATE INDEX IF NOT EXISTS idx_reports_hostname ON reports(hostname);
`);

// ─── HELPERS ──────────────────────────────────────────────────────────────────
function hashIP(ip) {
  return crypto.createHash('sha256').update(ip + 'urlguard_salt').digest('hex').slice(0, 16);
}

function getHostname(url) {
  try {
    if (!url.startsWith('http')) url = 'https://' + url;
    return new URL(url).hostname.toLowerCase();
  } catch { return null; }
}

// ─── API ROUTES ───────────────────────────────────────────────────────────────

// POST /api/analyses — Save an analysis result
app.post('/api/analyses', (req, res) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
  const {
    url, score, verdict, heuristic_score, visual_score,
    whois, factors, ai_summary, ai_signals, is_clone,
    cloned_brand, screenshot_url
  } = req.body;

  if (!url || score === undefined) {
    return res.status(400).json({ error: 'url and score are required' });
  }

  const hostname = getHostname(url);
  if (!hostname) return res.status(400).json({ error: 'Invalid URL' });

  const stmt = db.prepare(`
    INSERT INTO analyses (
      url, hostname, score, verdict, heuristic_score, visual_score,
      whois_years, whois_registrar, whois_country, whois_privacy,
      factors, ai_summary, ai_signals, is_clone, cloned_brand,
      screenshot_url, ip_hash
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const result = stmt.run(
    url, hostname, score, verdict, heuristic_score ?? null, visual_score ?? null,
    whois?.years ?? null, whois?.registrar ?? null, whois?.country ?? null,
    whois?.privacy ? 1 : 0,
    factors ? JSON.stringify(factors) : null,
    ai_summary ?? null,
    ai_signals ? JSON.stringify(ai_signals) : null,
    is_clone ? 1 : 0, cloned_brand ?? null,
    screenshot_url ?? null,
    hashIP(ip)
  );

  res.json({ id: result.lastInsertRowid, message: 'Analysis saved' });
});

// GET /api/analyses — List recent analyses
app.get('/api/analyses', (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 20, 100);
  const offset = parseInt(req.query.offset) || 0;
  const hostname = req.query.hostname;
  const verdict = req.query.verdict;

  let query = 'SELECT * FROM analyses WHERE 1=1';
  const params = [];

  if (hostname) { query += ' AND hostname LIKE ?'; params.push(`%${hostname}%`); }
  if (verdict) { query += ' AND verdict = ?'; params.push(verdict); }

  query += ' ORDER BY analyzed_at DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);

  const rows = db.prepare(query).all(...params);
  const total = db.prepare('SELECT COUNT(*) as count FROM analyses').get().count;

  res.json({
    data: rows.map(r => ({
      ...r,
      factors: r.factors ? JSON.parse(r.factors) : [],
      ai_signals: r.ai_signals ? JSON.parse(r.ai_signals) : [],
      whois: {
        years: r.whois_years,
        registrar: r.whois_registrar,
        country: r.whois_country,
        privacy: !!r.whois_privacy
      }
    })),
    total,
    limit,
    offset
  });
});

// GET /api/analyses/:id — Get single analysis
app.get('/api/analyses/:id', (req, res) => {
  const row = db.prepare('SELECT * FROM analyses WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Not found' });
  res.json({
    ...row,
    factors: row.factors ? JSON.parse(row.factors) : [],
    ai_signals: row.ai_signals ? JSON.parse(row.ai_signals) : []
  });
});

// GET /api/domains/:hostname — Domain reputation summary
app.get('/api/domains/:hostname', (req, res) => {
  const hostname = req.params.hostname.toLowerCase();

  const analyses = db.prepare(`
    SELECT score, verdict, analyzed_at FROM analyses
    WHERE hostname = ? ORDER BY analyzed_at DESC LIMIT 50
  `).all(hostname);

  if (!analyses.length) return res.status(404).json({ error: 'No data for this domain' });

  const avgScore = Math.round(analyses.reduce((s, r) => s + r.score, 0) / analyses.length);
  const verdictCounts = analyses.reduce((acc, r) => {
    acc[r.verdict] = (acc[r.verdict] || 0) + 1;
    return acc;
  }, {});

  const reports = db.prepare(`
    SELECT COUNT(*) as count FROM reports WHERE hostname = ? AND status != 'dismissed'
  `).get(hostname);

  const communityVotes = db.prepare(`
    SELECT vote, COUNT(*) as count FROM community_verdicts
    WHERE hostname = ? GROUP BY vote
  `).all(hostname);

  res.json({
    hostname,
    total_analyses: analyses.length,
    avg_score: avgScore,
    verdict_counts: verdictCounts,
    report_count: reports.count,
    community_votes: communityVotes,
    last_analyzed: analyses[0]?.analyzed_at,
    recent: analyses.slice(0, 5)
  });
});

// POST /api/reports — Submit a community report
app.post('/api/reports', (req, res) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
  const { url, reason, details } = req.body;

  if (!url || !reason) return res.status(400).json({ error: 'url and reason are required' });

  const validReasons = ['phishing', 'malware', 'scam', 'spam', 'fake_brand', 'other'];
  if (!validReasons.includes(reason)) return res.status(400).json({ error: 'Invalid reason' });

  const hostname = getHostname(url);
  if (!hostname) return res.status(400).json({ error: 'Invalid URL' });

  const ipHash = hashIP(ip);
  const existing = db.prepare(`
    SELECT id FROM reports WHERE hostname = ? AND ip_hash = ?
    AND reported_at > datetime('now', '-24 hours')
  `).get(hostname, ipHash);

  if (existing) return res.status(429).json({ error: 'Already reported in last 24h' });

  const result = db.prepare(`
    INSERT INTO reports (url, hostname, reason, details, ip_hash)
    VALUES (?, ?, ?, ?, ?)
  `).run(url, hostname, reason, details || null, ipHash);

  res.json({ id: result.lastInsertRowid, message: 'Report submitted. Thank you!' });
});

// GET /api/reports — List reports (public, anonymized)
app.get('/api/reports', (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 20, 100);
  const rows = db.prepare(`
    SELECT id, url, hostname, reason, details, reported_at, status
    FROM reports ORDER BY reported_at DESC LIMIT ?
  `).all(limit);
  res.json({ data: rows, total: db.prepare('SELECT COUNT(*) as c FROM reports').get().c });
});

// POST /api/votes — Community vote on a domain
app.post('/api/votes', (req, res) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
  const { url, vote } = req.body;

  if (!url || !['safe', 'unsafe'].includes(vote)) {
    return res.status(400).json({ error: 'url and vote (safe|unsafe) required' });
  }

  const hostname = getHostname(url);
  if (!hostname) return res.status(400).json({ error: 'Invalid URL' });

  const ipHash = hashIP(ip);
  const existing = db.prepare(`
    SELECT id FROM community_verdicts WHERE hostname = ? AND ip_hash = ?
    AND reported_at > datetime('now', '-7 days')
  `).get(hostname, ipHash);

  if (existing) return res.status(429).json({ error: 'Already voted for this domain' });

  db.prepare('INSERT INTO community_verdicts (url, hostname, vote, ip_hash) VALUES (?, ?, ?, ?)')
    .run(url, hostname, vote, ipHash);

  const votes = db.prepare(`
    SELECT vote, COUNT(*) as count FROM community_verdicts
    WHERE hostname = ? GROUP BY vote
  `).all(hostname);

  res.json({ message: 'Vote recorded', votes });
});

// GET /api/stats — Global stats
app.get('/api/stats', (req, res) => {
  const total = db.prepare('SELECT COUNT(*) as c FROM analyses').get().c;
  const today = db.prepare(`SELECT COUNT(*) as c FROM analyses WHERE analyzed_at > date('now')`).get().c;
  const verdicts = db.prepare(`SELECT verdict, COUNT(*) as c FROM analyses GROUP BY verdict`).all();
  const topDomains = db.prepare(`
    SELECT hostname, COUNT(*) as count, AVG(score) as avg_score
    FROM analyses GROUP BY hostname ORDER BY count DESC LIMIT 10
  `).all();
  const reports = db.prepare('SELECT COUNT(*) as c FROM reports').get().c;
  const avgScore = db.prepare('SELECT AVG(score) as avg FROM analyses').get().avg;

  res.json({
    total_analyses: total,
    analyses_today: today,
    total_reports: reports,
    avg_score: Math.round(avgScore || 0),
    verdicts: verdicts.reduce((acc, r) => { acc[r.verdict] = r.c; return acc; }, {}),
    top_domains: topDomains.map(d => ({ ...d, avg_score: Math.round(d.avg_score) }))
  });
});

// ─── START ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`URLGuard API running on http://localhost:${PORT}`);
  console.log(`Endpoints:`);
  console.log(`  POST /api/analyses       — Save analysis`);
  console.log(`  GET  /api/analyses       — List analyses`);
  console.log(`  GET  /api/analyses/:id   — Get analysis`);
  console.log(`  GET  /api/domains/:host  — Domain reputation`);
  console.log(`  POST /api/reports        — Submit report`);
  console.log(`  GET  /api/reports        — List reports`);
  console.log(`  POST /api/votes          — Community vote`);
  console.log(`  GET  /api/stats          — Global stats`);
});
