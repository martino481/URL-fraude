const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'urlguard_secret_change_in_prod';

app.use(cors());
app.use(express.json());

// ─── DATABASE ─────────────────────────────────────────────────────────────────
const db = new sqlite3.Database(path.join(__dirname, 'urlguard.db'), err => {
  if (err) console.error('DB error:', err);
  else console.log('SQLite connected');
});

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    avatar_color TEXT DEFAULT '#6e6ef5',
    bio TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    last_login TEXT,
    analyses_count INTEGER DEFAULT 0,
    reports_count INTEGER DEFAULT 0,
    is_admin INTEGER DEFAULT 0
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL, hostname TEXT NOT NULL, score INTEGER NOT NULL, verdict TEXT NOT NULL,
    heuristic_score INTEGER, visual_score INTEGER,
    whois_years INTEGER, whois_registrar TEXT, whois_country TEXT, whois_privacy INTEGER,
    factors TEXT, ai_summary TEXT, ai_signals TEXT, is_clone INTEGER DEFAULT 0,
    cloned_brand TEXT, screenshot_url TEXT,
    analyzed_at TEXT DEFAULT (datetime('now')), ip_hash TEXT,
    user_id INTEGER REFERENCES users(id)
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL, hostname TEXT NOT NULL, reason TEXT NOT NULL, details TEXT,
    reported_at TEXT DEFAULT (datetime('now')), ip_hash TEXT, status TEXT DEFAULT 'pending',
    user_id INTEGER REFERENCES users(id)
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS community_verdicts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL, hostname TEXT NOT NULL, vote TEXT NOT NULL,
    reported_at TEXT DEFAULT (datetime('now')), ip_hash TEXT,
    user_id INTEGER REFERENCES users(id)
  )`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_analyses_hostname ON analyses(hostname)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_analyses_user ON analyses(user_id)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_reports_user ON reports(user_id)`);
});

// ─── HELPERS ──────────────────────────────────────────────────────────────────
function hashIP(ip) { return crypto.createHash('sha256').update(ip+'urlguard_salt').digest('hex').slice(0,16); }
function hashPassword(pw) { return crypto.createHash('sha256').update(pw+'urlguard_pw_salt').digest('hex'); }
function getHostname(url) {
  try { if (!url.startsWith('http')) url='https://'+url; return new URL(url).hostname.toLowerCase(); }
  catch { return null; }
}
function dbGet(sql, params=[]) { return new Promise((res,rej) => db.get(sql,params,(e,r)=>e?rej(e):res(r))); }
function dbAll(sql, params=[]) { return new Promise((res,rej) => db.all(sql,params,(e,r)=>e?rej(e):res(r))); }
function dbRun(sql, params=[]) { return new Promise((res,rej) => db.run(sql,params,function(e){e?rej(e):res({lastID:this.lastID,changes:this.changes})})); }

// Simple JWT (no external dependency)
function signToken(payload) {
  const header = Buffer.from(JSON.stringify({alg:'HS256',typ:'JWT'})).toString('base64url');
  const body = Buffer.from(JSON.stringify({...payload, iat:Date.now(), exp:Date.now()+7*24*60*60*1000})).toString('base64url');
  const sig = crypto.createHmac('sha256',JWT_SECRET).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${sig}`;
}
function verifyToken(token) {
  try {
    const [header,body,sig] = token.split('.');
    const expected = crypto.createHmac('sha256',JWT_SECRET).update(`${header}.${body}`).digest('base64url');
    if (sig !== expected) return null;
    const payload = JSON.parse(Buffer.from(body,'base64url').toString());
    if (payload.exp < Date.now()) return null;
    return payload;
  } catch { return null; }
}

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Non authentifié' });
  const payload = verifyToken(auth.slice(7));
  if (!payload) return res.status(401).json({ error: 'Token invalide ou expiré' });
  req.user = payload;
  next();
}

function optionalAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (auth && auth.startsWith('Bearer ')) {
    const payload = verifyToken(auth.slice(7));
    if (payload) req.user = payload;
  }
  next();
}

// Badge system
function computeBadges(user) {
  const badges = [];
  if (user.analyses_count >= 1)   badges.push({ id:'first_scan', label:'Premier scan', emoji:'🔍', color:'#6e6ef5' });
  if (user.analyses_count >= 10)  badges.push({ id:'scanner', label:'Scanner', emoji:'⚡', color:'#2ecc7a' });
  if (user.analyses_count >= 50)  badges.push({ id:'hunter', label:'Chasseur', emoji:'🎯', color:'#f5a623' });
  if (user.analyses_count >= 100) badges.push({ id:'expert', label:'Expert', emoji:'🛡️', color:'#e84545' });
  if (user.analyses_count >= 500) badges.push({ id:'master', label:'Maître', emoji:'👑', color:'#FFD700' });
  if (user.reports_count >= 1)    badges.push({ id:'reporter', label:'Signaleur', emoji:'🚨', color:'#e84545' });
  if (user.reports_count >= 10)   badges.push({ id:'guardian', label:'Gardien', emoji:'🦅', color:'#2ecc7a' });
  if (user.is_admin)              badges.push({ id:'admin', label:'Admin', emoji:'⚙️', color:'#6e6ef5' });
  return badges;
}

function getLevel(analyses) {
  if (analyses >= 500) return { name:'Maître', level:5, color:'#FFD700', next:null };
  if (analyses >= 100) return { name:'Expert', level:4, color:'#e84545', next:500 };
  if (analyses >= 50)  return { name:'Chasseur', level:3, color:'#f5a623', next:100 };
  if (analyses >= 10)  return { name:'Scanner', level:2, color:'#2ecc7a', next:50 };
  return { name:'Novice', level:1, color:'#6e6ef5', next:10 };
}

// ─── AUTH ROUTES ──────────────────────────────────────────────────────────────
app.get('/', (req,res) => res.json({status:'ok',service:'URLGuard API',version:'2.0.0'}));

app.post('/api/auth/register', async (req,res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).json({ error: 'Tous les champs sont requis' });
    if (username.length < 3) return res.status(400).json({ error: 'Pseudo trop court (min 3 caractères)' });
    if (password.length < 6) return res.status(400).json({ error: 'Mot de passe trop court (min 6 caractères)' });
    if (!/^[^@]+@[^@]+\.[^@]+$/.test(email)) return res.status(400).json({ error: 'Email invalide' });

    const existing = await dbGet('SELECT id FROM users WHERE username=? OR email=?', [username, email]);
    if (existing) return res.status(409).json({ error: 'Pseudo ou email déjà utilisé' });

    const colors = ['#6e6ef5','#2ecc7a','#f5a623','#e84545','#00bcd4','#e91e8c'];
    const avatar_color = colors[Math.floor(Math.random()*colors.length)];
    const result = await dbRun('INSERT INTO users (username,email,password_hash,avatar_color) VALUES (?,?,?,?)',
      [username.trim(), email.toLowerCase().trim(), hashPassword(password), avatar_color]);

    const token = signToken({ id:result.lastID, username, email });
    res.json({ token, user:{ id:result.lastID, username, email, avatar_color, analyses_count:0, reports_count:0, badges:[], level:getLevel(0) }});
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/login', async (req,res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email et mot de passe requis' });
    const user = await dbGet('SELECT * FROM users WHERE email=? AND password_hash=?', [email.toLowerCase().trim(), hashPassword(password)]);
    if (!user) return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
    await dbRun('UPDATE users SET last_login=datetime("now") WHERE id=?', [user.id]);
    const token = signToken({ id:user.id, username:user.username, email:user.email });
    res.json({ token, user:{ ...user, password_hash:undefined, badges:computeBadges(user), level:getLevel(user.analyses_count) }});
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/auth/me', authMiddleware, async (req,res) => {
  try {
    const user = await dbGet('SELECT * FROM users WHERE id=?', [req.user.id]);
    if (!user) return res.status(404).json({ error: 'Utilisateur non trouvé' });
    res.json({ ...user, password_hash:undefined, badges:computeBadges(user), level:getLevel(user.analyses_count) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/auth/profile', authMiddleware, async (req,res) => {
  try {
    const { bio, avatar_color } = req.body;
    await dbRun('UPDATE users SET bio=?, avatar_color=? WHERE id=?', [bio||null, avatar_color||'#6e6ef5', req.user.id]);
    const user = await dbGet('SELECT * FROM users WHERE id=?', [req.user.id]);
    res.json({ ...user, password_hash:undefined, badges:computeBadges(user), level:getLevel(user.analyses_count) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── USER DASHBOARD ───────────────────────────────────────────────────────────
app.get('/api/users/:id/dashboard', authMiddleware, async (req,res) => {
  try {
    if (parseInt(req.params.id) !== req.user.id) return res.status(403).json({ error: 'Accès refusé' });
    const user = await dbGet('SELECT * FROM users WHERE id=?', [req.user.id]);
    const recentAnalyses = await dbAll('SELECT * FROM analyses WHERE user_id=? ORDER BY analyzed_at DESC LIMIT 20', [req.user.id]);
    const recentReports = await dbAll('SELECT * FROM reports WHERE user_id=? ORDER BY reported_at DESC LIMIT 10', [req.user.id]);
    const verdictCounts = await dbAll('SELECT verdict,COUNT(*) as c FROM analyses WHERE user_id=? GROUP BY verdict', [req.user.id]);
    const avgScore = await dbGet('SELECT AVG(score) as avg FROM analyses WHERE user_id=?', [req.user.id]);
    const suspectFound = (await dbGet('SELECT COUNT(*) as c FROM analyses WHERE user_id=? AND verdict="Suspect"', [req.user.id]))?.c || 0;

    res.json({
      user: { ...user, password_hash:undefined, badges:computeBadges(user), level:getLevel(user.analyses_count) },
      stats: { total_analyses:user.analyses_count, total_reports:user.reports_count, avg_score:Math.round(avgScore?.avg||0), suspect_found:suspectFound, verdict_counts:verdictCounts.reduce((a,r)=>{a[r.verdict]=r.c;return a;},{}) },
      recent_analyses: recentAnalyses.map(r=>({...r, factors:r.factors?JSON.parse(r.factors):[], whois:{years:r.whois_years,country:r.whois_country,registrar:r.whois_registrar}})),
      recent_reports: recentReports
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── LEADERBOARD ─────────────────────────────────────────────────────────────
app.get('/api/leaderboard', async (req,res) => {
  try {
    const users = await dbAll(`SELECT id,username,avatar_color,analyses_count,reports_count,created_at FROM users ORDER BY analyses_count DESC LIMIT 20`);
    res.json({ data: users.map(u => ({ ...u, badges:computeBadges(u), level:getLevel(u.analyses_count) })) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── ANALYSES (with user_id) ──────────────────────────────────────────────────
app.post('/api/analyses', optionalAuth, async (req,res) => {
  try {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
    const { url, score, verdict, heuristic_score, visual_score, whois, factors, ai_summary, ai_signals, is_clone, cloned_brand, screenshot_url } = req.body;
    if (!url || score===undefined) return res.status(400).json({ error: 'url and score required' });
    const hostname = getHostname(url);
    if (!hostname) return res.status(400).json({ error: 'Invalid URL' });
    const userId = req.user?.id || null;
    const result = await dbRun(
      `INSERT INTO analyses (url,hostname,score,verdict,heuristic_score,visual_score,whois_years,whois_registrar,whois_country,whois_privacy,factors,ai_summary,ai_signals,is_clone,cloned_brand,screenshot_url,ip_hash,user_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      [url,hostname,score,verdict,heuristic_score??null,visual_score??null,whois?.years??null,whois?.registrar??null,whois?.country??null,whois?.privacy?1:0,factors?JSON.stringify(factors):null,ai_summary??null,ai_signals?JSON.stringify(ai_signals):null,is_clone?1:0,cloned_brand??null,screenshot_url??null,hashIP(ip),userId]
    );
    if (userId) await dbRun('UPDATE users SET analyses_count=analyses_count+1 WHERE id=?', [userId]);
    res.json({ id:result.lastID, message:'Analysis saved' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/analyses', async (req,res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit)||20, 100);
    const offset = parseInt(req.query.offset)||0;
    let q='SELECT * FROM analyses WHERE 1=1'; const p=[];
    if (req.query.hostname) { q+=' AND hostname LIKE ?'; p.push(`%${req.query.hostname}%`); }
    if (req.query.verdict) { q+=' AND verdict=?'; p.push(req.query.verdict); }
    q+=' ORDER BY analyzed_at DESC LIMIT ? OFFSET ?'; p.push(limit,offset);
    const rows = await dbAll(q,p);
    const total = (await dbGet('SELECT COUNT(*) as count FROM analyses')).count;
    res.json({ data:rows.map(r=>({...r,factors:r.factors?JSON.parse(r.factors):[],ai_signals:r.ai_signals?JSON.parse(r.ai_signals):[],whois:{years:r.whois_years,registrar:r.whois_registrar,country:r.whois_country,privacy:!!r.whois_privacy}})), total, limit, offset });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/analyses/:id', async (req,res) => {
  try {
    const row = await dbGet('SELECT * FROM analyses WHERE id=?', [req.params.id]);
    if (!row) return res.status(404).json({ error:'Not found' });
    res.json({...row, factors:row.factors?JSON.parse(row.factors):[], ai_signals:row.ai_signals?JSON.parse(row.ai_signals):[]});
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/domains/:hostname', async (req,res) => {
  try {
    const hostname = req.params.hostname.toLowerCase();
    const analyses = await dbAll('SELECT score,verdict,analyzed_at FROM analyses WHERE hostname=? ORDER BY analyzed_at DESC LIMIT 50', [hostname]);
    if (!analyses.length) return res.status(404).json({ error:'No data for this domain' });
    const avgScore = Math.round(analyses.reduce((s,r)=>s+r.score,0)/analyses.length);
    const verdictCounts = analyses.reduce((acc,r)=>{acc[r.verdict]=(acc[r.verdict]||0)+1;return acc;},{});
    const reports = await dbGet('SELECT COUNT(*) as count FROM reports WHERE hostname=?', [hostname]);
    const communityVotes = await dbAll('SELECT vote,COUNT(*) as count FROM community_verdicts WHERE hostname=? GROUP BY vote', [hostname]);
    res.json({ hostname, total_analyses:analyses.length, avg_score:avgScore, verdict_counts:verdictCounts, report_count:reports.count, community_votes:communityVotes, last_analyzed:analyses[0]?.analyzed_at });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/reports', optionalAuth, async (req,res) => {
  try {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
    const { url, reason, details } = req.body;
    if (!url || !reason) return res.status(400).json({ error:'url and reason required' });
    if (!['phishing','malware','scam','spam','fake_brand','other'].includes(reason)) return res.status(400).json({ error:'Invalid reason' });
    const hostname = getHostname(url);
    if (!hostname) return res.status(400).json({ error:'Invalid URL' });
    const ipHash = hashIP(ip);
    const existing = await dbGet(`SELECT id FROM reports WHERE hostname=? AND ip_hash=? AND reported_at>datetime('now','-24 hours')`, [hostname,ipHash]);
    if (existing) return res.status(429).json({ error:'Already reported in last 24h' });
    const userId = req.user?.id || null;
    const result = await dbRun('INSERT INTO reports (url,hostname,reason,details,ip_hash,user_id) VALUES (?,?,?,?,?,?)', [url,hostname,reason,details||null,ipHash,userId]);
    if (userId) await dbRun('UPDATE users SET reports_count=reports_count+1 WHERE id=?', [userId]);
    res.json({ id:result.lastID, message:'Report submitted. Thank you!' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/reports', async (req,res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit)||20,100);
    const rows = await dbAll('SELECT id,url,hostname,reason,details,reported_at,status FROM reports ORDER BY reported_at DESC LIMIT ?', [limit]);
    const total = (await dbGet('SELECT COUNT(*) as c FROM reports')).c;
    res.json({ data:rows, total });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/votes', optionalAuth, async (req,res) => {
  try {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
    const { url, vote } = req.body;
    if (!url || !['safe','unsafe'].includes(vote)) return res.status(400).json({ error:'url and vote required' });
    const hostname = getHostname(url);
    if (!hostname) return res.status(400).json({ error:'Invalid URL' });
    const ipHash = hashIP(ip);
    const existing = await dbGet(`SELECT id FROM community_verdicts WHERE hostname=? AND ip_hash=? AND reported_at>datetime('now','-7 days')`, [hostname,ipHash]);
    if (existing) return res.status(429).json({ error:'Already voted' });
    await dbRun('INSERT INTO community_verdicts (url,hostname,vote,ip_hash,user_id) VALUES (?,?,?,?,?)', [url,hostname,vote,ipHash,req.user?.id||null]);
    const votes = await dbAll('SELECT vote,COUNT(*) as count FROM community_verdicts WHERE hostname=? GROUP BY vote', [hostname]);
    res.json({ message:'Vote recorded', votes });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/stats', async (req,res) => {
  try {
    const total = (await dbGet('SELECT COUNT(*) as c FROM analyses')).c;
    const today = (await dbGet(`SELECT COUNT(*) as c FROM analyses WHERE analyzed_at>date('now')`)).c;
    const verdicts = await dbAll('SELECT verdict,COUNT(*) as c FROM analyses GROUP BY verdict');
    const topDomains = await dbAll('SELECT hostname,COUNT(*) as count,AVG(score) as avg_score FROM analyses GROUP BY hostname ORDER BY count DESC LIMIT 10');
    const reports = (await dbGet('SELECT COUNT(*) as c FROM reports')).c;
    const avgRow = await dbGet('SELECT AVG(score) as avg FROM analyses');
    const usersCount = (await dbGet('SELECT COUNT(*) as c FROM users')).c;
    res.json({ total_analyses:total, analyses_today:today, total_reports:reports, avg_score:Math.round(avgRow?.avg||0), total_users:usersCount, verdicts:verdicts.reduce((acc,r)=>{acc[r.verdict]=r.c;return acc;},{}), top_domains:topDomains.map(d=>({...d,avg_score:Math.round(d.avg_score)})) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});


// ─── SSL CHECK ────────────────────────────────────────────────────────────────
app.get('/api/ssl/:hostname', async (req, res) => {
  const https = require('https');
  const tls = require('tls');
  const hostname = req.params.hostname.toLowerCase().replace(/^https?:\/\//, '').split('/')[0];

  try {
    const sslInfo = await new Promise((resolve, reject) => {
      const socket = tls.connect(443, hostname, { servername: hostname, rejectUnauthorized: false }, () => {
        const cert = socket.getPeerCertificate(true);
        const protocol = socket.getProtocol();
        const cipher = socket.getCipher();
        socket.destroy();

        if (!cert || !cert.subject) return reject(new Error('No certificate found'));

        const now = new Date();
        const validFrom = new Date(cert.valid_from);
        const validTo = new Date(cert.valid_to);
        const daysLeft = Math.round((validTo - now) / (1000 * 60 * 60 * 24));
        const daysTotal = Math.round((validTo - validFrom) / (1000 * 60 * 60 * 24));
        const isExpired = now > validTo;
        const isNotYetValid = now < validFrom;
        const isSelfSigned = cert.issuer?.CN === cert.subject?.CN;
        const isWildcard = cert.subject?.CN?.startsWith('*.');
        const isTrustedCA = !isSelfSigned;

        // Extract SANs (Subject Alternative Names)
        const sans = cert.subjectaltname
          ? cert.subjectaltname.split(', ').map(s => s.replace('DNS:', '').replace('IP Address:', ''))
          : [];

        // Grade the SSL
        let grade = 'A+';
        let gradeScore = 100;
        const issues = [];
        const strengths = [];

        if (isExpired) { grade = 'F'; gradeScore = 0; issues.push('Certificat expiré'); }
        else if (isNotYetValid) { grade = 'F'; gradeScore = 0; issues.push('Certificat pas encore valide'); }
        else if (daysLeft < 7) { grade = 'C'; gradeScore -= 40; issues.push(`Expire dans ${daysLeft} jours !`); }
        else if (daysLeft < 30) { grade = 'B'; gradeScore -= 20; issues.push(`Expire bientôt (${daysLeft} jours)`); }
        else { strengths.push(`Valide encore ${daysLeft} jours`); }

        if (isSelfSigned) { if (gradeScore > 0) grade = 'C'; gradeScore -= 30; issues.push('Certificat auto-signé (non approuvé)'); }
        else { strengths.push('Émis par une autorité de confiance'); }

        if (protocol === 'TLSv1' || protocol === 'TLSv1.1') { if (grade === 'A+') grade = 'B'; gradeScore -= 20; issues.push(`Protocole obsolète (${protocol})`); }
        else if (protocol === 'TLSv1.2') { strengths.push('TLS 1.2'); }
        else if (protocol === 'TLSv1.3') { strengths.push('TLS 1.3 (meilleur protocole)'); }

        if (isWildcard) { strengths.push('Certificat wildcard (couvre tous les sous-domaines)'); }
        if (sans.length > 1) { strengths.push(`Couvre ${sans.length} domaine(s)`); }

        gradeScore = Math.max(0, gradeScore);
        if (gradeScore >= 90 && !issues.length) grade = 'A+';
        else if (gradeScore >= 80) grade = 'A';
        else if (gradeScore >= 70) grade = 'B';
        else if (gradeScore >= 50) grade = 'C';
        else grade = 'F';

        resolve({
          hostname,
          valid: !isExpired && !isNotYetValid && isTrustedCA,
          grade,
          grade_score: gradeScore,
          subject: {
            cn: cert.subject?.CN || null,
            org: cert.subject?.O || null,
            country: cert.subject?.C || null,
          },
          issuer: {
            cn: cert.issuer?.CN || null,
            org: cert.issuer?.O || null,
            country: cert.issuer?.C || null,
          },
          valid_from: validFrom.toISOString(),
          valid_to: validTo.toISOString(),
          days_left: daysLeft,
          days_total: daysTotal,
          is_expired: isExpired,
          is_self_signed: isSelfSigned,
          is_wildcard: isWildcard,
          is_trusted_ca: isTrustedCA,
          protocol,
          cipher: cipher?.name || null,
          cipher_bits: cipher?.version || null,
          sans: sans.slice(0, 10),
          serial: cert.serialNumber || null,
          fingerprint: cert.fingerprint || null,
          issues,
          strengths,
          checked_at: new Date().toISOString()
        });
      });

      socket.on('error', err => {
        if (err.code === 'ECONNREFUSED') resolve({ hostname, valid: false, grade: 'F', grade_score: 0, error: 'Connexion refusée — pas de serveur HTTPS sur ce domaine', issues: ['Pas de HTTPS'], strengths: [], checked_at: new Date().toISOString() });
        else if (err.code === 'ENOTFOUND') resolve({ hostname, valid: false, grade: 'F', grade_score: 0, error: 'Domaine introuvable', issues: ['Domaine inexistant'], strengths: [], checked_at: new Date().toISOString() });
        else resolve({ hostname, valid: false, grade: 'F', grade_score: 0, error: err.message, issues: ['Erreur de connexion SSL'], strengths: [], checked_at: new Date().toISOString() });
      });

      socket.setTimeout(8000, () => { socket.destroy(); reject(new Error('Timeout')); });
    });

    res.json(sslInfo);
  } catch(e) {
    res.json({ hostname, valid: false, grade: 'F', grade_score: 0, error: e.message, issues: ['Impossible de vérifier le SSL'], strengths: [], checked_at: new Date().toISOString() });
  }
});


// ─── AI VISUAL ANALYSIS ───────────────────────────────────────────────────────
app.post('/api/ai/analyze', async (req, res) => {
  const https = require('https');
  const { imageBase64, url, heuristicScore } = req.body;

  if (!imageBase64 || !url) return res.status(400).json({ error: 'imageBase64 and url required' });

  const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
  if (!ANTHROPIC_API_KEY) return res.status(500).json({ error: 'ANTHROPIC_API_KEY not configured on server' });

  const body = JSON.stringify({
    model: 'claude-sonnet-4-20250514',
    max_tokens: 1000,
    messages: [{
      role: 'user',
      content: [
        { type: 'image', source: { type: 'base64', media_type: 'image/jpeg', data: imageBase64 } },
        { type: 'text', text: `Expert cybersécurité. Analyse ce screenshot de "${url}" (score heuristique préalable: ${heuristicScore}/100). Réponds UNIQUEMENT en JSON valide sans markdown:\n{"visual_score":<0-100>,"verdict":"<Fiable|Incertain|Suspect>","summary":"<2 phrases en français>","signals":[{"positive":true/false,"text":"<signal visuel>"}],"is_clone":<bool>,"cloned_brand":"<marque ou null>"}\nCritères: qualité design, logos de marques connues, formulaires suspects login/CB/password, fautes orthographe, footer absent, imitation d'un site légitime.` }
      ]
    }]
  });

  const options = {
    hostname: 'api.anthropic.com',
    path: '/v1/messages',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': ANTHROPIC_API_KEY,
      'anthropic-version': '2023-06-01',
      'Content-Length': Buffer.byteLength(body)
    }
  };

  try {
    const result = await new Promise((resolve, reject) => {
      const reqHttp = https.request(options, (response) => {
        let data = '';
        response.on('data', chunk => data += chunk);
        response.on('end', () => {
          try {
            const parsed = JSON.parse(data);
            if (parsed.error) return reject(new Error(parsed.error.message || 'API error'));
            const text = parsed.content?.find(b => b.type === 'text')?.text || '{}';
            const clean = text.replace(/```json|```/g, '').trim();
            resolve(JSON.parse(clean));
          } catch(e) { reject(new Error('Invalid AI response')); }
        });
      });
      reqHttp.on('error', reject);
      reqHttp.write(body);
      reqHttp.end();
    });
    res.json(result);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.listen(PORT, () => console.log(`URLGuard API v2 running on port ${PORT}`));
