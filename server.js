// NAHAD NOTES server: zero npm dependencies, SQLite database. Needs Node 22.13+ (built-in node:sqlite).
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const PORT = process.env.PORT || 3000;
const DATA = process.env.DATA_DIR || path.join(__dirname, 'data');
const PAGE = path.join(__dirname, 'index.html');
const MAX_BODY = 15 * 1024 * 1024;
fs.mkdirSync(DATA, { recursive: true });
const { DatabaseSync } = require('node:sqlite');
const db = new DatabaseSync(path.join(DATA, 'nahad.db'));
db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users(username TEXT PRIMARY KEY, salt TEXT NOT NULL, hash TEXT NOT NULL, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS notes(username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE, id TEXT NOT NULL, data TEXT NOT NULL, updated INTEGER NOT NULL, PRIMARY KEY(username,id));
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT NOT NULL);`);
const q = {
  getUser: db.prepare('SELECT * FROM users WHERE username=?'),
  addUser: db.prepare('INSERT INTO users(username,salt,hash,created) VALUES(?,?,?,?)'),
  list: db.prepare('SELECT data FROM notes WHERE username=?'),
  upsert: db.prepare('INSERT INTO notes(username,id,data,updated) VALUES(?,?,?,?) ON CONFLICT(username,id) DO UPDATE SET data=excluded.data, updated=excluded.updated'),
  del: db.prepare('DELETE FROM notes WHERE username=? AND id=?'),
  meta: db.prepare('SELECT v FROM meta WHERE k=?'),
  setMeta: db.prepare('INSERT OR REPLACE INTO meta(k,v) VALUES(?,?)'),
};

let SECRET = process.env.SESSION_SECRET;
if (!SECRET) {
  const r = q.meta.get('secret');
  if (r) SECRET = r.v; else { SECRET = crypto.randomBytes(32).toString('hex'); q.setMeta.run('secret', SECRET); }
}
// One-time import from the earlier JSON-file version, if its files are present.
try {
  const uf = path.join(DATA, 'users.json');
  if (fs.existsSync(uf)) {
    const users = JSON.parse(fs.readFileSync(uf, 'utf8'));
    for (const [n, u] of Object.entries(users)) {
      if (q.getUser.get(n)) continue;
      q.addUser.run(n, u.salt, u.hash, Date.now());
      const nf = path.join(DATA, 'notes', Buffer.from(n).toString('hex') + '.json');
      if (fs.existsSync(nf)) for (const note of JSON.parse(fs.readFileSync(nf, 'utf8'))) q.upsert.run(n, note.id, JSON.stringify(note), note.t || Date.now());
    }
    fs.renameSync(uf, uf + '.imported');
  }
} catch (e) { console.error('Import skipped:', e.message); }

const sign = s => crypto.createHmac('sha256', SECRET).update(s).digest('hex');
function makeToken(u) { const p = u + '|' + (Date.now() + 30 * 864e5); return Buffer.from(p).toString('base64url') + '.' + sign(p); }
function readToken(t) {
  if (!t) return null; const [b, sig] = t.split('.'); if (!b || !sig) return null;
  const p = Buffer.from(b, 'base64url').toString(); const good = sign(p);
  if (sig.length !== good.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good))) return null;
  const [u, exp] = p.split('|'); return Date.now() < +exp ? u : null;
}
const cookie = req => Object.fromEntries((req.headers.cookie || '').split(';').map(c => c.trim().split(/=(.*)/s).slice(0, 2)).filter(x => x[0]));
const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 64).toString('hex');

const hits = new Map(); // simple login rate limit per IP
function limited(ip) {
  const now = Date.now(), a = (hits.get(ip) || []).filter(t => now - t < 10 * 6e4); a.push(now); hits.set(ip, a); return a.length > 20;
}
const send = (res, code, obj, headers = {}) => { res.writeHead(code, { 'Content-Type': 'application/json', ...headers }); res.end(JSON.stringify(obj)); };
const setCookie = (res, t, secure) => `nn=${t}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${30 * 86400}${secure ? '; Secure' : ''}`;

function body(req) {
  return new Promise((ok, no) => {
    let n = 0; const ch = [];
    req.on('data', c => { n += c.length; if (n > MAX_BODY) { no(new Error('big')); req.destroy(); } else ch.push(c); });
    req.on('end', () => { try { ok(JSON.parse(Buffer.concat(ch).toString() || '{}')); } catch { no(new Error('bad json')); } });
  });
}

http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x'), p = url.pathname;
  const secure = (req.headers['x-forwarded-proto'] || '') === 'https';
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  try {
    if (p.startsWith('/api/')) {
      const user = readToken(cookie(req).nn);
      if (p === '/api/register' || p === '/api/login') {
        if (req.method !== 'POST') return send(res, 405, { error: 'Method not allowed' });
        if (limited(ip)) return send(res, 429, { error: 'Too many attempts. Try again in a few minutes.' });
        const { username, password } = await body(req); const n = String(username || '').trim().toLowerCase();
        if (p === '/api/register') {
          if (!/^[a-z0-9_.-]{3,24}$/.test(n)) return send(res, 400, { error: 'Username: 3–24 letters, numbers, . _ -' });
          if (String(password || '').length < 6) return send(res, 400, { error: 'Password needs at least 6 characters.' });
          if (q.getUser.get(n)) return send(res, 409, { error: 'That username is taken. Sign in instead.' });
          const salt = crypto.randomBytes(16).toString('hex'); q.addUser.run(n, salt, hashPw(password, salt), Date.now());
        } else {
          const u = q.getUser.get(n);
          if (!u || !crypto.timingSafeEqual(Buffer.from(u.hash), Buffer.from(hashPw(String(password || ''), u.salt)))) return send(res, 401, { error: 'Wrong username or password.' });
        }
        return send(res, 200, { username: n }, { 'Set-Cookie': setCookie(res, makeToken(n), secure) });
      }
      if (p === '/api/logout') return send(res, 200, {}, { 'Set-Cookie': 'nn=; HttpOnly; Path=/; Max-Age=0' });
      if (!user) return send(res, 401, { error: 'Not signed in.' });
      if (p === '/api/me') return send(res, 200, { username: user });
      if (p === '/api/notes' && req.method === 'GET') return send(res, 200, q.list.all(user).map(r => JSON.parse(r.data)));
      const m = p.match(/^\/api\/notes\/([a-z0-9]{1,40})$/);
      if (m) {
        if (req.method === 'PUT') {
          const n = await body(req); n.id = m[1];
          q.upsert.run(user, n.id, JSON.stringify(n), Date.now()); return send(res, 200, { ok: true });
        }
        if (req.method === 'DELETE') { q.del.run(user, m[1]); return send(res, 200, { ok: true }); }
      }
      return send(res, 404, { error: 'Not found' });
    }
    // the app page (every non-API path serves it)
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    fs.createReadStream(PAGE).pipe(res);
  } catch (e) { send(res, 400, { error: e.message === 'big' ? 'Note too large.' : 'Bad request.' }); }
}).listen(PORT, () => console.log('NAHAD NOTES running on port ' + PORT));
