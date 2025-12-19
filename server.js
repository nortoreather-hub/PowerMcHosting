const express = require('express');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');

const app = express();
app.use(cors());
app.use(express.json());

const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
const usersPath = path.join(DATA_DIR, 'users.json');
const serversPath = path.join(DATA_DIR, 'servers.json');

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';

// Optional SMTP config for sending verification emails
const SMTP_HOST = process.env.SMTP_HOST;
const SMTP_PORT = process.env.SMTP_PORT;
const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;
const FROM_EMAIL = process.env.FROM_EMAIL || `no-reply@${process.env.HOSTNAME || 'example.com'}`;

let mailer = null;
if (SMTP_HOST && SMTP_USER && SMTP_PASS) {
  mailer = nodemailer.createTransport({ host: SMTP_HOST, port: Number(SMTP_PORT) || 587, auth: { user: SMTP_USER, pass: SMTP_PASS } });
}

function readJSON(p, fallback) {
  try { return JSON.parse(fs.readFileSync(p, 'utf8') || 'null') || fallback; }
  catch (e) { return fallback; }
}
function writeJSON(p, obj) { fs.writeFileSync(p, JSON.stringify(obj, null, 2)); }

// Simple helpers
function findUser(username) {
  const users = readJSON(usersPath, []);
  return users.find(u => u.username === username);
}

// Auth
app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username+password required' });
  const user = findUser(username);
  if (!user || user.password !== password) return res.status(401).json({ error: 'invalid credentials' });
  // support bcrypt-hashed passwords and plaintext legacy passwords
  const pwMatches = user.password && user.password.startsWith('$2') ? bcrypt.compareSync(password, user.password) : (user.password === password);
  if (!pwMatches) return res.status(401).json({ error: 'invalid credentials' });
  if (user.verified === false) return res.status(403).json({ error: 'email not verified' });
  const token = jwt.sign({ username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '12h' });
  res.json({ token });
});

// Signup endpoint — creates a new user and sends verification email if mailer configured
app.post('/api/signup', (req, res) => {
  const { username, password, email } = req.body || {};
  if (!username || !password || !email) return res.status(400).json({ error: 'username,password,email required' });
  const users = readJSON(usersPath, []);
  if (users.find(u => u.username === username)) return res.status(409).json({ error: 'username exists' });
  if (users.find(u => u.email === email)) return res.status(409).json({ error: 'email exists' });
  const hash = bcrypt.hashSync(password, 10);
  const newUser = { username, password: hash, role: 'admin', email, verified: false };
  users.push(newUser);
  writeJSON(usersPath, users);

  // create verification token
  const token = jwt.sign({ username: newUser.username, email: newUser.email }, JWT_SECRET, { expiresIn: '7d' });
  const verifyUrl = `${req.protocol}://${req.get('host')}/api/verify?token=${token}`;

  if (mailer) {
    mailer.sendMail({ from: FROM_EMAIL, to: newUser.email, subject: 'Verify your PowerHosting account', text: `Click to verify: ${verifyUrl}`, html: `Click to verify: <a href="${verifyUrl}">${verifyUrl}</a>` })
      .then(()=> res.json({ ok: true, message: 'verification email sent' }))
      .catch(err=> { console.error('mail error', err); res.json({ ok: true, message: 'user created, but failed to send email' }); });
  } else {
    // no mailer: return link in response (for dev)
    res.json({ ok: true, verifyUrl });
  }
});

// Verify email link
app.get('/api/verify', (req, res) => {
  const token = req.query.token;
  if (!token) return res.status(400).send('token required');
  try {
    const data = jwt.verify(token, JWT_SECRET);
    const users = readJSON(usersPath, []);
    const u = users.find(x => x.username === data.username && x.email === data.email);
    if (!u) return res.status(404).send('user not found');
    u.verified = true;
    writeJSON(usersPath, users);
    return res.send('email verified — you can close this page and log in');
  } catch (e) { return res.status(400).send('invalid token'); }
});

function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Bearer ')) return res.status(401).json({ error: 'missing token' });
  const token = h.slice(7);
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) { res.status(401).json({ error: 'invalid token' }); }
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'unauthenticated' });
    if (req.user.role !== role && req.user.role !== 'owner') return res.status(403).json({ error: 'forbidden' });
    next();
  };
}

// Users management (owner only for listing/creating)
app.get('/api/users', auth, requireRole('owner'), (req, res) => {
  const users = readJSON(usersPath, []);
  res.json(users.map(u => ({ username: u.username, role: u.role })));
});

app.post('/api/users', auth, requireRole('owner'), (req, res) => {
  const { username, password, role } = req.body || {};
  if (!username || !password || !role) return res.status(400).json({ error: 'username,password,role required' });
  const users = readJSON(usersPath, []);
  if (users.find(u => u.username === username)) return res.status(409).json({ error: 'user exists' });
  users.push({ username, password, role });
  writeJSON(usersPath, users);
  res.json({ ok: true });
});

// Servers
app.get('/api/servers', auth, (req, res) => {
  const servers = readJSON(serversPath, []);
  // Filter: return servers the user has access to, or all if owner
  if (req.user.role === 'owner') return res.json(servers);
  const allowed = servers.filter(s => (s.access || []).includes(req.user.username));
  res.json(allowed);
});

app.post('/api/servers', auth, requireRole('owner'), (req, res) => {
  const { id, name, host, port, rconPort, rconPassword, memory } = req.body || {};
  if (!id || !name) return res.status(400).json({ error: 'id and name required' });
  const servers = readJSON(serversPath, []);
  if (servers.find(s => s.id === id)) return res.status(409).json({ error: 'server id exists' });
  servers.push({ id, name, host, port, rconPort, rconPassword, memory: memory || '1G', access: [] });
  writeJSON(serversPath, servers);
  res.json({ ok: true });
});

// Grant access to a user for a server
app.post('/api/servers/:id/grant', auth, requireRole('owner'), (req, res) => {
  const sid = req.params.id;
  const { username } = req.body || {};
  if (!username) return res.status(400).json({ error: 'username required' });
  const servers = readJSON(serversPath, []);
  const s = servers.find(x => x.id === sid);
  if (!s) return res.status(404).json({ error: 'server not found' });
  s.access = s.access || [];
  if (!s.access.includes(username)) s.access.push(username);
  writeJSON(serversPath, servers);
  res.json({ ok: true });
});

// Revoke access
app.post('/api/servers/:id/revoke', auth, requireRole('owner'), (req, res) => {
  const sid = req.params.id;
  const { username } = req.body || {};
  const servers = readJSON(serversPath, []);
  const s = servers.find(x => x.id === sid);
  if (!s) return res.status(404).json({ error: 'server not found' });
  s.access = (s.access || []).filter(u => u !== username);
  writeJSON(serversPath, servers);
  res.json({ ok: true });
});

// Set server memory (admins and owners). Admins must have access to the server.
app.post('/api/servers/:id/memory', auth, requireRole('admin'), (req, res) => {
  const sid = req.params.id;
  const { memory } = req.body || {};
  if (!memory) return res.status(400).json({ error: 'memory required' });
  const servers = readJSON(serversPath, []);
  const s = servers.find(x => x.id === sid);
  if (!s) return res.status(404).json({ error: 'server not found' });
  // If not owner, ensure admin has explicit access to this server
  if (req.user.role !== 'owner' && !(s.access || []).includes(req.user.username)) return res.status(403).json({ error: 'forbidden' });
  s.memory = memory;
  writeJSON(serversPath, servers);
  res.json({ ok: true });
});

// Serve frontend
app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`PowerHosting panel running on port ${PORT}`));
