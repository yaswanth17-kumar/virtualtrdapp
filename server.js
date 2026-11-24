require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const path = require('path');
const fs = require('fs');

const app = express();

/* ---------- CORS: allow GitHub Pages, Render & local dev ---------- */
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS ||
  'https://dwijesh2911-cyber.github.io,https://virtual-stock-trading-app-b2c3.onrender.com,http://localhost:5000,http://127.0.0.1:5000,http://localhost:5500,http://127.0.0.1:5500')
  .split(',').map(s => s.trim()).filter(Boolean);

app.use(cors({
  origin: (origin, cb) => (!origin || ALLOWED_ORIGINS.includes(origin)) ? cb(null, true) : cb(null, false),
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '100kb' }));

/* ---------- Models ---------- */
const userSchema = new mongoose.Schema({
  userId: { type: String, required: true, unique: true, lowercase: true, trim: true },
  name: { type: String, required: true, trim: true, maxlength: 60 },
  passwordHash: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  cashBalance: { type: Number, default: 1000000 },
  holdings: { type: mongoose.Schema.Types.Mixed, default: {} },
  createdAt: { type: Date, default: Date.now }
}, { minimize: false });
const User = mongoose.models.User || mongoose.model('User', userSchema);

const tradeSchema = new mongoose.Schema({
  userId: { type: String, index: true },
  time: { type: Date, default: Date.now },
  type: { type: String, enum: ['BUY', 'SELL'] },
  symbol: String,
  quantity: Number,
  price: Number,
  total: Number
});
const Trade = mongoose.models.Trade || mongoose.model('Trade', tradeSchema);

/* ---------- Helpers ---------- */
const sign = u => jwt.sign({ userId: u.userId, role: u.role }, process.env.JWT_SECRET, { expiresIn: '7d' });
const publicUser = u => ({ userId: u.userId, name: u.name, role: u.role, createdAt: u.createdAt });

function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'No token provided.' });
  try { req.auth = jwt.verify(token, process.env.JWT_SECRET); next(); }
  catch (e) { res.status(401).json({ error: 'Session expired. Please log in again.' }); }
}
const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

/* ---------- Serve Frontend & Health ---------- */
app.get('/', (req, res) => {
  const indexPath = path.join(__dirname, 'index.html');
  if (fs.existsSync(indexPath)) return res.sendFile(indexPath);
  res.json({ ok: true, service: 'ApexTrader API' });
});
app.get('/api/health', (req, res) => res.json({ ok: true }));

/* ---------- Auth ---------- */
app.post('/api/auth/register', wrap(async (req, res) => {
  let { name, userId, password } = req.body || {};
  userId = String(userId || '').trim().toLowerCase();
  name = String(name || '').trim();
  password = String(password || '');
  if (!/^[a-z0-9_]{3,20}$/.test(userId)) return res.status(400).json({ error: 'ID must be 3-20 characters: letters, numbers or underscore.' });
  if (!name) return res.status(400).json({ error: 'Enter your name.' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  if (await User.findOne({ userId })) return res.status(409).json({ error: 'This ID is already taken.' });
  const user = await User.create({ userId, name, passwordHash: await bcrypt.hash(password, 10) });
  res.status(201).json({ token: sign(user), user: publicUser(user) });
}));

app.post('/api/auth/login', wrap(async (req, res) => {
  const userId = String((req.body || {}).userId || '').trim().toLowerCase();
  const password = String((req.body || {}).password || '');
  const user = await User.findOne({ userId });
  if (!user) return res.status(404).json({ code: 'NOT_REGISTERED', error: 'No account found with this ID.' });
  if (!(await bcrypt.compare(password, user.passwordHash))) return res.status(401).json({ error: 'Incorrect password.' });
  res.json({ token: sign(user), user: publicUser(user) });
}));

app.get('/api/auth/me', auth, wrap(async (req, res) => {
  const user = await User.findOne({ userId: req.auth.userId });
  if (!user) return res.status(401).json({ error: 'Account not found.' });
  res.json(publicUser(user));
}));

/* ---------- Users ---------- */
function ownerOnly(req, res, next) {
  if (req.params.id.toLowerCase() !== req.auth.userId && req.auth.role !== 'admin')
    return res.status(403).json({ error: 'Forbidden.' });
  next();
}

app.get('/api/users/:id', auth, ownerOnly, wrap(async (req, res) => {
  const id = req.params.id.toLowerCase();
  const user = await User.findOne({ userId: id });
  if (!user) return res.status(404).json({ error: 'User not found.' });
  const trades = await Trade.find({ userId: id }).sort({ time: -1 }).limit(500).lean();
  res.json({
    userId: user.userId, name: user.name, cashBalance: user.cashBalance, holdings: user.holdings || {},
    history: trades.map(t => ({ time: t.time, type: t.type, symbol: t.symbol, quantity: t.quantity, price: t.price, total: t.total }))
  });
}));

app.put('/api/users/:id', auth, ownerOnly, wrap(async (req, res) => {
  const name = String((req.body || {}).name || '').trim().slice(0, 60);
  if (!name) return res.status(400).json({ error: 'Name required.' });
  const user = await User.findOneAndUpdate({ userId: req.params.id.toLowerCase() }, { name }, { new: true });
  if (!user) return res.status(404).json({ error: 'User not found.' });
  res.json(publicUser(user));
}));

/* ---------- Trades ---------- */
app.post('/api/trades', auth, wrap(async (req, res) => {
  const { type, symbol } = req.body || {};
  const quantity = parseInt(req.body.quantity, 10);
  const price = Number(req.body.price);
  if (!['BUY', 'SELL'].includes(type)) return res.status(400).json({ error: 'Invalid trade type.' });
  if (!symbol || typeof symbol !== 'string' || symbol.length > 20 || /[.$]/.test(symbol)) return res.status(400).json({ error: 'Invalid symbol.' });
  if (!Number.isInteger(quantity) || quantity <= 0) return res.status(400).json({ error: 'Invalid quantity.' });
  if (!isFinite(price) || price <= 0) return res.status(400).json({ error: 'Invalid price.' });

  const user = await User.findOne({ userId: req.auth.userId });
  if (!user) return res.status(401).json({ error: 'Account not found.' });
  const total = price * quantity;
  const holdings = { ...(user.holdings || {}) };

  if (type === 'BUY') {
    if (user.cashBalance < total) return res.status(400).json({ error: 'Insufficient cash.' });
    const h = holdings[symbol];
    if (h) { const nq = h.quantity + quantity; holdings[symbol] = { quantity: nq, avgPrice: ((h.quantity * h.avgPrice) + total) / nq }; }
    else holdings[symbol] = { quantity, avgPrice: price };
    user.cashBalance -= total;
  } else {
    const h = holdings[symbol];
    if (!h || h.quantity < quantity) return res.status(400).json({ error: 'Not enough shares.' });
    h.quantity -= quantity;
    if (h.quantity === 0) delete holdings[symbol]; else holdings[symbol] = h;
    user.cashBalance += total;
  }
  user.holdings = holdings;
  user.markModified('holdings');
  await user.save();
  const trade = await Trade.create({ userId: user.userId, type, symbol, quantity, price, total });
  res.status(201).json({ ok: true, trade, cashBalance: user.cashBalance, holdings: user.holdings });
}));

/* ---------- News (Google News RSS) ---------- */
function decode(s) {
  return String(s || '').replace(/<!\[CDATA\[|\]\]>/g, '')
    .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'").trim();
}
function parseRss(xml, symbol) {
  const items = [];
  const re = /<item>([\s\S]*?)<\/item>/g; let m;
  const pick = (blk, tag) => { const r = new RegExp(`<${tag}[^>]*>([\\s\\S]*?)</${tag}>`).exec(blk); return r ? decode(r[1]) : ''; };
  while ((m = re.exec(xml)) && items.length < 15) {
    const b = m[1];
    items.push({ title: pick(b, 'title'), link: pick(b, 'link'), pubDate: pick(b, 'pubDate'), source: pick(b, 'source'), symbol: symbol || '' });
  }
  return items;
}
const newsCache = new Map();
async function fetchNews(q, symbol) {
  const hit = newsCache.get(q);
  if (hit && Date.now() - hit.t < 5 * 60 * 1000) return hit.items;
  const url = `https://news.google.com/rss/search?q=${encodeURIComponent(q)}&hl=en-IN&gl=IN&ceid=IN:en`;
  const r = await axios.get(url, { timeout: 8000, responseType: 'text' });
  const items = parseRss(r.data, symbol);
  newsCache.set(q, { t: Date.now(), items });
  return items;
}
app.get('/api/news', wrap(async (req, res) => {
  try {
    let items = [];
    if (req.query.market) items = await fetchNews('Indian stock market NSE Sensex Nifty when:2d', '');
    else {
      const syms = String(req.query.symbols || '').split(',').map(s => s.trim()).filter(Boolean).slice(0, 5);
      const lists = await Promise.all(syms.map(s => fetchNews(`${s} share NSE stock when:7d`, s).then(a => a.slice(0, 5)).catch(() => [])));
      items = lists.flat();
    }
    items.sort((a, b) => new Date(b.pubDate) - new Date(a.pubDate));
    res.json({ items: items.slice(0, 20) });
  } catch (e) { res.status(502).json({ error: 'News unavailable.' }); }
}));

/* ---------- Errors ---------- */
app.use('/api', (req, res) => res.status(404).json({ error: 'Not found.' }));
app.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: 'Server error.' }); });

/* ---------- DB init ---------- */
async function ensureAdmin() {
  const id = (process.env.ADMIN_USER || '').toLowerCase(), pw = process.env.ADMIN_PASSWORD;
  if (!id || !pw || pw.length < 8) return;
  if (await User.findOne({ userId: id })) return;
  await User.create({ userId: id, name: 'Admin', role: 'admin', passwordHash: await bcrypt.hash(pw, 10) });
  console.log('👑 Admin account created:', id);
}
async function seedDefaults() { /* nothing to seed yet */ }

const PORT = process.env.PORT || 5000;
let ready;
function init() {
  if (!process.env.MONGO_URI || !process.env.JWT_SECRET)
    return Promise.reject(new Error('Set MONGO_URI and JWT_SECRET'));
  if (!ready) ready = mongoose.connect(process.env.MONGO_URI).then(async () => {
    console.log('✅ MongoDB connected');
    await ensureAdmin();
    seedDefaults().catch(e => console.error('Seed error:', e.message));
  });
  return ready;
}

if (require.main === module) {
  init()
    .then(() => app.listen(PORT, '0.0.0.0', () => console.log(`🚀 Server running on port ${PORT}`)))
    .catch(err => { console.error('❌', err.message); process.exit(1); });
}

module.exports = { app, parseRss, init };