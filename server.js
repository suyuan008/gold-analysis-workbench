const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { URL } = require('node:url');
const { Pool } = require('pg');

const port = process.env.PORT || 4173;
const root = __dirname;
const dataDir = path.join(root, 'data');
const storeFile = path.join(dataDir, 'store.json');
const databaseUrl = process.env.DATABASE_URL || '';
const authSecret = process.env.AUTH_SECRET || 'change-me-in-production';
const pool = databaseUrl
  ? new Pool({
      connectionString: databaseUrl,
      ssl: process.env.PGSSLMODE === 'disable' ? false : { rejectUnauthorized: false },
    })
  : null;

const fallbackNews = [
  {
    title: 'Gold keeps a firm bid as traders watch inflation data',
    source: 'Google News',
    link: 'https://news.google.com/',
    published: new Date().toISOString(),
    summary: 'Inflation, yields and dollar direction remain the main drivers.',
  },
  {
    title: 'Central-bank buying still supports the long-term gold thesis',
    source: 'Google News',
    link: 'https://news.google.com/',
    published: new Date().toISOString(),
    summary: 'Structural demand keeps the long-term floor relevant.',
  },
];

const fallbackMarket = {
  symbol: 'XAUUSD',
  price: 4502.0,
  change: 14.2,
  changePct: 0.32,
  updatedAt: new Date().toISOString(),
  updatedAtReadable: 'fallback snapshot',
  silver: 76.8,
  dxy: 104.12,
  ust10y: 4.41,
  volatility: '中高',
  bias: '偏多震荡',
  score: 72,
  levels: ['4450.00', '4518.00', '4542.00'],
  indicators: {
    rsi: 64,
    macd: '偏强',
    adx: 26,
    atr: '18.8',
    pattern: '上升通道内回踩',
  },
  series: [],
};

let store = loadStore();
let latestMarket = null;
let previousMarket = null;
let latestNews = fallbackNews;
let newsRefreshedAt = 0;
let marketRefreshInFlight = null;
let marketRefreshedAt = 0;
let dbReady = false;
const clients = new Map();
let clientSeq = 0;

function ensureDataDir() {
  if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
}

function emptyStore() {
  return { users: [], rulesByUser: {}, notesByUser: {} };
}

function loadStore() {
  ensureDataDir();
  if (!fs.existsSync(storeFile)) {
    const initial = emptyStore();
    fs.writeFileSync(storeFile, JSON.stringify(initial, null, 2), 'utf8');
    return initial;
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(storeFile, 'utf8'));
    return {
      ...emptyStore(),
      ...parsed,
      users: Array.isArray(parsed.users) ? parsed.users : [],
      rulesByUser: parsed.rulesByUser && typeof parsed.rulesByUser === 'object' ? parsed.rulesByUser : {},
      notesByUser: parsed.notesByUser && typeof parsed.notesByUser === 'object' ? parsed.notesByUser : {},
    };
  } catch {
    const initial = emptyStore();
    fs.writeFileSync(storeFile, JSON.stringify(initial, null, 2), 'utf8');
    return initial;
  }
}

function persistStore() {
  ensureDataDir();
  const tmp = `${storeFile}.${Date.now()}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(store, null, 2), 'utf8');
  fs.renameSync(tmp, storeFile);
}

function sendJson(res, status, data) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
  });
  res.end(JSON.stringify(data));
}

function sendText(res, status, text, type = 'text/plain; charset=utf-8') {
  res.writeHead(status, {
    'Content-Type': type,
    'Cache-Control': 'no-store',
  });
  res.end(text);
}

function mimeType(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  if (ext === '.html') return 'text/html; charset=utf-8';
  if (ext === '.css') return 'text/css; charset=utf-8';
  if (ext === '.js') return 'application/javascript; charset=utf-8';
  if (ext === '.json') return 'application/json; charset=utf-8';
  return 'application/octet-stream';
}

function safeJoin(base, target) {
  const resolvedBase = path.resolve(base);
  const resolvedTarget = path.resolve(base, `.${target}`);
  return resolvedTarget === resolvedBase || resolvedTarget.startsWith(`${resolvedBase}${path.sep}`) ? resolvedTarget : null;
}

function parseCookies(req) {
  const raw = req.headers.cookie || '';
  return raw.split(';').reduce((acc, pair) => {
    const idx = pair.indexOf('=');
    if (idx === -1) return acc;
    const key = pair.slice(0, idx).trim();
    const value = pair.slice(idx + 1).trim();
    if (key) acc[key] = decodeURIComponent(value);
    return acc;
  }, {});
}

function passwordHash(salt, password) {
  return crypto.createHash('sha256').update(`${salt}:${password}`).digest('hex');
}

function signToken(userId) {
  const payload = Buffer.from(JSON.stringify({
    userId,
    exp: Date.now() + 1000 * 60 * 60 * 24 * 30,
  })).toString('base64url');
  const sig = crypto.createHmac('sha256', authSecret).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}

function verifyToken(token) {
  if (!token) return null;
  const [payload, sig] = String(token).split('.');
  if (!payload || !sig) return null;
  const expected = crypto.createHmac('sha256', authSecret).update(payload).digest('base64url');
  if (expected !== sig) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (!data.exp || Date.now() > data.exp) return null;
    return data.userId || null;
  } catch {
    return null;
  }
}

function setSessionCookie(res, token) {
  res.setHeader('Set-Cookie', [`gold_session=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${60 * 60 * 24 * 30}`]);
}

function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', ['gold_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0']);
}

function getUserFromStoreById(id) {
  return store.users.find((user) => user.id === id) || null;
}

function getUserFromStoreByUsername(username) {
  const key = username.trim().toLowerCase();
  return store.users.find((user) => user.usernameLower === key) || null;
}

async function ensureDb() {
  if (!pool || dbReady) return false;
  await pool.query(`
    CREATE TABLE IF NOT EXISTS gold_users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      username_lower TEXT UNIQUE NOT NULL,
      salt TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL
    );
    CREATE TABLE IF NOT EXISTS gold_rules (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES gold_users(id) ON DELETE CASCADE,
      label TEXT NOT NULL,
      type TEXT NOT NULL,
      value NUMERIC NOT NULL,
      level TEXT NOT NULL,
      enabled BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL
    );
    CREATE TABLE IF NOT EXISTS gold_notes (
      user_id TEXT PRIMARY KEY REFERENCES gold_users(id) ON DELETE CASCADE,
      text TEXT NOT NULL DEFAULT '',
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  dbReady = true;
  return true;
}

async function dbQuery(sql, params = []) {
  if (!pool) return null;
  await ensureDb();
  return pool.query(sql, params);
}

async function getCurrentUserAsync(req) {
  const token = parseCookies(req).gold_session;
  const userId = verifyToken(token);
  if (!userId) return null;
  if (pool) {
    const result = await dbQuery(
      'SELECT id, username, username_lower, salt, password_hash, created_at FROM gold_users WHERE id = $1 LIMIT 1',
      [userId]
    );
    const row = result.rows[0];
    if (!row) return null;
    return {
      id: row.id,
      username: row.username,
      usernameLower: row.username_lower,
      salt: row.salt,
      passwordHash: row.password_hash,
      createdAt: row.created_at,
    };
  }
  return getUserFromStoreById(userId);
}

function toPublicUser(user) {
  return {
    id: user.id,
    username: user.username,
    createdAt: user.createdAt,
  };
}

function normalizeRule(rule) {
  const value = Number(rule.value);
  if (!Number.isFinite(value)) return null;
  return {
    id: String(rule.id || crypto.randomUUID()),
    label: String(rule.label || '未命名规则').trim().slice(0, 60),
    type: rule.type === 'below' ? 'below' : 'above',
    value: Number(value.toFixed(2)),
    level: ['high', 'mid', 'low'].includes(rule.level) ? rule.level : 'mid',
    enabled: rule.enabled !== false,
    createdAt: rule.createdAt || new Date().toISOString(),
  };
}

function normalizeRules(rules) {
  const seen = new Set();
  const out = [];
  for (const rule of Array.isArray(rules) ? rules : []) {
    const clean = normalizeRule(rule);
    if (!clean) continue;
    const key = `${clean.label}|${clean.type}|${clean.value}|${clean.level}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(clean);
  }
  return out;
}

function getRulesForUser(userId) {
  return Array.isArray(store.rulesByUser[userId]) ? store.rulesByUser[userId] : [];
}

function setRulesForUser(userId, rules) {
  store.rulesByUser[userId] = normalizeRules(rules);
  persistStore();
  return store.rulesByUser[userId];
}

function getNotesForUser(userId) {
  return store.notesByUser[userId] || { text: '', updatedAt: null };
}

function setNotesForUser(userId, text) {
  store.notesByUser[userId] = {
    text: String(text || ''),
    updatedAt: new Date().toISOString(),
  };
  persistStore();
  return store.notesByUser[userId];
}

async function listUsers() {
  if (pool) {
    const result = await dbQuery('SELECT id, username, username_lower, salt, password_hash, created_at FROM gold_users');
    return result.rows.map((row) => ({
      id: row.id,
      username: row.username,
      usernameLower: row.username_lower,
      salt: row.salt,
      passwordHash: row.password_hash,
      createdAt: row.created_at,
    }));
  }
  return store.users;
}

async function getRulesForUserDb(userId) {
  if (pool) {
    const result = await dbQuery(
      'SELECT id, label, type, value, level, enabled, created_at FROM gold_rules WHERE user_id = $1 ORDER BY created_at DESC',
      [userId]
    );
    return result.rows.map((row) => ({
      id: row.id,
      label: row.label,
      type: row.type,
      value: Number(row.value),
      level: row.level,
      enabled: row.enabled,
      createdAt: row.created_at,
    }));
  }
  return getRulesForUser(userId);
}

function parseFeedItems(xml) {
  const items = [];
  const itemRegex = /<item>([\s\S]*?)<\/item>/g;
  let match;
  while ((match = itemRegex.exec(xml))) {
    const block = match[1];
    const textOf = (tag) => {
      const hit = block.match(new RegExp(`<${tag}>([\\s\\S]*?)<\\/${tag}>`, 'i'));
      if (!hit) return '';
      return hit[1]
        .replace(/<!\[CDATA\[(.*?)\]\]>/g, '$1')
        .replace(/&amp;/g, '&')
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>')
        .trim();
    };
    const title = textOf('title');
    if (!title) continue;
    items.push({
      title,
      link: textOf('link') || 'https://news.google.com',
      published: textOf('pubDate') || new Date().toISOString(),
      summary: textOf('description'),
      source: 'Google News',
    });
  }
  return items;
}

async function fetchJson(url) {
  const res = await fetch(url, { headers: { 'user-agent': 'Mozilla/5.0' } });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

async function fetchText(url) {
  const res = await fetch(url, { headers: { 'user-agent': 'Mozilla/5.0' } });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.text();
}

function generateSeries(basePrice, drift) {
  const points = [];
  let price = basePrice;
  for (let i = 0; i < 72; i += 1) {
    const wave = Math.sin(i / 4.5) * 1.6 + Math.cos(i / 9.5) * 0.9;
    const noise = (Math.sin(i * 1.7) + Math.cos(i * 0.9)) * 0.25;
    const open = price;
    const close = price + drift + wave * 0.35 + noise;
    const high = Math.max(open, close) + 1.4 + (i % 3) * 0.08;
    const low = Math.min(open, close) - 1.4 - ((i + 1) % 3) * 0.08;
    points.push({ open, high, low, close });
    price = close;
  }
  return points;
}

function deriveIndicators(series) {
  const closes = series.map((point) => point.close);
  const last = closes.at(-1);
  const prev = closes.at(-2) ?? last;
  const pct = prev ? ((last - prev) / prev) * 100 : 0;
  const avgRange = series.slice(-14).reduce((sum, point) => sum + (point.high - point.low), 0) / Math.max(1, Math.min(14, series.length));
  const rsi = Math.max(10, Math.min(90, Math.round(50 + pct * 900)));
  const adx = Math.max(12, Math.min(42, Math.round(18 + Math.abs(pct) * 7)));
  return {
    rsi,
    macd: pct >= 0 ? '偏强' : '偏弱',
    adx,
    atr: avgRange.toFixed(1),
    pattern: pct >= 0 ? '上升通道内回踩' : '短线修正',
  };
}

function sanitizeMarket(snapshot) {
  return {
    symbol: snapshot.symbol,
    price: snapshot.price,
    change: snapshot.change,
    changePct: snapshot.changePct,
    updatedAt: snapshot.updatedAt,
    updatedAtReadable: snapshot.updatedAtReadable,
    silver: snapshot.silver,
    dxy: snapshot.dxy,
    ust10y: snapshot.ust10y,
    volatility: snapshot.volatility,
    bias: snapshot.bias,
    score: snapshot.score,
    levels: snapshot.levels,
    indicators: snapshot.indicators,
    series: snapshot.series,
  };
}

async function refreshMarket(force = false) {
  const cacheAge = Date.now() - marketRefreshedAt;
  if (!force && latestMarket && cacheAge < 4500) return latestMarket;
  if (marketRefreshInFlight) return marketRefreshInFlight;
  marketRefreshInFlight = (async () => {
    let snapshot = fallbackMarket;
    try {
      const [gold, silver] = await Promise.all([
        fetchJson('https://api.gold-api.com/price/XAU'),
        fetchJson('https://api.gold-api.com/price/XAG'),
      ]);
      const price = Number(gold.price);
      const previousPrice = latestMarket?.price ?? (price - 14.2);
      const change = price - previousPrice;
      const changePct = previousPrice ? (change / previousPrice) * 100 : 0;
      const series = generateSeries(Math.max(2200, price - 40), change >= 0 ? 0.8 : -0.2);
      const indicators = deriveIndicators(series);
      previousMarket = latestMarket;
      snapshot = {
        symbol: 'XAUUSD',
        price,
        change,
        changePct,
        updatedAt: gold.updatedAt || new Date().toISOString(),
        updatedAtReadable: gold.updatedAtReadable || 'a few seconds ago',
        silver: Number(silver.price),
        dxy: 104.12,
        ust10y: 4.41,
        volatility: Math.abs(changePct) > 0.35 ? '中高' : '中',
        bias: price >= 4500 ? '趋势偏强' : '偏多震荡',
        score: price >= 4500 ? 78 : 72,
        levels: [price - 52, price + 18, price + 42].map((value) => value.toFixed(2)),
        indicators,
        series,
      };
    } catch {
      previousMarket = latestMarket;
      snapshot = latestMarket || fallbackMarket;
    }
    latestMarket = snapshot;
    marketRefreshedAt = Date.now();
    if (previousMarket) dispatchRuleCrossings(previousMarket, latestMarket);
    broadcastToAll('market', sanitizeMarket(latestMarket));
    return latestMarket;
  })().finally(() => {
    marketRefreshInFlight = null;
  });
  return marketRefreshInFlight;
}

async function refreshNews(force = false) {
  const cacheAge = Date.now() - newsRefreshedAt;
  if (!force && latestNews.length && cacheAge < 10 * 60 * 1000) return latestNews;
  try {
    const query = encodeURIComponent('gold price OR XAUUSD OR Federal Reserve OR inflation');
    const rssUrl = `https://news.google.com/rss/search?q=${query}&hl=en-US&gl=US&ceid=US:en`;
    const xml = await fetchText(rssUrl);
    const items = parseFeedItems(xml).slice(0, 6);
    latestNews = items.length ? items : fallbackNews;
  } catch {
    latestNews = fallbackNews;
  }
  newsRefreshedAt = Date.now();
  return latestNews;
}

function buildAlert(rule, price) {
  return {
    id: rule.id,
    label: rule.label,
    level: rule.level,
    message: `${rule.label} 触发：当前价 ${price.toFixed(2)} ${rule.type === 'above' ? '高于' : '低于'} ${Number(rule.value).toFixed(2)}`,
    triggeredAt: new Date().toISOString(),
  };
}

async function dispatchRuleCrossings(previous, current) {
  const users = await listUsers();
  for (const user of users) {
    const rules = await getRulesForUserDb(user.id);
    for (const rule of rules) {
      if (!rule.enabled) continue;
      const threshold = Number(rule.value);
      const prevState = rule.type === 'above' ? previous.price >= threshold : previous.price <= threshold;
      const nextState = rule.type === 'above' ? current.price >= threshold : current.price <= threshold;
      if (!prevState && nextState) {
        broadcastToUser(user.id, 'alert', buildAlert(rule, current.price));
      }
    }
  }
}

function sendEvent(res, event, data) {
  res.write(`event: ${event}\n`);
  res.write(`data: ${JSON.stringify(data)}\n\n`);
}

function broadcastToAll(event, data) {
  for (const client of clients.values()) sendEvent(client.res, event, data);
}

function broadcastToUser(userId, event, data) {
  for (const client of clients.values()) {
    if (client.userId === userId) sendEvent(client.res, event, data);
  }
}

async function handleAuthRegister(req, res) {
  const body = await readJson(req);
  const username = String(body.username || '').trim();
  const password = String(body.password || '');
  if (username.length < 2 || password.length < 6) {
    sendJson(res, 400, { error: 'invalid_input', message: '用户名至少 2 个字符，密码至少 6 个字符' });
    return;
  }
  if (pool) {
    const existing = await dbQuery('SELECT id FROM gold_users WHERE username_lower = $1 LIMIT 1', [username.toLowerCase()]);
    if (existing.rows[0]) {
      sendJson(res, 409, { error: 'user_exists', message: '这个用户名已经存在' });
      return;
    }
  } else if (getUserFromStoreByUsername(username)) {
    sendJson(res, 409, { error: 'user_exists', message: '这个用户名已经存在' });
    return;
  }

  const salt = crypto.randomBytes(16).toString('hex');
  const user = {
    id: crypto.randomUUID(),
    username,
    usernameLower: username.toLowerCase(),
    salt,
    passwordHash: passwordHash(salt, password),
    createdAt: new Date().toISOString(),
  };

  if (pool) {
    await dbQuery(
      `INSERT INTO gold_users (id, username, username_lower, salt, password_hash, created_at)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [user.id, user.username, user.usernameLower, user.salt, user.passwordHash, user.createdAt]
    );
  } else {
    store.users.push(user);
    persistStore();
  }

  setSessionCookie(res, signToken(user.id));
  sendJson(res, 200, { user: toPublicUser(user) });
}

async function handleAuthLogin(req, res) {
  const body = await readJson(req);
  const username = String(body.username || '').trim();
  const password = String(body.password || '');
  let user = null;

  if (pool) {
    const result = await dbQuery(
      'SELECT id, username, username_lower, salt, password_hash, created_at FROM gold_users WHERE username_lower = $1 LIMIT 1',
      [username.toLowerCase()]
    );
    const row = result.rows[0];
    if (row) {
      user = {
        id: row.id,
        username: row.username,
        usernameLower: row.username_lower,
        salt: row.salt,
        passwordHash: row.password_hash,
        createdAt: row.created_at,
      };
    }
  } else {
    user = getUserFromStoreByUsername(username);
  }

  if (!user || user.passwordHash !== passwordHash(user.salt, password)) {
    sendJson(res, 401, { error: 'invalid_credentials', message: '用户名或密码不正确' });
    return;
  }

  setSessionCookie(res, signToken(user.id));
  sendJson(res, 200, { user: toPublicUser(user) });
}

async function handleAuthLogout(req, res) {
  clearSessionCookie(res);
  sendJson(res, 200, { ok: true });
}

async function handleAuthMe(req, res) {
  const user = await getCurrentUserAsync(req);
  if (!user) {
    sendJson(res, 401, { user: null });
    return;
  }
  sendJson(res, 200, { user: toPublicUser(user) });
}

async function handleRulesGet(req, res) {
  const user = await getCurrentUserAsync(req);
  if (!user) {
    sendJson(res, 401, { error: 'unauthorized' });
    return;
  }
  if (pool) {
    const result = await dbQuery(
      'SELECT id, label, type, value, level, enabled, created_at FROM gold_rules WHERE user_id = $1 ORDER BY created_at DESC',
      [user.id]
    );
    sendJson(res, 200, {
      rules: result.rows.map((row) => ({
        id: row.id,
        label: row.label,
        type: row.type,
        value: Number(row.value),
        level: row.level,
        enabled: row.enabled,
        createdAt: row.created_at,
      })),
    });
    return;
  }
  sendJson(res, 200, { rules: getRulesForUser(user.id) });
}

async function handleRulesPost(req, res) {
  const user = await getCurrentUserAsync(req);
  if (!user) {
    sendJson(res, 401, { error: 'unauthorized', message: '请先登录再保存规则' });
    return;
  }
  const body = await readJson(req);
  const rules = normalizeRules(body.rules);
  if (pool) {
    await dbQuery('DELETE FROM gold_rules WHERE user_id = $1', [user.id]);
    for (const rule of rules) {
      await dbQuery(
        `INSERT INTO gold_rules (id, user_id, label, type, value, level, enabled, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
        [rule.id, user.id, rule.label, rule.type, rule.value, rule.level, rule.enabled, rule.createdAt]
      );
    }
  } else {
    setRulesForUser(user.id, rules);
  }
  sendJson(res, 200, { rules });
}

async function handleNotesGet(req, res) {
  const user = await getCurrentUserAsync(req);
  if (!user) {
    sendJson(res, 401, { error: 'unauthorized' });
    return;
  }
  if (pool) {
    const result = await dbQuery('SELECT text, updated_at FROM gold_notes WHERE user_id = $1 LIMIT 1', [user.id]);
    const row = result.rows[0];
    sendJson(res, 200, row ? { text: row.text, updatedAt: row.updated_at } : { text: '', updatedAt: null });
    return;
  }
  sendJson(res, 200, getNotesForUser(user.id));
}

async function handleNotesPost(req, res) {
  const user = await getCurrentUserAsync(req);
  if (!user) {
    sendJson(res, 401, { error: 'unauthorized', message: '请先登录再保存笔记' });
    return;
  }
  const body = await readJson(req);
  if (pool) {
    await dbQuery(
      `INSERT INTO gold_notes (user_id, text, updated_at)
       VALUES ($1, $2, NOW())
       ON CONFLICT (user_id)
       DO UPDATE SET text = EXCLUDED.text, updated_at = NOW()`,
      [user.id, String(body.text || '')]
    );
    sendJson(res, 200, { text: String(body.text || ''), updatedAt: new Date().toISOString() });
    return;
  }
  sendJson(res, 200, setNotesForUser(user.id, body.text || ''));
}

async function handleAlerts(req, res) {
  const user = await getCurrentUserAsync(req);
  const body = req.method === 'POST' ? await readJson(req) : {};
  const rules = normalizeRules(body.rules || (user ? await getRulesForUserDb(user.id) : []));
  const snapshot = latestMarket || (await refreshMarket(false)) || fallbackMarket;
  const alerts = [];
  for (const rule of rules) {
    if (!rule.enabled) continue;
    const hit = rule.type === 'above' ? snapshot.price >= rule.value : snapshot.price <= rule.value;
    if (hit) alerts.push(buildAlert(rule, snapshot.price));
  }
  sendJson(res, 200, { alerts, snapshot: { price: snapshot.price, updatedAt: snapshot.updatedAt } });
}

function startSse(req, res) {
  getCurrentUserAsync(req).then((user) => {
    const id = ++clientSeq;
    clients.set(id, { res, userId: user?.id || null });
    res.writeHead(200, {
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no',
    });
    res.write(`event: hello\ndata: ${JSON.stringify({ ok: true, user: user ? toPublicUser(user) : null })}\n\n`);
    if (latestMarket) sendEvent(res, 'market', sanitizeMarket(latestMarket));
    if (latestNews.length) sendEvent(res, 'news', latestNews);
    const ping = setInterval(() => {
      res.write(': ping\n\n');
    }, 20000);
    req.on('close', () => {
      clearInterval(ping);
      clients.delete(id);
    });
  }).catch(() => {
    res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('SSE failed');
  });
}

function serveStatic(req, res, requestUrl) {
  const relPath = requestUrl.pathname === '/' ? '/index.html' : requestUrl.pathname;
  const filePath = safeJoin(root, relPath);
  if (!filePath) {
    sendText(res, 403, 'Forbidden');
    return;
  }
  fs.readFile(filePath, (err, data) => {
    if (err) {
      sendText(res, 404, 'Not found');
      return;
    }
    res.writeHead(200, {
      'Content-Type': mimeType(filePath),
      'Cache-Control': 'no-store',
    });
    res.end(data);
  });
}

async function route(req, res) {
  const requestUrl = new URL(req.url, `http://${req.headers.host}`);

  if (requestUrl.pathname === '/api/health') {
    sendJson(res, 200, { ok: true, time: new Date().toISOString() });
    return;
  }

  if (requestUrl.pathname === '/api/market') {
    const force = requestUrl.searchParams.get('force') === '1';
    const snapshot = force || !latestMarket ? await refreshMarket(force) : latestMarket;
    sendJson(res, 200, sanitizeMarket(snapshot));
    return;
  }

  if (requestUrl.pathname === '/api/news') {
    const items = await refreshNews(false);
    sendJson(res, 200, { items, source: 'google_news_rss' });
    return;
  }

  if (requestUrl.pathname === '/api/events') {
    startSse(req, res);
    return;
  }

  if (requestUrl.pathname === '/api/auth/register' && req.method === 'POST') {
    await handleAuthRegister(req, res);
    return;
  }
  if (requestUrl.pathname === '/api/auth/login' && req.method === 'POST') {
    await handleAuthLogin(req, res);
    return;
  }
  if (requestUrl.pathname === '/api/auth/logout' && req.method === 'POST') {
    await handleAuthLogout(req, res);
    return;
  }
  if (requestUrl.pathname === '/api/auth/me' && req.method === 'GET') {
    await handleAuthMe(req, res);
    return;
  }

  if (requestUrl.pathname === '/api/rules' && req.method === 'GET') {
    await handleRulesGet(req, res);
    return;
  }
  if (requestUrl.pathname === '/api/rules' && req.method === 'POST') {
    await handleRulesPost(req, res);
    return;
  }

  if (requestUrl.pathname === '/api/notes' && req.method === 'GET') {
    await handleNotesGet(req, res);
    return;
  }
  if (requestUrl.pathname === '/api/notes' && req.method === 'POST') {
    await handleNotesPost(req, res);
    return;
  }

  if (requestUrl.pathname === '/api/alerts' && (req.method === 'GET' || req.method === 'POST')) {
    await handleAlerts(req, res);
    return;
  }

  serveStatic(req, res, requestUrl);
}

async function bootstrap() {
  ensureDataDir();
  if (pool) await ensureDb();
  await refreshMarket();
  await refreshNews(true);
  setInterval(() => {
    refreshMarket().catch(() => {});
  }, 5000);
  setInterval(() => {
    refreshNews(false).catch(() => {});
  }, 10 * 60 * 1000);
}

bootstrap().catch(() => {});

http.createServer((req, res) => {
  route(req, res).catch((err) => {
    sendJson(res, 500, { error: 'server_error', message: String(err.message || err) });
  });
}).listen(port, () => {
  console.log(`Serving http://localhost:${port}`);
});
