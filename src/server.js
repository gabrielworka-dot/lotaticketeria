/**
 * LOTA TICKETERIA — Plataforma de Ingressos e Comunidade
 * Inspirado em Tri.RS (marketplace) + Cheers (comunidade, promoters, cortesia)
 */

const express = require('express');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const fetch   = require('node-fetch');
const fs      = require('fs');
const path    = require('path');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'role_dev_secret_change_in_prod';

// ── Security headers ──────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

// ── Rate limiting ──────────────────────────────────────────
const rateLimits = new Map();
function rateLimit(windowMs = 60000, max = 30) {
  return (req, res, next) => {
    const key = req.ip + (req.path || '');
    const now = Date.now();
    const r = rateLimits.get(key) || { count: 0, start: now };
    if (now - r.start > windowMs) { r.count = 0; r.start = now; }
    r.count++;
    rateLimits.set(key, r);
    if (r.count > max) return res.status(429).json({ error: 'Muitas requisições. Aguarde um momento.' });
    next();
  };
}
setInterval(() => { const now = Date.now(); rateLimits.forEach((v,k) => { if (now - v.start > 120000) rateLimits.delete(k); }); }, 60000);

// ── Paths ─────────────────────────────────────────────────
const DATA_DIR = fs.existsSync('/app') ? '/app' : path.join(__dirname, '..');
const POSSIBLE_PUBLIC = [ path.join(__dirname, '../public'), path.join(process.cwd(), 'public'), '/app/public' ];
const PUBLIC_DIR = POSSIBLE_PUBLIC.find(p => { try { return fs.existsSync(path.join(p,'index.html')); } catch(e) { return false; }}) || path.join(__dirname,'../public');

app.use(express.json({ limit: '5mb' }));
app.use(express.static(PUBLIC_DIR));

function esc(s) { return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function sanitize(str, maxLen = 500) {
  if (typeof str !== 'string') return '';
  return str.trim().slice(0, maxLen).replace(/<[^>]*>/g, '');
}
function slugify(str) {
  return String(str || '')
    .toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '').slice(0, 50) || 'item';
}
function gerarSlugUnico(nome, existentes) {
  const base = slugify(nome);
  let slug = base;
  let i = 1;
  while (existentes.includes(slug)) { slug = base + '-' + (++i); }
  return slug;
}
function gerarCodigoTicket() {
  return 'RL-' + uuidv4().split('-')[0].toUpperCase() + '-' + Math.random().toString(36).slice(2, 6).toUpperCase();
}
function gerarCodigoPromoter() {
  return Math.random().toString(36).slice(2, 8).toUpperCase();
}

// ── Database (usuários) ───────────────────────────────────
const DB_FILE = path.join(DATA_DIR, 'db.json');
function loadDB() {
  try { if (fs.existsSync(DB_FILE)) return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch(e) {}
  return {
    users: [{
      id: 'admin-001', nome: 'Administrador', email: 'admin@role.com',
      senha: bcrypt.hashSync('admin123', 12),
      isAdmin: true, isOrganizador: true, organizadorSlug: 'role-admin',
      bio: '', avatarUrl: '', bannerUrl: '', redesSociais: {},
      createdAt: new Date().toISOString()
    }],
    ticketSlugs: {}, marketplaceFeePercent: 10, loginAttempts: {}
  };
}
function saveDB(d) { try { fs.writeFileSync(DB_FILE, JSON.stringify(d, null, 2)); } catch(e) {} }
let db = loadDB();
if (!db.loginAttempts) db.loginAttempts = {};
if (!db.ticketSlugs) db.ticketSlugs = {};
if (db.marketplaceFeePercent === undefined) db.marketplaceFeePercent = 10;
console.log(`✅ Banco carregado: ${db.users.length} usuário(s)`);

// ── Coleções em arquivo (eventos, pedidos, posts, follows) ──
function loadColecao(nome) {
  try { const f = path.join(DATA_DIR, nome + '.json'); if (fs.existsSync(f)) return JSON.parse(fs.readFileSync(f, 'utf8')); } catch(e) {}
  return [];
}
function saveColecao(nome, arr) { try { fs.writeFileSync(path.join(DATA_DIR, nome + '.json'), JSON.stringify(arr)); } catch(e) {} }
let EVENTOS  = loadColecao('eventos');
let PEDIDOS  = loadColecao('pedidos');
let POSTS    = loadColecao('posts');
let FOLLOWS  = loadColecao('follows');
function persistEventos() { saveColecao('eventos', EVENTOS); }
function persistPedidos() { saveColecao('pedidos', PEDIDOS); }
function persistPosts()   { saveColecao('posts', POSTS); }
function persistFollows() { saveColecao('follows', FOLLOWS); }

// ── Auth helpers ──────────────────────────────────────────
function auth(req, res, next) {
  const token = (req.headers['authorization'] || '').replace('Bearer ', '').trim();
  if (!token) return res.status(401).json({ error: 'Token não enviado.' });
  try {
    const dec = jwt.verify(token, JWT_SECRET);
    const user = db.users.find(u => u.id === dec.id);
    if (!user) return res.status(401).json({ error: 'Sessão inválida.' });
    req.user = user;
    next();
  } catch(e) { return res.status(401).json({ error: 'Token inválido ou expirado.' }); }
}
function organizadorOnly(req, res, next) {
  if (!req.user.isOrganizador) return res.status(403).json({ error: 'Apenas organizadores podem acessar isso.' });
  next();
}
function adminOnly(req, res, next) {
  if (!req.user.isAdmin) return res.status(403).json({ error: 'Acesso restrito.' });
  next();
}
function safe(u) { const { senha, mpAccount, ...r } = u; return { ...r, mpConectado: !!mpAccount?.accessToken }; }
function eventoDoUsuario(eventoId, userId) {
  const ev = EVENTOS.find(e => e.id === eventoId);
  if (!ev || ev.organizadorId !== userId) return null;
  return ev;
}

// ════════════════════════════════════════════════════════
// AUTH
// ════════════════════════════════════════════════════════
app.post('/api/auth/registro', rateLimit(60000, 10), (req, res) => {
  const nome = sanitize(req.body.nome || '', 100);
  const email = sanitize(req.body.email || '', 150).toLowerCase();
  const senha = (req.body.senha || '').slice(0, 200);
  if (!nome || !email || !senha) return res.status(400).json({ error: 'Preencha todos os campos.' });
  if (senha.length < 6) return res.status(400).json({ error: 'Senha deve ter pelo menos 6 caracteres.' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'E-mail inválido.' });
  if (db.users.find(u => u.email === email)) return res.status(400).json({ error: 'E-mail já cadastrado.' });
  const user = {
    id: uuidv4(), nome, email, senha: bcrypt.hashSync(senha, 12),
    isAdmin: false, isOrganizador: false, organizadorSlug: '',
    bio: '', avatarUrl: '', bannerUrl: '', redesSociais: {},
    createdAt: new Date().toISOString()
  };
  db.users.push(user); saveDB(db);
  const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '30d' });
  res.status(201).json({ token, user: safe(user) });
});

app.post('/api/auth/login', rateLimit(60000, 10), (req, res) => {
  const email = sanitize(req.body.email || '', 150).toLowerCase();
  const senha = (req.body.senha || '').slice(0, 200);
  const ip = req.ip;
  const attempts = db.loginAttempts[ip] || { count: 0, lastAttempt: 0 };
  const now = Date.now();
  if (attempts.count >= 5 && now - attempts.lastAttempt < 300000) return res.status(429).json({ error: 'Muitas tentativas. Aguarde 5 minutos.' });
  const user = db.users.find(u => u.email === email);
  if (!user || !bcrypt.compareSync(senha, user.senha)) {
    db.loginAttempts[ip] = { count: (attempts.count || 0) + 1, lastAttempt: now }; saveDB(db);
    return res.status(401).json({ error: 'E-mail ou senha incorretos.' });
  }
  delete db.loginAttempts[ip]; saveDB(db);
  const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: safe(user) });
});

app.get('/api/auth/me', auth, (req, res) => res.json({ user: safe(req.user) }));

app.patch('/api/auth/perfil', auth, (req, res) => {
  const user = db.users.find(u => u.id === req.user.id);
  const { nome, bio, avatarUrl, bannerUrl, redesSociais, senhaAtual, novaSenha } = req.body;
  if (nome) user.nome = sanitize(nome, 100);
  if (bio !== undefined) user.bio = sanitize(bio, 500);
  if (avatarUrl !== undefined) user.avatarUrl = sanitize(avatarUrl, 300);
  if (bannerUrl !== undefined) user.bannerUrl = sanitize(bannerUrl, 300);
  if (redesSociais) user.redesSociais = { instagram: sanitize(redesSociais.instagram||'',60), tiktok: sanitize(redesSociais.tiktok||'',60), site: sanitize(redesSociais.site||'',200) };
  if (novaSenha) {
    if (!senhaAtual || !bcrypt.compareSync(senhaAtual, user.senha)) return res.status(401).json({ error: 'Senha atual incorreta.' });
    if (novaSenha.length < 6) return res.status(400).json({ error: 'Nova senha muito curta.' });
    user.senha = bcrypt.hashSync(novaSenha, 12);
  }
  saveDB(db);
  res.json({ user: safe(user) });
});

app.post('/api/auth/tornar-organizador', auth, (req, res) => {
  const user = db.users.find(u => u.id === req.user.id);
  if (user.isOrganizador) return res.json({ user: safe(user) });
  const { nomePublico, bio } = req.body;
  if (!nomePublico) return res.status(400).json({ error: 'Nome público obrigatório.' });
  const slugsExistentes = db.users.filter(u => u.organizadorSlug).map(u => u.organizadorSlug);
  user.isOrganizador = true;
  user.nomePublico = sanitize(nomePublico, 100);
  user.organizadorSlug = gerarSlugUnico(nomePublico, slugsExistentes);
  user.bio = sanitize(bio || '', 500);
  saveDB(db);
  res.json({ user: safe(user) });
});

// ════════════════════════════════════════════════════════
// MERCADO PAGO OAUTH (marketplace/split — mesmo padrão validado no Lota)
// ════════════════════════════════════════════════════════
const MP_CLIENT_ID     = process.env.MP_CLIENT_ID || '';
const MP_CLIENT_SECRET = process.env.MP_CLIENT_SECRET || '';
const MP_API = 'https://api.mercadopago.com';
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const RESEND_FROM    = process.env.RESEND_FROM_EMAIL || 'Lota Ticketeria <onboarding@resend.dev>';

app.get('/api/mp/oauth/connect', auth, (req, res) => {
  if (!MP_CLIENT_ID) return res.status(400).json({ error: 'Marketplace do Mercado Pago não configurado (MP_CLIENT_ID ausente).' });
  const state = jwt.sign({ uid: req.user.id }, JWT_SECRET, { expiresIn: '15m' });
  const host = req.get('host'); const proto = req.get('x-forwarded-proto') || 'https';
  const redirectUri = `${proto}://${host}/api/mp/oauth/callback`;
  const url = `https://auth.mercadopago.com/authorization?client_id=${MP_CLIENT_ID}&response_type=code&platform_id=mp&state=${encodeURIComponent(state)}&redirect_uri=${encodeURIComponent(redirectUri)}`;
  res.json({ url });
});

app.get('/api/mp/oauth/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code || !state) return res.status(400).send('Parâmetros inválidos.');
    let uid; try { uid = jwt.verify(state, JWT_SECRET).uid; } catch(e) { return res.status(400).send('Sessão expirada, tente novamente.'); }
    const host = req.get('host'); const proto = req.get('x-forwarded-proto') || 'https';
    const redirectUri = `${proto}://${host}/api/mp/oauth/callback`;
    const tokenResp = await fetch(`${MP_API}/oauth/token`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_id: MP_CLIENT_ID, client_secret: MP_CLIENT_SECRET, grant_type: 'authorization_code', code, redirect_uri: redirectUri })
    });
    const tokenData = await tokenResp.json();
    if (!tokenResp.ok) return res.status(400).send('Erro ao conectar: ' + (tokenData.message || 'tente novamente'));
    const user = db.users.find(u => u.id === uid);
    if (user) {
      user.mpAccount = {
        accessToken: tokenData.access_token, refreshToken: tokenData.refresh_token,
        mpUserId: tokenData.user_id, testMode: tokenData.live_mode === false,
        connectedAt: new Date().toISOString()
      };
      saveDB(db);
    }
    res.send(`<html><body style="background:#0F0E0C;color:#F0EDE8;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0"><div style="text-align:center"><div style="font-size:40px;margin-bottom:12px">✅</div><h2>Conta Mercado Pago conectada!</h2><p style="color:#A09880">Pode fechar esta janela e voltar à Lota Ticketeria.</p></div></body></html>`);
  } catch(e) { res.status(500).send('Erro: ' + e.message); }
});

app.get('/api/mp/status', auth, (req, res) => {
  const acc = req.user.mpAccount;
  res.json({ connected: !!acc?.accessToken, mpUserId: acc?.mpUserId || null, testMode: !!acc?.testMode, feePercent: db.marketplaceFeePercent });
});
app.post('/api/mp/disconnect', auth, (req, res) => {
  const user = db.users.find(u => u.id === req.user.id);
  if (user) { delete user.mpAccount; saveDB(db); }
  res.json({ ok: true });
});

// ════════════════════════════════════════════════════════
// EVENTOS (organizador)
// ════════════════════════════════════════════════════════
app.get('/api/meus-eventos', auth, organizadorOnly, (req, res) => {
  res.json({ eventos: EVENTOS.filter(e => e.organizadorId === req.user.id) });
});

app.post('/api/eventos', auth, organizadorOnly, (req, res) => {
  const { nome, descricao, dataEvento, horaEvento, local, cidade, categoria, imagemCapa } = req.body;
  if (!nome || !dataEvento) return res.status(400).json({ error: 'Nome e data obrigatórios.' });
  const slugsExistentes = Object.keys(db.ticketSlugs);
  const slug = gerarSlugUnico(nome, slugsExistentes);
  const evento = {
    id: uuidv4(), organizadorId: req.user.id, slug,
    nome: sanitize(nome, 100), descricao: sanitize(descricao || '', 2000),
    dataEvento, horaEvento: sanitize(horaEvento || '', 10),
    local: sanitize(local || '', 150), cidade: sanitize(cidade || '', 80),
    categoria: sanitize(categoria || 'Festas e shows', 40),
    imagemCapa: sanitize(imagemCapa || '', 300),
    status: 'rascunho',
    cores: { primaria: '#C47B14', fundo: '#18160F' },
    lotes: [], cupons: [], promoters: [],
    pixels: { metaPixelId: '', tiktokPixelId: '', gaMeasurementId: '', googleAdsConversionId: '', googleAdsConversionLabel: '' },
    politicaCancelamento: 'sem-cancelamento',
    createdAt: new Date().toISOString(), updatedAt: new Date().toISOString()
  };
  EVENTOS.push(evento);
  db.ticketSlugs[slug] = { userId: req.user.id, eventoId: evento.id };
  saveDB(db); persistEventos();
  res.status(201).json({ evento });
});

app.get('/api/eventos/:id', auth, (req, res) => {
  const ev = eventoDoUsuario(req.params.id, req.user.id);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  res.json({ evento: ev });
});

app.patch('/api/eventos/:id', auth, (req, res) => {
  const ev = eventoDoUsuario(req.params.id, req.user.id);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  const campos = ['nome','descricao','dataEvento','horaEvento','local','cidade','categoria','imagemCapa','politicaCancelamento'];
  campos.forEach(c => { if (req.body[c] !== undefined) ev[c] = typeof req.body[c] === 'string' ? sanitize(req.body[c], c === 'descricao' ? 2000 : 150) : req.body[c]; });
  if (req.body.cores) ev.cores = req.body.cores;
  ev.updatedAt = new Date().toISOString();
  persistEventos();
  res.json({ evento: ev });
});

app.patch('/api/eventos/:id/publicar', auth, (req, res) => {
  const ev = eventoDoUsuario(req.params.id, req.user.id);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  if (req.body.publicar && !req.user.mpAccount?.accessToken) return res.status(400).json({ error: 'Conecte sua conta Mercado Pago antes de publicar.' });
  ev.status = req.body.publicar ? 'publicado' : 'rascunho';
  ev.updatedAt = new Date().toISOString();
  persistEventos();
  res.json({ evento: ev });
});

app.delete('/api/eventos/:id', auth, (req, res) => {
  const ev = eventoDoUsuario(req.params.id, req.user.id);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  EVENTOS = EVENTOS.filter(e => e.id !== req.params.id);
  delete db.ticketSlugs[ev.slug];
  saveDB(db); persistEventos();
  res.json({ ok: true });
});

// ── LOTES ──
app.patch('/api/eventos/:id/lotes', auth, (req, res) => {
  const ev = eventoDoUsuario(req.params.id, req.user.id);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  if (!Array.isArray(req.body.lotes)) return res.status(400).json({ error: 'Lotes inválidos.' });
  ev.lotes = req.body.lotes.map(l => ({
    id: l.id || uuidv4(), nome: sanitize(l.nome || 'Lote', 60),
    preco: l.cortesia ? 0 : Math.max(0, parseFloat(l.preco) || 0),
    qtdTotal: Math.max(0, parseInt(l.qtdTotal) || 0), vendidos: parseInt(l.vendidos) || 0,
    ativo: l.ativo !== false, cortesia: !!l.cortesia, exclusivoPromoter: !!l.exclusivoPromoter
  }));
  ev.updatedAt = new Date().toISOString();
  persistEventos();
  res.json({ evento: ev });
});

// ── CUPONS ──
app.post('/api/eventos/:id/cupons', auth, (req, res) => {
  const ev = eventoDoUsuario(req.params.id, req.user.id);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  const { codigo, tipo, valor, usosMax } = req.body;
  if (!codigo || !tipo || !valor) return res.status(400).json({ error: 'Preencha código, tipo e valor.' });
  const codigoNorm = sanitize(codigo, 30).toUpperCase();
  if (ev.cupons.find(c => c.codigo === codigoNorm)) return res.status(400).json({ error: 'Já existe um cupom com esse código.' });
  ev.cupons.push({ id: uuidv4(), codigo: codigoNorm, tipo: tipo === 'fixo' ? 'fixo' : 'percentual', valor: Math.max(0, parseFloat(valor) || 0), usosMax: parseInt(usosMax) || 0, usosAtuais: 0, ativo: true, createdAt: new Date().toISOString() });
  ev.updatedAt = new Date().toISOString();
  persistEventos();
  res.status(201).json({ evento: ev });
});
app.patch('/api/eventos/:id/cupons/:cupomId', auth, (req, res) => {
  const ev = eventoDoUsuario(req.params.id, req.user.id);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  const c = ev.cupons.find(x => x.id === req.params.cupomId);
  if (!c) return res.status(404).json({ error: 'Cupom não encontrado.' });
  if (req.body.ativo !== undefined) c.ativo = !!req.body.ativo;
  if (req.body.usosMax !== undefined) c.usosMax = parseInt(req.body.usosMax) || 0;
  persistEventos();
  res.json({ evento: ev });
});
app.delete('/api/eventos/:id/cupons/:cupomId', auth, (req, res) => {
  const ev = eventoDoUsuario(req.params.id, req.user.id);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  ev.cupons = ev.cupons.filter(c => c.id !== req.params.cupomId);
  persistEventos();
  res.json({ evento: ev });
});

// ── PROMOTERS ──
app.post('/api/eventos/:id/promoters', auth, (req, res) => {
  const ev = eventoDoUsuario(req.params.id, req.user.id);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  const { nome, email, comissaoPercentual } = req.body;
  if (!nome) return res.status(400).json({ error: 'Nome do promoter obrigatório.' });
  ev.promoters.push({
    id: uuidv4(), nome: sanitize(nome, 100), email: sanitize(email || '', 150),
    codigoRef: gerarCodigoPromoter(), comissaoPercentual: Math.max(0, Math.min(100, parseFloat(comissaoPercentual) || 10)),
    vendas: 0, receita: 0, ativo: true, createdAt: new Date().toISOString()
  });
  ev.updatedAt = new Date().toISOString();
  persistEventos();
  res.status(201).json({ evento: ev });
});
app.patch('/api/eventos/:id/promoters/:promoterId', auth, (req, res) => {
  const ev = eventoDoUsuario(req.params.id, req.user.id);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  const p = ev.promoters.find(x => x.id === req.params.promoterId);
  if (!p) return res.status(404).json({ error: 'Promoter não encontrado.' });
  if (req.body.nome) p.nome = sanitize(req.body.nome, 100);
  if (req.body.comissaoPercentual !== undefined) p.comissaoPercentual = Math.max(0, Math.min(100, parseFloat(req.body.comissaoPercentual) || 0));
  if (req.body.ativo !== undefined) p.ativo = !!req.body.ativo;
  persistEventos();
  res.json({ evento: ev });
});
app.delete('/api/eventos/:id/promoters/:promoterId', auth, (req, res) => {
  const ev = eventoDoUsuario(req.params.id, req.user.id);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  ev.promoters = ev.promoters.filter(p => p.id !== req.params.promoterId);
  persistEventos();
  res.json({ evento: ev });
});

// ── PIXELS / ANALYTICS ──
app.patch('/api/eventos/:id/pixels', auth, (req, res) => {
  const ev = eventoDoUsuario(req.params.id, req.user.id);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  const { metaPixelId, tiktokPixelId, gaMeasurementId, googleAdsConversionId, googleAdsConversionLabel } = req.body;
  ev.pixels = {
    metaPixelId: sanitize(metaPixelId || '', 40), tiktokPixelId: sanitize(tiktokPixelId || '', 40),
    gaMeasurementId: sanitize(gaMeasurementId || '', 40), googleAdsConversionId: sanitize(googleAdsConversionId || '', 40),
    googleAdsConversionLabel: sanitize(googleAdsConversionLabel || '', 60)
  };
  ev.updatedAt = new Date().toISOString();
  persistEventos();
  res.json({ evento: ev });
});

// ════════════════════════════════════════════════════════
// RELATÓRIOS, PARTICIPANTES, BORDERÔ
// ════════════════════════════════════════════════════════
app.get('/api/eventos/:id/pedidos', auth, (req, res) => {
  const ev = eventoDoUsuario(req.params.id, req.user.id);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  res.json({ pedidos: PEDIDOS.filter(p => p.eventoId === ev.id) });
});

app.get('/api/eventos/:id/relatorio', auth, (req, res) => {
  const ev = eventoDoUsuario(req.params.id, req.user.id);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  const pedidos = PEDIDOS.filter(p => p.eventoId === ev.id && p.status === 'pago');
  const totalReceita = pedidos.reduce((s,p) => s + p.total, 0);
  const totalIngressos = pedidos.reduce((s,p) => s + (p.tickets||[]).length, 0);
  const porLote = {};
  ev.lotes.forEach(l => { porLote[l.nome] = { vendidos: l.vendidos, receita: 0 }; });
  pedidos.forEach(p => (p.itens||[]).forEach(it => {
    const lote = ev.lotes.find(l => l.id === it.loteId);
    if (lote && porLote[lote.nome]) porLote[lote.nome].receita += (it.precoUnit || 0) * (it.qtd || 0);
  }));
  const porDia = {};
  pedidos.forEach(p => { const d = p.pagoEm ? p.pagoEm.slice(0,10) : p.createdAt.slice(0,10); if (!porDia[d]) porDia[d] = { qtd: 0, receita: 0 }; porDia[d].qtd += (p.tickets||[]).length; porDia[d].receita += p.total; });
  const porPromoter = ev.promoters.map(pr => ({ nome: pr.nome, vendas: pr.vendas, receita: pr.receita }));
  const porCupom = ev.cupons.map(c => ({ codigo: c.codigo, usos: c.usosAtuais }));
  res.json({ totalReceita, totalIngressos, totalPedidos: pedidos.length, porLote, porDia, porPromoter, porCupom });
});

app.get('/api/eventos/:id/participantes.csv', auth, (req, res) => {
  const ev = eventoDoUsuario(req.params.id, req.user.id);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  const pedidos = PEDIDOS.filter(p => p.eventoId === ev.id && p.status === 'pago');
  const linhas = [['Nome','E-mail','Telefone','Lote','Código Ingresso','Usado','Data da Compra']];
  pedidos.forEach(p => (p.tickets||[]).forEach(t => {
    linhas.push([p.comprador?.nome||'', p.comprador?.email||'', p.comprador?.telefone||'', t.loteNome||'', t.codigo, t.usado?'Sim':'Não', new Date(p.createdAt).toLocaleString('pt-BR')]);
  }));
  const csv = linhas.map(r => r.map(v => '"'+String(v).replace(/"/g,'""')+'"').join(';')).join('\r\n');
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="participantes-${ev.slug}.csv"`);
  res.send('\uFEFF' + csv);
});

app.get('/api/eventos/:id/bordero.csv', auth, (req, res) => {
  const ev = eventoDoUsuario(req.params.id, req.user.id);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  const pedidos = PEDIDOS.filter(p => p.eventoId === ev.id && p.status === 'pago');
  const feePercent = db.marketplaceFeePercent || 10;
  const linhas = [
    ['BORDERÔ DE VENDAS — ' + ev.nome],
    ['Data de emissão', new Date().toLocaleString('pt-BR')],
    [''],
    ['Pedido','Comprador','E-mail','Itens','Valor Bruto (R$)','Comissão Plataforma (R$)','Valor Líquido (R$)','Status','Data']
  ];
  let totalBruto = 0, totalComissao = 0;
  pedidos.forEach(p => {
    const comissao = Math.round(p.total * (feePercent/100) * 100) / 100;
    totalBruto += p.total; totalComissao += comissao;
    linhas.push([p.id.slice(0,8), p.comprador?.nome||'', p.comprador?.email||'', (p.tickets||[]).length, p.total.toFixed(2).replace('.',','), comissao.toFixed(2).replace('.',','), (p.total-comissao).toFixed(2).replace('.',','), p.status, new Date(p.createdAt).toLocaleDateString('pt-BR')]);
  });
  linhas.push(['']);
  linhas.push(['TOTAL', '', '', '', totalBruto.toFixed(2).replace('.',','), totalComissao.toFixed(2).replace('.',','), (totalBruto-totalComissao).toFixed(2).replace('.',','), '', '']);
  const csv = linhas.map(r => r.map(v => '"'+String(v).replace(/"/g,'""')+'"').join(';')).join('\r\n');
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="bordero-${ev.slug}.csv"`);
  res.send('\uFEFF' + csv);
});

// ── CHECK-IN ──
app.post('/api/checkin/validar', auth, rateLimit(60000, 60), (req, res) => {
  const { eventoId, codigo } = req.body;
  const ev = eventoDoUsuario(eventoId, req.user.id);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  const pedidos = PEDIDOS.filter(p => p.eventoId === eventoId);
  let ticket = null, pedido = null;
  for (const p of pedidos) { const t = (p.tickets||[]).find(tk => tk.codigo === sanitize(codigo, 40)); if (t) { ticket = t; pedido = p; break; } }
  if (!ticket) return res.status(404).json({ error: 'Ingresso não encontrado.', valido: false });
  if (ticket.usado) return res.json({ valido: false, jaUsado: true, usadoEm: ticket.usadoEm, ticket, comprador: pedido.comprador });
  ticket.usado = true; ticket.usadoEm = new Date().toISOString();
  persistPedidos();
  res.json({ valido: true, ticket, comprador: pedido.comprador });
});

// ════════════════════════════════════════════════════════
// COMUNIDADE — perfil público, seguir, feed
// ════════════════════════════════════════════════════════
app.get('/api/organizadores/:slug', (req, res) => {
  const user = db.users.find(u => u.organizadorSlug === req.params.slug);
  if (!user) return res.status(404).json({ error: 'Página não encontrada.' });
  const eventosPublicados = EVENTOS.filter(e => e.organizadorId === user.id && e.status === 'publicado');
  const posts = POSTS.filter(p => p.organizadorId === user.id).sort((a,b) => new Date(b.createdAt) - new Date(a.createdAt));
  const seguidores = FOLLOWS.filter(f => f.organizadorId === user.id).length;
  // Verifica se o usuário autenticado (se houver) já segue este organizador
  let jaSegue = false;
  const token = (req.headers['authorization'] || '').replace('Bearer ', '').trim();
  if (token) {
    try { const dec = jwt.verify(token, JWT_SECRET); jaSegue = FOLLOWS.some(f => f.userId === dec.id && f.organizadorId === user.id); } catch(e) {}
  }
  res.json({
    organizador: { id: user.id, nome: user.nomePublico || user.nome, slug: user.organizadorSlug, bio: user.bio, avatarUrl: user.avatarUrl, bannerUrl: user.bannerUrl, redesSociais: user.redesSociais || {}, seguidores, jaSegue },
    eventos: eventosPublicados.map(e => ({ id: e.id, slug: e.slug, nome: e.nome, dataEvento: e.dataEvento, cidade: e.cidade, imagemCapa: e.imagemCapa, categoria: e.categoria })),
    posts
  });
});

app.post('/api/organizadores/:organizadorId/seguir', auth, (req, res) => {
  const organizadorId = req.params.organizadorId;
  if (organizadorId === req.user.id) return res.status(400).json({ error: 'Você não pode seguir a si mesmo.' });
  const existente = FOLLOWS.find(f => f.userId === req.user.id && f.organizadorId === organizadorId);
  if (existente) { FOLLOWS = FOLLOWS.filter(f => f !== existente); persistFollows(); return res.json({ seguindo: false }); }
  FOLLOWS.push({ userId: req.user.id, organizadorId, createdAt: new Date().toISOString() });
  persistFollows();
  res.json({ seguindo: true });
});

app.get('/api/feed', auth, (req, res) => {
  const seguindo = FOLLOWS.filter(f => f.userId === req.user.id).map(f => f.organizadorId);
  const posts = POSTS.filter(p => seguindo.includes(p.organizadorId)).sort((a,b) => new Date(b.createdAt) - new Date(a.createdAt)).slice(0, 100);
  const comAutor = posts.map(p => { const org = db.users.find(u => u.id === p.organizadorId); return { ...p, autorNome: org?.nomePublico || org?.nome, autorSlug: org?.organizadorSlug, autorAvatar: org?.avatarUrl }; });
  res.json({ posts: comAutor, seguindoCount: seguindo.length });
});

app.post('/api/posts', auth, organizadorOnly, (req, res) => {
  const { texto, imagemUrl } = req.body;
  if (!texto) return res.status(400).json({ error: 'Escreva algo para publicar.' });
  const post = { id: uuidv4(), organizadorId: req.user.id, texto: sanitize(texto, 1000), imagemUrl: sanitize(imagemUrl || '', 300), createdAt: new Date().toISOString() };
  POSTS.unshift(post); persistPosts();
  res.status(201).json({ post });
});
app.delete('/api/posts/:id', auth, (req, res) => {
  const post = POSTS.find(p => p.id === req.params.id);
  if (!post || post.organizadorId !== req.user.id) return res.status(404).json({ error: 'Post não encontrado.' });
  POSTS = POSTS.filter(p => p.id !== req.params.id); persistPosts();
  res.json({ ok: true });
});

// ════════════════════════════════════════════════════════
// MARKETPLACE PÚBLICO
// ════════════════════════════════════════════════════════
app.get('/api/public/eventos', rateLimit(60000, 60), (req, res) => {
  const { cidade, categoria, busca } = req.query;
  let lista = EVENTOS.filter(e => e.status === 'publicado' && new Date(e.dataEvento) >= new Date(Date.now() - 86400000));
  if (cidade) lista = lista.filter(e => e.cidade.toLowerCase() === String(cidade).toLowerCase());
  if (categoria) lista = lista.filter(e => e.categoria.toLowerCase() === String(categoria).toLowerCase());
  if (busca) { const b = String(busca).toLowerCase(); lista = lista.filter(e => e.nome.toLowerCase().includes(b) || e.descricao.toLowerCase().includes(b)); }
  lista.sort((a,b) => new Date(a.dataEvento) - new Date(b.dataEvento));
  res.json({ eventos: lista.map(e => {
    const precos = e.lotes.filter(l=>l.ativo && !l.cortesia).map(l=>l.preco);
    return { slug: e.slug, nome: e.nome, dataEvento: e.dataEvento, horaEvento: e.horaEvento, cidade: e.cidade, local: e.local, categoria: e.categoria, imagemCapa: e.imagemCapa, precoMin: precos.length?Math.min(...precos):0 };
  })});
});

app.get('/api/public/eventos/:slug', rateLimit(60000, 60), (req, res) => {
  const ref = db.ticketSlugs[req.params.slug];
  if (!ref) return res.status(404).json({ error: 'Evento não encontrado.' });
  const ev = EVENTOS.find(e => e.id === ref.eventoId);
  if (!ev || ev.status !== 'publicado') return res.status(404).json({ error: 'Evento não encontrado ou não publicado.' });
  const organizador = db.users.find(u => u.id === ev.organizadorId);
  const lotesPublicos = ev.lotes.filter(l => l.ativo && !l.exclusivoPromoter && l.vendidos < l.qtdTotal)
    .map(l => ({ id: l.id, nome: l.nome, preco: l.preco, cortesia: l.cortesia, disponivel: l.qtdTotal - l.vendidos }));
  res.json({
    nome: ev.nome, descricao: ev.descricao, dataEvento: ev.dataEvento, horaEvento: ev.horaEvento,
    local: ev.local, cidade: ev.cidade, categoria: ev.categoria, imagemCapa: ev.imagemCapa, cores: ev.cores,
    lotes: lotesPublicos, pixels: ev.pixels, testMode: !!organizador?.mpAccount?.testMode,
    organizador: { nome: organizador?.nomePublico || organizador?.nome, slug: organizador?.organizadorSlug }
  });
});

app.get('/api/public/eventos/:slug/promoter/:codigoRef', rateLimit(60000, 60), (req, res) => {
  const ref = db.ticketSlugs[req.params.slug];
  if (!ref) return res.status(404).json({ error: 'Evento não encontrado.' });
  const ev = EVENTOS.find(e => e.id === ref.eventoId);
  const promoter = ev?.promoters.find(p => p.codigoRef === req.params.codigoRef && p.ativo);
  if (!promoter) return res.status(404).json({ error: 'Promoter não encontrado.' });
  const lotesExclusivos = ev.lotes.filter(l => l.ativo && l.vendidos < l.qtdTotal).map(l => ({ id: l.id, nome: l.nome, preco: l.preco, cortesia: l.cortesia, disponivel: l.qtdTotal - l.vendidos }));
  res.json({ promoterNome: promoter.nome, lotes: lotesExclusivos });
});

// ── CHECKOUT (com cupom, promoter e cortesia) ──
app.post('/api/public/checkout', rateLimit(60000, 20), async (req, res) => {
  try {
    const { slug, itens, comprador, cupom, ref } = req.body;
    const ticketRef = db.ticketSlugs[slug];
    if (!ticketRef) return res.status(404).json({ error: 'Evento não encontrado.' });
    const ev = EVENTOS.find(e => e.id === ticketRef.eventoId);
    if (!ev || ev.status !== 'publicado') return res.status(404).json({ error: 'Vendas encerradas.' });
    if (!comprador?.nome || !comprador?.email) return res.status(400).json({ error: 'Nome e e-mail obrigatórios.' });
    if (!Array.isArray(itens) || !itens.length) return res.status(400).json({ error: 'Selecione ao menos um ingresso.' });

    const organizador = db.users.find(u => u.id === ev.organizadorId);
    const producerToken = organizador?.mpAccount?.accessToken;

    let subtotal = 0, itensDetalhados = [];
    for (const it of itens) {
      const lote = ev.lotes.find(l => l.id === it.loteId);
      if (!lote || !lote.ativo) return res.status(400).json({ error: 'Lote indisponível.' });
      const qtd = Math.max(1, parseInt(it.qtd) || 1);
      if (lote.vendidos + qtd > lote.qtdTotal) return res.status(400).json({ error: `Apenas ${lote.qtdTotal - lote.vendidos} disponíveis em "${lote.nome}".` });
      subtotal += lote.preco * qtd;
      itensDetalhados.push({ loteId: lote.id, qtd, precoUnit: lote.preco, loteNome: lote.nome });
    }

    // Aplica cupom
    let desconto = 0, cupomObj = null;
    if (cupom) {
      cupomObj = ev.cupons.find(c => c.codigo === String(cupom).toUpperCase().trim() && c.ativo);
      if (!cupomObj) return res.status(400).json({ error: 'Cupom inválido ou expirado.' });
      if (cupomObj.usosMax > 0 && cupomObj.usosAtuais >= cupomObj.usosMax) return res.status(400).json({ error: 'Cupom esgotado.' });
      desconto = cupomObj.tipo === 'fixo' ? cupomObj.valor : Math.round(subtotal * (cupomObj.valor/100) * 100) / 100;
      desconto = Math.min(desconto, subtotal);
    }
    const total = Math.round((subtotal - desconto) * 100) / 100;

    // Promoter (referência de venda)
    let promoterObj = ref ? ev.promoters.find(p => p.codigoRef === ref && p.ativo) : null;

    const pedidoId = uuidv4();

    // CORTESIA / total zero — não precisa Mercado Pago, aprova na hora
    if (total <= 0) {
      const pedido = {
        id: pedidoId, eventoId: ev.id, status: 'pago', pagoEm: new Date().toISOString(),
        comprador: { nome: sanitize(comprador.nome,100), email: comprador.email, telefone: sanitize(comprador.telefone||'',30) },
        itens: itensDetalhados, subtotal, desconto, total: 0, cupomUsado: cupomObj?.codigo || null,
        promoterRef: promoterObj?.id || null, mpPaymentId: 'CORTESIA', tickets: [], createdAt: new Date().toISOString()
      };
      gerarTicketsEAtualizar(ev, pedido, cupomObj, promoterObj);
      PEDIDOS.push(pedido); persistPedidos(); persistEventos();
      await enviarEmailIngressos(pedido, ev.nome);
      return res.json({ ok: true, pedidoId, cortesia: true });
    }

    if (!producerToken) return res.status(500).json({ error: 'Este produtor ainda não conectou uma conta de pagamento.' });

    const host = req.get('host'); const proto = req.get('x-forwarded-proto') || 'https';
    const baseUrl = `${proto}://${host}`;
    const feePercent = db.marketplaceFeePercent || 10;
    const marketplaceFee = Math.round(total * (feePercent/100) * 100) / 100;

    const mpItems = itensDetalhados.map(it => ({ title: `${ev.nome} — ${it.loteNome}`, quantity: it.qtd, unit_price: it.precoUnit, currency_id: 'BRL' }));
    if (desconto > 0) mpItems.push({ title: 'Desconto (cupom ' + (cupomObj?.codigo||'') + ')', quantity: 1, unit_price: -desconto, currency_id: 'BRL' });

    const prefBody = {
      items: mpItems, payer: { name: sanitize(comprador.nome,100), email: comprador.email },
      external_reference: pedidoId, marketplace_fee: marketplaceFee,
      back_urls: { success: `${baseUrl}/e/${slug}?pedido=${pedidoId}&status=success`, pending: `${baseUrl}/e/${slug}?pedido=${pedidoId}&status=pending`, failure: `${baseUrl}/e/${slug}?pedido=${pedidoId}&status=failure` },
      auto_return: 'approved',
      notification_url: `${baseUrl}/api/mp/webhook?uid=${organizador.id}&ped=${pedidoId}`,
      statement_descriptor: 'LOTA TICKETS'
    };
    const mpResp = await fetch(`${MP_API}/checkout/preferences`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${producerToken}` }, body: JSON.stringify(prefBody) });
    const mpData = await mpResp.json();
    if (!mpResp.ok) return res.status(400).json({ error: mpData.message || 'Erro ao criar pagamento.' });

    PEDIDOS.push({
      id: pedidoId, eventoId: ev.id, status: 'pendente',
      comprador: { nome: sanitize(comprador.nome,100), email: comprador.email, telefone: sanitize(comprador.telefone||'',30) },
      itens: itensDetalhados, subtotal, desconto, total, cupomUsado: cupomObj?.codigo || null, promoterRef: promoterObj?.id || null,
      marketplaceFee, mpPreferenceId: mpData.id, mpPaymentId: null, tickets: [], createdAt: new Date().toISOString()
    });
    persistPedidos();
    res.json({ ok: true, pedidoId, init_point: mpData.init_point, testMode: !!organizador?.mpAccount?.testMode });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

function gerarTicketsEAtualizar(ev, pedido, cupomObj, promoterObj) {
  pedido.tickets = [];
  for (const it of pedido.itens) {
    const lote = ev.lotes.find(l => l.id === it.loteId);
    if (lote) lote.vendidos = (lote.vendidos || 0) + it.qtd;
    for (let i = 0; i < it.qtd; i++) pedido.tickets.push({ codigo: gerarCodigoTicket(), loteNome: it.loteNome, usado: false, usadoEm: null });
  }
  if (cupomObj) cupomObj.usosAtuais = (cupomObj.usosAtuais || 0) + 1;
  if (promoterObj) { promoterObj.vendas = (promoterObj.vendas || 0) + pedido.tickets.length; promoterObj.receita = (promoterObj.receita || 0) + pedido.total; }
  ev.updatedAt = new Date().toISOString();
}

async function enviarEmailIngressos(pedido, nomeEvento) {
  if (!RESEND_API_KEY || !pedido.comprador?.email) return;
  const ticketsHtml = (pedido.tickets || []).map(t => `
    <div style="border:1px solid #2A2822;border-radius:10px;padding:16px;margin-bottom:10px;display:flex;align-items:center;gap:16px;background:#161410;">
      <img src="https://api.qrserver.com/v1/create-qr-code/?size=120x120&data=${encodeURIComponent(t.codigo)}" width="90" height="90" style="border-radius:8px;background:#fff;padding:4px" />
      <div><div style="font-family:monospace;font-weight:700;color:#C47B14;font-size:14px;">${t.codigo}</div><div style="font-size:12px;color:#A09880;margin-top:2px;">${esc(t.loteNome)}</div></div>
    </div>`).join('');
  const html = `<div style="background:#0F0E0C;padding:32px 20px;font-family:Arial,sans-serif;color:#F0EDE8;"><div style="max-width:480px;margin:0 auto;">
    <div style="font-size:22px;font-weight:800;color:#C47B14;margin-bottom:4px;">🎟️ Lota Ticketeria</div>
    <p style="font-size:14px;color:#A09880;margin-bottom:24px;">Confirmação de compra</p>
    <h2 style="font-size:18px;margin-bottom:6px;">Seu ingresso para</h2>
    <p style="font-size:20px;font-weight:800;color:#fff;margin-bottom:20px;">${esc(nomeEvento)}</p>
    <p style="font-size:13px;color:#A09880;margin-bottom:16px;">Olá ${esc(pedido.comprador.nome)}, aqui estão seus ingressos:</p>
    ${ticketsHtml}
    <p style="font-size:11px;color:#605848;margin-top:20px;">Apresente o QR Code na entrada.</p>
    </div></div>`;
  try {
    await fetch('https://api.resend.com/emails', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${RESEND_API_KEY}` }, body: JSON.stringify({ from: RESEND_FROM, to: pedido.comprador.email, subject: `🎟️ Seus ingressos — ${nomeEvento}`, html }) });
  } catch(e) { console.error('Erro e-mail:', e.message); }
}

// ── WEBHOOK MERCADO PAGO ──
app.post('/api/mp/webhook', async (req, res) => {
  try {
    const paymentId = req.body?.data?.id || req.query['data.id'];
    const type = req.body?.type || req.query.type;
    if (type !== 'payment' || !paymentId) return res.sendStatus(200);
    const { uid, ped: pedidoId } = req.query;
    if (!uid || !pedidoId) return res.sendStatus(200);
    const organizador = db.users.find(u => u.id === uid);
    const producerToken = organizador?.mpAccount?.accessToken;
    if (!producerToken) return res.sendStatus(200);

    const payResp = await fetch(`${MP_API}/v1/payments/${paymentId}`, { headers: { 'Authorization': `Bearer ${producerToken}` } });
    const payment = await payResp.json();
    if (!payResp.ok) return res.sendStatus(200);

    const pedido = PEDIDOS.find(p => p.id === pedidoId);
    if (!pedido) return res.sendStatus(200);
    if (pedido.mpPaymentId === String(paymentId) && pedido.status === 'pago') return res.sendStatus(200);
    pedido.mpPaymentId = String(paymentId);

    if (payment.status === 'approved' && pedido.status !== 'pago') {
      pedido.status = 'pago'; pedido.pagoEm = new Date().toISOString();
      const ev = EVENTOS.find(e => e.id === pedido.eventoId);
      if (ev) {
        const cupomObj = pedido.cupomUsado ? ev.cupons.find(c => c.codigo === pedido.cupomUsado) : null;
        const promoterObj = pedido.promoterRef ? ev.promoters.find(p => p.id === pedido.promoterRef) : null;
        gerarTicketsEAtualizar(ev, pedido, cupomObj, promoterObj);
        persistEventos();
        await enviarEmailIngressos(pedido, ev.nome);
      }
    } else if (['rejected','cancelled'].includes(payment.status)) {
      pedido.status = 'recusado';
    }
    persistPedidos();
    res.sendStatus(200);
  } catch(e) { res.sendStatus(200); }
});

app.get('/api/public/pedido/:pedidoId', rateLimit(60000, 60), (req, res) => {
  const pedido = PEDIDOS.find(p => p.id === req.params.pedidoId);
  if (!pedido) return res.status(404).json({ error: 'Pedido não encontrado.' });
  res.json({ status: pedido.status, total: pedido.total, tickets: pedido.tickets || [], comprador: { nome: pedido.comprador.nome } });
});

// Rota pública amigável /e/:slug e /o/:slug
app.get('/e/:slug', (req, res) => { const p = path.join(PUBLIC_DIR, 'evento.html'); if (fs.existsSync(p)) return res.sendFile(p); res.status(404).send('Não encontrado.'); });
app.get('/o/:slug', (req, res) => { const p = path.join(PUBLIC_DIR, 'organizador.html'); if (fs.existsSync(p)) return res.sendFile(p); res.status(404).send('Não encontrado.'); });

// ════════════════════════════════════════════════════════
// ADMIN (plataforma)
// ════════════════════════════════════════════════════════
app.get('/api/admin/marketplace-fee', auth, adminOnly, (req, res) => res.json({ feePercent: db.marketplaceFeePercent }));
app.patch('/api/admin/marketplace-fee', auth, adminOnly, (req, res) => {
  const v = parseFloat(req.body.feePercent);
  if (isNaN(v) || v < 0 || v > 50) return res.status(400).json({ error: 'Valor inválido (0-50%).' });
  db.marketplaceFeePercent = v; saveDB(db);
  res.json({ ok: true, feePercent: v });
});
app.get('/api/admin/usuarios', auth, adminOnly, (req, res) => res.json({ usuarios: db.users.map(safe) }));

// ════════════════════════════════════════════════════════
app.get('/health', (req, res) => {
  res.json({
    status: 'ok', app: 'Lota Ticketeria', users: db.users.length, eventos: EVENTOS.length,
    mercadopago_oauth: (MP_CLIENT_ID && MP_CLIENT_SECRET) ? '✅' : '❌ (configure MP_CLIENT_ID e MP_CLIENT_SECRET)',
    resend_email: !!RESEND_API_KEY ? '✅' : '❌ (configure RESEND_API_KEY)',
    uptime: Math.round(process.uptime()) + 's'
  });
});

app.get('*', (req, res) => {
  const idx = path.join(PUBLIC_DIR, 'index.html');
  if (fs.existsSync(idx)) return res.sendFile(idx);
  res.status(500).send('index.html não encontrado.');
});

app.listen(PORT, () => {
  console.log(`\n🎟️  LOTA TICKETERIA rodando na porta ${PORT}`);
  console.log(`   Mercado Pago: ${(MP_CLIENT_ID && MP_CLIENT_SECRET) ? '✅' : '❌'}`);
  console.log(`   Resend: ${RESEND_API_KEY ? '✅' : '❌'}\n`);
});
