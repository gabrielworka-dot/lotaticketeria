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
const PDFDocument = require('pdfkit');
const QRCode  = require('qrcode');
const speakeasy = require('speakeasy');

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
// Imagens podem vir como URL normal ou como data URI base64 (upload direto) — precisa de limite bem maior
function sanitizeImagem(str) {
  if (typeof str !== 'string') return '';
  const v = str.trim();
  if (v.startsWith('data:image/')) return v.slice(0, 2_000_000); // até ~2MB em base64
  return v.slice(0, 500).replace(/<[^>]*>/g, '');
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
// Extrai o ID de um vídeo do YouTube a partir de qualquer formato de link comum
function extrairYoutubeId(url) {
  if (!url || typeof url !== 'string') return '';
  const m = url.match(/(?:youtube\.com\/(?:watch\?v=|embed\/|shorts\/)|youtu\.be\/)([a-zA-Z0-9_-]{11})/);
  return m ? m[1] : '';
}

// ── Database (usuários) ───────────────────────────────────
const DB_FILE = path.join(DATA_DIR, 'db.json');
function loadDB() {
  try { if (fs.existsSync(DB_FILE)) return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch(e) {}
  return {
    users: [{
      id: 'admin-001', nome: 'Administrador', email: 'admin@role.com',
      senha: bcrypt.hashSync('admin123', 12),
      isAdmin: true, ativo: true, isOrganizador: true, organizadorSlug: 'role-admin',
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
let ADIANTAMENTOS = loadColecao('adiantamentos');
function persistEventos() { saveColecao('eventos', EVENTOS); }
function persistPedidos() { saveColecao('pedidos', PEDIDOS); }
function persistPosts()   { saveColecao('posts', POSTS); }
function persistFollows() { saveColecao('follows', FOLLOWS); }
function persistAdiantamentos() { saveColecao('adiantamentos', ADIANTAMENTOS); }

// ── Auth helpers ──────────────────────────────────────────
function auth(req, res, next) {
  const token = (req.headers['authorization'] || '').replace('Bearer ', '').trim();
  if (!token) return res.status(401).json({ error: 'Token não enviado.' });
  try {
    const dec = jwt.verify(token, JWT_SECRET);
    const user = db.users.find(u => u.id === dec.id);
    if (!user) return res.status(401).json({ error: 'Sessão inválida.' });
    if (user.ativo === false) return res.status(403).json({ error: 'Esta conta foi desativada.' });
    req.user = user;
    next();
  } catch(e) { return res.status(401).json({ error: 'Token inválido ou expirado.' }); }
}
function organizadorOnly(req, res, next) {
  if (!req.user.isOrganizador) return res.status(403).json({ error: 'Apenas organizadores podem acessar isso.' });
  next();
}
function organizadorOuColaborador(req, res, next) {
  if (!req.user.isOrganizador && !req.user.colaboradorDe) return res.status(403).json({ error: 'Acesso restrito a produtores e sua equipe.' });
  next();
}
function adminOnly(req, res, next) {
  if (!req.user.isAdmin) return res.status(403).json({ error: 'Acesso restrito.' });
  next();
}
function safe(u) { const { senha, twoFactorSecret, twoFactorSecretPendente, ...r } = u; return r; }
function eventoDoUsuario(eventoId, userId) {
  const ev = EVENTOS.find(e => e.id === eventoId);
  if (!ev || ev.organizadorId !== userId) return null;
  return ev;
}
// Usado só em rotas de LEITURA — permite dono do evento OU colaborador com acesso de visualização
function eventoVisivelPara(eventoId, user) {
  const ev = EVENTOS.find(e => e.id === eventoId);
  if (!ev) return null;
  if (ev.organizadorId === user.id) return ev;
  if (user.colaboradorDe && ev.organizadorId === user.colaboradorDe) return ev;
  return null;
}

// ════════════════════════════════════════════════════════
// AUTH
// ════════════════════════════════════════════════════════
app.post('/api/auth/registro', rateLimit(60000, 10), async (req, res) => {
  const nome = sanitize(req.body.nome || '', 100);
  const email = sanitize(req.body.email || '', 150).toLowerCase();
  const senha = (req.body.senha || '').slice(0, 200);
  const ehProdutor = req.body.tipo === 'produtor';
  const nomePublicoInformado = sanitize(req.body.nomePublico || '', 100);
  const cpfCnpj = sanitize(req.body.cpfCnpj || '', 20).replace(/[^\d]/g, '');
  const tipoDocumento = req.body.tipoDocumento === 'cnpj' ? 'cnpj' : 'cpf';
  if (!nome || !email || !senha) return res.status(400).json({ error: 'Preencha todos os campos.' });
  if (senha.length < 6) return res.status(400).json({ error: 'Senha deve ter pelo menos 6 caracteres.' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'E-mail inválido.' });
  if (ehProdutor && !nomePublicoInformado) return res.status(400).json({ error: 'Nome público obrigatório para produtores.' });
  if (ehProdutor && !cpfCnpj) return res.status(400).json({ error: 'CPF ou CNPJ obrigatório para produtores.' });
  if (db.users.find(u => u.email === email)) return res.status(400).json({ error: 'E-mail já cadastrado.' });
  const slugsExistentes = db.users.filter(u => u.organizadorSlug).map(u => u.organizadorSlug);
  const user = {
    id: uuidv4(), nome, email, senha: bcrypt.hashSync(senha, 12),
    isAdmin: false, ativo: true, emailVerificado: false, verificado: false, colaboradorDe: null,
    isOrganizador: ehProdutor,
    nomePublico: ehProdutor ? nomePublicoInformado : '',
    organizadorSlug: ehProdutor ? gerarSlugUnico(nomePublicoInformado, slugsExistentes) : '',
    cpfCnpj: ehProdutor ? cpfCnpj : '', tipoDocumento: ehProdutor ? tipoDocumento : '',
    pagamentoInfo: { chavePix: '', tipoChavePix: '', nomeTitular: '', nomeBanco: '', numeroAgencia: '', tipoConta: '' },
    bio: '', avatarUrl: '', bannerUrl: '', redesSociais: {},
    createdAt: new Date().toISOString()
  };
  db.users.push(user); saveDB(db);
  const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '30d' });
  const host = req.get('host'); const proto = req.get('x-forwarded-proto') || 'https';
  enviarEmailVerificacao(user, proto, host).catch(() => {});
  res.status(201).json({ token, user: safe(user) });
});

async function enviarEmailVerificacao(user, proto, host) {
  const verifyToken = jwt.sign({ uid: user.id, tipo: 'verificacao' }, JWT_SECRET, { expiresIn: '3d' });
  const link = `${proto}://${host}/verificar-email.html?token=${verifyToken}`;
  const html = `<div style="background:#0F0E0C;padding:32px 20px;font-family:Arial,sans-serif;color:#F0EDE8;"><div style="max-width:480px;margin:0 auto;">
    <div style="font-size:22px;font-weight:800;color:#C47B14;margin-bottom:20px;">🎟️ Lota Ticketeria</div>
    <h2 style="font-size:18px;margin-bottom:12px;">Confirme seu e-mail</h2>
    <p style="font-size:13px;color:#A09880;margin-bottom:20px;">Olá ${esc(user.nome)}! Clique no botão abaixo para confirmar seu cadastro. O link expira em 3 dias.</p>
    <a href="${link}" style="display:inline-block;background:#E8961A;color:#18160F;font-weight:800;padding:12px 24px;border-radius:9px;text-decoration:none;font-size:14px;">Confirmar e-mail →</a>
    <p style="font-size:11px;color:#605848;margin-top:24px;">Se não foi você quem se cadastrou, ignore este e-mail.</p>
    </div></div>`;
  return enviarEmailGenerico(user.email, '✅ Confirme seu e-mail — Lota Ticketeria', html);
}


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
  if (user.ativo === false) return res.status(403).json({ error: 'Esta conta foi desativada. Entre em contato com o suporte.' });
  delete db.loginAttempts[ip]; saveDB(db);
  // Conta com 2FA ativo — não libera o token final ainda, exige o código do autenticador
  if (user.twoFactorAtivo) {
    const preAuthToken = jwt.sign({ id: user.id, tipo: 'pre2fa' }, JWT_SECRET, { expiresIn: '5m' });
    return res.json({ precisa2FA: true, preAuthToken });
  }
  const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: safe(user) });
});

app.post('/api/auth/2fa/verificar-login', rateLimit(60000, 10), (req, res) => {
  const { preAuthToken, codigo } = req.body;
  if (!preAuthToken || !codigo) return res.status(400).json({ error: 'Dados incompletos.' });
  let dec;
  try { dec = jwt.verify(preAuthToken, JWT_SECRET); } catch(e) { return res.status(401).json({ error: 'Sessão expirada. Faça login novamente.' }); }
  if (dec.tipo !== 'pre2fa') return res.status(400).json({ error: 'Token inválido.' });
  const user = db.users.find(u => u.id === dec.id);
  if (!user || !user.twoFactorAtivo || !user.twoFactorSecret) return res.status(400).json({ error: 'Autenticação em duas etapas não está ativa.' });
  const valido = speakeasy.totp.verify({ secret: user.twoFactorSecret, encoding: 'base32', token: String(codigo).trim(), window: 1 });
  if (!valido) return res.status(401).json({ error: 'Código incorreto.' });
  const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: safe(user) });
});

app.post('/api/auth/2fa/setup', auth, (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ error: 'Disponível apenas para contas de administrador.' });
  const secret = speakeasy.generateSecret({ name: `Lota Ticketeria (${req.user.email})`, length: 20 });
  const user = db.users.find(u => u.id === req.user.id);
  user.twoFactorSecretPendente = secret.base32;
  saveDB(db);
  QRCode.toDataURL(secret.otpauth_url).then(qr => {
    res.json({ qrCode: qr, secretManual: secret.base32 });
  }).catch(() => res.status(500).json({ error: 'Erro ao gerar QR Code.' }));
});

app.post('/api/auth/2fa/ativar', auth, (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ error: 'Disponível apenas para contas de administrador.' });
  const user = db.users.find(u => u.id === req.user.id);
  if (!user.twoFactorSecretPendente) return res.status(400).json({ error: 'Inicie a configuração antes de confirmar.' });
  const { codigo } = req.body;
  const valido = speakeasy.totp.verify({ secret: user.twoFactorSecretPendente, encoding: 'base32', token: String(codigo || '').trim(), window: 1 });
  if (!valido) return res.status(400).json({ error: 'Código incorreto. Confira o app autenticador e tente novamente.' });
  user.twoFactorSecret = user.twoFactorSecretPendente;
  user.twoFactorAtivo = true;
  delete user.twoFactorSecretPendente;
  saveDB(db);
  res.json({ ok: true, user: safe(user) });
});

app.post('/api/auth/2fa/desativar', auth, (req, res) => {
  const user = db.users.find(u => u.id === req.user.id);
  const { senha } = req.body;
  if (!senha || !bcrypt.compareSync(senha, user.senha)) return res.status(401).json({ error: 'Senha incorreta.' });
  user.twoFactorAtivo = false;
  delete user.twoFactorSecret;
  delete user.twoFactorSecretPendente;
  saveDB(db);
  res.json({ ok: true, user: safe(user) });
});

app.get('/api/auth/me', auth, (req, res) => res.json({ user: safe(req.user) }));

app.post('/api/auth/verificar-email', rateLimit(60000, 10), (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'Token ausente.' });
  let dec;
  try { dec = jwt.verify(token, JWT_SECRET); } catch(e) { return res.status(400).json({ error: 'Link inválido ou expirado.' }); }
  if (dec.tipo !== 'verificacao') return res.status(400).json({ error: 'Link inválido.' });
  const user = db.users.find(u => u.id === dec.uid);
  if (!user) return res.status(404).json({ error: 'Usuário não encontrado.' });
  user.emailVerificado = true;
  saveDB(db);
  res.json({ ok: true });
});

app.post('/api/auth/reenviar-verificacao', auth, rateLimit(60000, 3), async (req, res) => {
  if (req.user.emailVerificado) return res.json({ ok: true, jaVerificado: true });
  const host = req.get('host'); const proto = req.get('x-forwarded-proto') || 'https';
  await enviarEmailVerificacao(req.user, proto, host).catch(() => {});
  res.json({ ok: true });
});

app.patch('/api/auth/perfil', auth, (req, res) => {
  const user = db.users.find(u => u.id === req.user.id);
  const { nome, bio, avatarUrl, bannerUrl, redesSociais, senhaAtual, novaSenha, cpfCnpj, tipoDocumento, pagamentoInfo } = req.body;
  if (nome) user.nome = sanitize(nome, 100);
  if (bio !== undefined) user.bio = sanitize(bio, 500);
  if (avatarUrl !== undefined) user.avatarUrl = sanitizeImagem(avatarUrl);
  if (bannerUrl !== undefined) user.bannerUrl = sanitizeImagem(bannerUrl);
  if (redesSociais) user.redesSociais = { instagram: sanitize(redesSociais.instagram||'',60), tiktok: sanitize(redesSociais.tiktok||'',60), site: sanitize(redesSociais.site||'',200) };
  if (cpfCnpj !== undefined) user.cpfCnpj = sanitize(cpfCnpj, 20).replace(/[^\d]/g, '');
  if (tipoDocumento !== undefined) user.tipoDocumento = tipoDocumento === 'cnpj' ? 'cnpj' : 'cpf';
  if (pagamentoInfo) {
    user.pagamentoInfo = {
      chavePix: sanitize(pagamentoInfo.chavePix || '', 140),
      tipoChavePix: sanitize(pagamentoInfo.tipoChavePix || '', 20),
      nomeTitular: sanitize(pagamentoInfo.nomeTitular || '', 100),
      nomeBanco: sanitize(pagamentoInfo.nomeBanco || '', 80),
      numeroAgencia: sanitize(pagamentoInfo.numeroAgencia || '', 20),
      tipoConta: sanitize(pagamentoInfo.tipoConta || '', 20)
    };
  }
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
// EQUIPE — colaboradores com acesso somente de visualização
// ════════════════════════════════════════════════════════
app.get('/api/produtor/colaboradores', auth, organizadorOnly, (req, res) => {
  const membros = db.users.filter(u => u.colaboradorDe === req.user.id).map(u => ({ id: u.id, nome: u.nome, email: u.email }));
  res.json({ colaboradores: membros });
});

app.post('/api/produtor/colaboradores', auth, organizadorOnly, (req, res) => {
  const email = sanitize(req.body.email || '', 150).toLowerCase();
  if (!email) return res.status(400).json({ error: 'Informe o e-mail da pessoa.' });
  const pessoa = db.users.find(u => u.email === email);
  if (!pessoa) return res.status(404).json({ error: 'Não existe conta cadastrada com esse e-mail. Peça para a pessoa criar uma conta primeiro.' });
  if (pessoa.id === req.user.id) return res.status(400).json({ error: 'Você não pode se adicionar como colaborador de si mesmo.' });
  if (pessoa.isOrganizador) return res.status(400).json({ error: 'Essa conta já é de um produtor e não pode ser adicionada como colaboradora.' });
  if (pessoa.colaboradorDe && pessoa.colaboradorDe !== req.user.id) return res.status(400).json({ error: 'Essa pessoa já é colaboradora de outro produtor.' });
  pessoa.colaboradorDe = req.user.id;
  saveDB(db);
  res.status(201).json({ ok: true, colaborador: { id: pessoa.id, nome: pessoa.nome, email: pessoa.email } });
});

app.delete('/api/produtor/colaboradores/:userId', auth, organizadorOnly, (req, res) => {
  const pessoa = db.users.find(u => u.id === req.params.userId && u.colaboradorDe === req.user.id);
  if (!pessoa) return res.status(404).json({ error: 'Colaborador não encontrado.' });
  pessoa.colaboradorDe = null;
  saveDB(db);
  res.json({ ok: true });
});


// (MP_CLIENT_ID/MP_CLIENT_SECRET não são mais necessários — pagamento único via MP_ACCESS_TOKEN)
const MP_API = 'https://api.mercadopago.com';
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const RESEND_FROM    = process.env.RESEND_FROM_EMAIL || 'Lota Ticketeria <onboarding@resend.dev>';

async function enviarEmailGenerico(destinatario, assunto, html) {
  if (!RESEND_API_KEY || !destinatario) { console.error('Resend não configurado ou destinatário ausente ao tentar enviar:', assunto); return false; }
  try {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${RESEND_API_KEY}` },
      body: JSON.stringify({ from: RESEND_FROM, to: destinatario, subject: assunto, html })
    });
    if (!r.ok) { const errBody = await r.text().catch(()=>''); console.error('Resend recusou o e-mail:', assunto, r.status, errBody); }
    return r.ok;
  } catch(e) { console.error('Erro e-mail:', e.message); return false; }
}

// ════════════════════════════════════════════════════════
// RECUPERAÇÃO DE SENHA
// ════════════════════════════════════════════════════════
app.post('/api/auth/esqueci-senha', rateLimit(60000, 5), async (req, res) => {
  const email = sanitize(req.body.email || '', 150).toLowerCase();
  // Sempre responde sucesso, mesmo se o e-mail não existir — evita expor quais e-mails estão cadastrados
  const user = db.users.find(u => u.email === email);
  if (user) {
    const token = jwt.sign({ uid: user.id, tipo: 'reset' }, JWT_SECRET, { expiresIn: '30m' });
    const host = req.get('host'); const proto = req.get('x-forwarded-proto') || 'https';
    const link = `${proto}://${host}/redefinir-senha.html?token=${token}`;
    const html = `<div style="background:#0F0E0C;padding:32px 20px;font-family:Arial,sans-serif;color:#F0EDE8;"><div style="max-width:480px;margin:0 auto;">
      <div style="font-size:22px;font-weight:800;color:#C47B14;margin-bottom:20px;">🎟️ Lota Ticketeria</div>
      <h2 style="font-size:18px;margin-bottom:12px;">Redefinir sua senha</h2>
      <p style="font-size:13px;color:#A09880;margin-bottom:20px;">Clique no botão abaixo para criar uma nova senha. Este link expira em 30 minutos.</p>
      <a href="${link}" style="display:inline-block;background:#E8961A;color:#18160F;font-weight:800;padding:12px 24px;border-radius:9px;text-decoration:none;font-size:14px;">Redefinir senha →</a>
      <p style="font-size:11px;color:#605848;margin-top:24px;">Se você não pediu isso, pode ignorar este e-mail com segurança.</p>
      </div></div>`;
    await enviarEmailGenerico(user.email, '🔑 Redefinir sua senha — Lota Ticketeria', html);
  }
  res.json({ ok: true, message: 'Se o e-mail existir, você receberá um link de redefinição.' });
});

app.post('/api/auth/redefinir-senha', rateLimit(60000, 10), (req, res) => {
  const { token, novaSenha } = req.body;
  if (!token || !novaSenha) return res.status(400).json({ error: 'Dados incompletos.' });
  if (novaSenha.length < 6) return res.status(400).json({ error: 'Senha deve ter pelo menos 6 caracteres.' });
  let dec;
  try { dec = jwt.verify(token, JWT_SECRET); } catch(e) { return res.status(400).json({ error: 'Link inválido ou expirado. Solicite um novo.' }); }
  if (dec.tipo !== 'reset') return res.status(400).json({ error: 'Link inválido.' });
  const user = db.users.find(u => u.id === dec.uid);
  if (!user) return res.status(400).json({ error: 'Usuário não encontrado.' });
  user.senha = bcrypt.hashSync(novaSenha, 12);
  saveDB(db);
  res.json({ ok: true });
});

// ════════════════════════════════════════════════════════
// MEUS INGRESSOS (comprador logado)
// ════════════════════════════════════════════════════════
app.get('/api/meus-ingressos', auth, (req, res) => {
  const meusPedidos = PEDIDOS.filter(p => p.status === 'pago' && (p.compradorUserId === req.user.id || (p.comprador?.email || '').toLowerCase() === req.user.email.toLowerCase()));
  const comEvento = meusPedidos.map(p => {
    const ev = EVENTOS.find(e => e.id === p.eventoId);
    return { pedidoId: p.id, eventoNome: ev?.nome || 'Evento', eventoSlug: ev?.slug || '', dataEvento: ev?.dataEvento || null, imagemCapa: ev?.imagemCapa || '', total: p.total, tickets: p.tickets || [], createdAt: p.createdAt };
  }).sort((a,b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json({ pedidos: comEvento });
});

// Pagamentos agora são recebidos numa ÚNICA conta da plataforma (não mais OAuth por produtor).
// O valor devido a cada produtor é calculado internamente e pago por PIX manual via pedido de adiantamento.
const MP_PLATFORM_TOKEN = process.env.MP_ACCESS_TOKEN || '';
const MP_PUBLIC_KEY = process.env.MP_PUBLIC_KEY || '';
function isTestToken(token) { return /^TEST-/i.test(token || ''); }

// ════════════════════════════════════════════════════════
// EVENTOS (organizador)
// ════════════════════════════════════════════════════════
app.get('/api/meus-eventos', auth, organizadorOuColaborador, (req, res) => {
  const idAlvo = req.user.colaboradorDe || req.user.id;
  res.json({ eventos: EVENTOS.filter(e => e.organizadorId === idAlvo), modoVisualizacao: !!req.user.colaboradorDe });
});

app.post('/api/eventos', auth, organizadorOnly, (req, res) => {
  const { nome, descricao, dataEvento, horaEvento, local, cidade, categoria, imagemCapa, videoUrl } = req.body;
  if (!nome || !dataEvento) return res.status(400).json({ error: 'Nome e data obrigatórios.' });
  const slugsExistentes = Object.keys(db.ticketSlugs);
  const slug = gerarSlugUnico(nome, slugsExistentes);
  const evento = {
    id: uuidv4(), organizadorId: req.user.id, slug,
    nome: sanitize(nome, 100), descricao: sanitize(descricao || '', 2000),
    dataEvento, horaEvento: sanitize(horaEvento || '', 10),
    local: sanitize(local || '', 150), cidade: sanitize(cidade || '', 80),
    categoria: sanitize(categoria || 'Festas e shows', 40),
    imagemCapa: sanitizeImagem(imagemCapa || ''),
    videoUrl: extrairYoutubeId(videoUrl || '') ? sanitize(videoUrl, 200) : '',
    status: 'rascunho',
    cores: { primaria: '#C47B14', fundo: '#18160F' },
    lotes: [], cupons: [], promoters: [],
    pixels: { metaPixelId: '', tiktokPixelId: '', gaMeasurementId: '', googleAdsConversionId: '', googleAdsConversionLabel: '' },
    politicaCancelamento: 'sem-cancelamento',
    mapaAssentos: { ativo: false, palco: 'PALCO', setores: [] },
    assentosOcupados: [],
    createdAt: new Date().toISOString(), updatedAt: new Date().toISOString()
  };
  EVENTOS.push(evento);
  db.ticketSlugs[slug] = { userId: req.user.id, eventoId: evento.id };
  saveDB(db); persistEventos();
  res.status(201).json({ evento });
});

app.get('/api/eventos/:id', auth, (req, res) => {
  const ev = eventoVisivelPara(req.params.id, req.user);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  res.json({ evento: ev, somenteLeitura: ev.organizadorId !== req.user.id });
});

app.patch('/api/eventos/:id', auth, (req, res) => {
  const ev = eventoDoUsuario(req.params.id, req.user.id);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  const campos = ['nome','descricao','dataEvento','horaEvento','local','cidade','categoria','politicaCancelamento'];
  campos.forEach(c => { if (req.body[c] !== undefined) ev[c] = typeof req.body[c] === 'string' ? sanitize(req.body[c], c === 'descricao' ? 2000 : 150) : req.body[c]; });
  if (req.body.imagemCapa !== undefined) ev.imagemCapa = sanitizeImagem(req.body.imagemCapa);
  if (req.body.videoUrl !== undefined) ev.videoUrl = req.body.videoUrl && extrairYoutubeId(req.body.videoUrl) ? sanitize(req.body.videoUrl, 200) : '';
  if (req.body.cores) ev.cores = req.body.cores;
  ev.updatedAt = new Date().toISOString();
  persistEventos();
  res.json({ evento: ev });
});

// ── MAPA DE ASSENTOS ──
app.patch('/api/eventos/:id/mapa-assentos', auth, (req, res) => {
  const ev = eventoDoUsuario(req.params.id, req.user.id);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  const { ativo, palco, setores } = req.body;
  if (!ev.mapaAssentos) ev.mapaAssentos = { ativo: false, palco: 'PALCO', setores: [] };
  if (ativo !== undefined) ev.mapaAssentos.ativo = !!ativo;
  if (palco !== undefined) ev.mapaAssentos.palco = sanitize(palco, 40);
  if (Array.isArray(setores)) {
    ev.mapaAssentos.setores = setores.map(s => ({
      id: s.id || uuidv4(), nome: sanitize(s.nome || 'Setor', 40), loteId: s.loteId || '',
      linhas: Math.max(1, Math.min(30, parseInt(s.linhas) || 1)),
      assentosPorLinha: Math.max(1, Math.min(40, parseInt(s.assentosPorLinha) || 1)),
      cor: sanitize(s.cor || '#C47B14', 10)
    }));
  }
  ev.updatedAt = new Date().toISOString();
  persistEventos();
  res.json({ evento: ev });
});

app.patch('/api/eventos/:id/publicar', auth, (req, res) => {
  const ev = eventoDoUsuario(req.params.id, req.user.id);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
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

app.post('/api/eventos/:id/duplicar', auth, (req, res) => {
  const original = eventoDoUsuario(req.params.id, req.user.id);
  if (!original) return res.status(404).json({ error: 'Evento não encontrado.' });
  const slugsExistentes = Object.keys(db.ticketSlugs);
  const novoNome = original.nome + ' (cópia)';
  const slug = gerarSlugUnico(novoNome, slugsExistentes);
  const copia = {
    ...JSON.parse(JSON.stringify(original)),
    id: uuidv4(), slug, nome: novoNome, status: 'rascunho',
    lotes: original.lotes.map(l => ({ ...l, id: uuidv4(), vendidos: 0 })),
    cupons: original.cupons.map(c => ({ ...c, id: uuidv4(), usosAtuais: 0 })),
    promoters: original.promoters.map(p => ({ ...p, id: uuidv4(), codigoRef: gerarCodigoPromoter(), vendas: 0, receita: 0 })),
    assentosOcupados: [],
    createdAt: new Date().toISOString(), updatedAt: new Date().toISOString()
  };
  // Reaplica os novos IDs de lote nos setores do mapa de assentos (senão ficam apontando pro lote antigo)
  if (copia.mapaAssentos?.setores?.length) {
    copia.mapaAssentos.setores = copia.mapaAssentos.setores.map((s, i) => ({ ...s, id: uuidv4(), loteId: copia.lotes[original.lotes.findIndex(l => l.id === s.loteId)]?.id || copia.lotes[0]?.id || '' }));
  }
  EVENTOS.push(copia);
  db.ticketSlugs[slug] = { userId: req.user.id, eventoId: copia.id };
  saveDB(db); persistEventos();
  res.status(201).json({ evento: copia });
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
// SALDO E ADIANTAMENTO (repasse manual via PIX pelo administrador)
// ════════════════════════════════════════════════════════
function calcularSaldoProdutor(userId) {
  const eventosDoProdutor = EVENTOS.filter(e => e.organizadorId === userId).map(e => e.id);
  const pedidosPagos = PEDIDOS.filter(p => eventosDoProdutor.includes(p.eventoId) && p.status === 'pago');
  const saldoBruto = pedidosPagos.reduce((s, p) => s + (p.valorIngressos !== undefined ? p.valorIngressos : (p.total - ((p.taxaAdministrativa !== undefined ? p.taxaAdministrativa : (p.marketplaceFee || 0))))), 0);
  const meusAdiantamentos = ADIANTAMENTOS.filter(a => a.produtorId === userId);
  const totalJaPago = meusAdiantamentos.filter(a => a.status === 'pago').reduce((s, a) => s + a.valor, 0);
  const totalPendente = meusAdiantamentos.filter(a => a.status === 'pendente').reduce((s, a) => s + a.valor, 0);
  const saldoDisponivel = Math.max(0, Math.round((saldoBruto - totalJaPago - totalPendente) * 100) / 100);
  return { saldoBruto, totalJaPago, totalPendente, saldoDisponivel };
}

app.get('/api/produtor/saldo', auth, organizadorOnly, (req, res) => {
  res.json(calcularSaldoProdutor(req.user.id));
});

app.get('/api/produtor/adiantamentos', auth, organizadorOnly, (req, res) => {
  const lista = ADIANTAMENTOS.filter(a => a.produtorId === req.user.id).sort((a, b) => new Date(b.solicitadoEm) - new Date(a.solicitadoEm));
  res.json({ adiantamentos: lista });
});

app.post('/api/produtor/adiantamento', auth, organizadorOnly, (req, res) => {
  const valor = Math.round((parseFloat(req.body.valor) || 0) * 100) / 100;
  if (valor <= 0) return res.status(400).json({ error: 'Informe um valor válido.' });
  if (!req.user.pagamentoInfo?.chavePix) return res.status(400).json({ error: 'Cadastre sua chave PIX no perfil antes de solicitar um adiantamento.' });
  if (!req.user.cpfCnpj) return res.status(400).json({ error: 'Cadastre seu CPF/CNPJ no perfil antes de solicitar um adiantamento.' });
  const { saldoDisponivel } = calcularSaldoProdutor(req.user.id);
  if (valor > saldoDisponivel) return res.status(400).json({ error: `Valor solicitado maior que o saldo disponível (R$ ${saldoDisponivel.toFixed(2)}).` });
  const agora = new Date();
  const prazoLimite = new Date(agora.getTime() + 2 * 24 * 60 * 60 * 1000); // 2 dias
  const adiantamento = {
    id: uuidv4(), produtorId: req.user.id, valor,
    chavePix: req.user.pagamentoInfo.chavePix, tipoChavePix: req.user.pagamentoInfo.tipoChavePix,
    nomeTitular: req.user.pagamentoInfo.nomeTitular, cpfCnpj: req.user.cpfCnpj,
    nomeBanco: req.user.pagamentoInfo.nomeBanco || '', numeroAgencia: req.user.pagamentoInfo.numeroAgencia || '', tipoConta: req.user.pagamentoInfo.tipoConta || '',
    status: 'pendente', solicitadoEm: agora.toISOString(), prazoLimite: prazoLimite.toISOString(),
    pagoEm: null, observacoesAdmin: ''
  };
  ADIANTAMENTOS.push(adiantamento);
  persistAdiantamentos();
  res.status(201).json({ adiantamento });
});

// ── ADMIN — processar adiantamentos ──
app.get('/api/admin/adiantamentos', auth, adminOnly, (req, res) => {
  const lista = ADIANTAMENTOS.map(a => {
    const produtor = db.users.find(u => u.id === a.produtorId);
    return { ...a, produtorNome: produtor?.nomePublico || produtor?.nome || '—', produtorEmail: produtor?.email || '—' };
  }).sort((a, b) => new Date(b.solicitadoEm) - new Date(a.solicitadoEm));
  res.json({ adiantamentos: lista });
});

app.patch('/api/admin/adiantamentos/:id', auth, adminOnly, (req, res) => {
  const a = ADIANTAMENTOS.find(x => x.id === req.params.id);
  if (!a) return res.status(404).json({ error: 'Pedido de adiantamento não encontrado.' });
  const { status, observacoes } = req.body;
  if (!['pago', 'recusado'].includes(status)) return res.status(400).json({ error: 'Status inválido.' });
  a.status = status;
  if (status === 'pago') a.pagoEm = new Date().toISOString();
  if (observacoes !== undefined) a.observacoesAdmin = sanitize(observacoes, 300);
  persistAdiantamentos();
  res.json({ ok: true, adiantamento: a });
});

// ════════════════════════════════════════════════════════
// RELATÓRIOS, PARTICIPANTES, BORDERÔ
// ════════════════════════════════════════════════════════
app.get('/api/eventos/:id/pedidos', auth, (req, res) => {
  const ev = eventoVisivelPara(req.params.id, req.user);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  res.json({ pedidos: PEDIDOS.filter(p => p.eventoId === ev.id) });
});

// ── CANCELAMENTO / REEMBOLSO DE PEDIDO ──
app.post('/api/eventos/:id/pedidos/:pedidoId/reembolsar', auth, async (req, res) => {
  const ev = eventoDoUsuario(req.params.id, req.user.id);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  const pedido = PEDIDOS.find(p => p.id === req.params.pedidoId && p.eventoId === ev.id);
  if (!pedido) return res.status(404).json({ error: 'Pedido não encontrado.' });
  if (pedido.status !== 'pago') return res.status(400).json({ error: 'Somente pedidos pagos podem ser reembolsados.' });

  // Cortesia ou pagamento simulado — não envolve dinheiro real, só cancela localmente
  const semPagamentoReal = pedido.mpPaymentId === 'CORTESIA' || String(pedido.mpPaymentId || '').startsWith('SIMULADO');

  if (!semPagamentoReal) {
    if (!MP_PLATFORM_TOKEN) return res.status(500).json({ error: 'Mercado Pago não configurado no servidor.' });
    try {
      const refResp = await fetch(`${MP_API}/v1/payments/${pedido.mpPaymentId}/refunds`, {
        method: 'POST', headers: { 'Authorization': `Bearer ${MP_PLATFORM_TOKEN}`, 'Content-Type': 'application/json', 'X-Idempotency-Key': uuidv4() },
        body: JSON.stringify({})
      });
      if (!refResp.ok) {
        const errData = await refResp.json().catch(() => ({}));
        return res.status(400).json({ error: errData.message || 'Erro ao processar reembolso no Mercado Pago.' });
      }
    } catch (e) {
      return res.status(500).json({ error: 'Erro ao conectar com o Mercado Pago: ' + e.message });
    }
  }

  // Marca pedido como reembolsado, invalida ingressos e libera as vagas do lote (e assentos, se houver)
  pedido.status = 'reembolsado';
  pedido.reembolsadoEm = new Date().toISOString();
  (pedido.tickets || []).forEach(t => { t.cancelado = true; });
  const qtdTotal = (pedido.itens || []).reduce((s, it) => s + it.qtd, 0);
  for (const it of (pedido.itens || [])) {
    const lote = ev.lotes.find(l => l.id === it.loteId);
    if (lote) lote.vendidos = Math.max(0, (lote.vendidos || 0) - it.qtd);
    if (it.assento && ev.assentosOcupados) ev.assentosOcupados = ev.assentosOcupados.filter(a => a !== it.assento);
  }
  if (pedido.cupomUsado) {
    const c = ev.cupons.find(c => c.codigo === pedido.cupomUsado);
    if (c) c.usosAtuais = Math.max(0, (c.usosAtuais || 0) - 1);
  }
  if (pedido.promoterRef) {
    const p = ev.promoters.find(p => p.id === pedido.promoterRef);
    if (p) { p.vendas = Math.max(0, (p.vendas || 0) - qtdTotal); p.receita = Math.max(0, (p.receita || 0) - pedido.total); }
  }
  persistPedidos(); persistEventos();
  res.json({ ok: true, reembolsoReal: !semPagamentoReal });
});

app.get('/api/eventos/:id/relatorio', auth, (req, res) => {
  const ev = eventoVisivelPara(req.params.id, req.user);
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
  const ev = eventoVisivelPara(req.params.id, req.user);
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
  const ev = eventoVisivelPara(req.params.id, req.user);
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
  if (ticket.cancelado) return res.json({ valido: false, cancelado: true, ticket, comprador: pedido.comprador });
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
    organizador: { id: user.id, nome: user.nomePublico || user.nome, slug: user.organizadorSlug, bio: user.bio, avatarUrl: user.avatarUrl, bannerUrl: user.bannerUrl, redesSociais: user.redesSociais || {}, seguidores, jaSegue, verificado: !!user.verificado },
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
app.get('/api/public/cidades', rateLimit(60000, 60), (req, res) => {
  const cidades = [...new Set(EVENTOS.filter(e => e.status === 'publicado' && e.cidade).map(e => e.cidade))].sort();
  res.json({ cidades });
});

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
    videoYoutubeId: extrairYoutubeId(ev.videoUrl || ''),
    lotes: lotesPublicos, pixels: ev.pixels, testMode: isTestToken(MP_PLATFORM_TOKEN),
    feePercent: db.marketplaceFeePercent || 10,
    mpPublicKey: MP_PUBLIC_KEY,
    mapaAssentos: ev.mapaAssentos?.ativo ? ev.mapaAssentos : null,
    assentosOcupados: ev.mapaAssentos?.ativo ? (ev.assentosOcupados || []) : [],
    organizador: { nome: organizador?.nomePublico || organizador?.nome, slug: organizador?.organizadorSlug, verificado: !!organizador?.verificado }
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
    // Autenticação opcional — se o comprador estiver logado, vinculamos a compra à conta dele
    let compradorUserId = null;
    const authHeader = (req.headers['authorization'] || '').replace('Bearer ', '').trim();
    if (authHeader) { try { compradorUserId = jwt.verify(authHeader, JWT_SECRET).id; } catch(e) {} }
    const ticketRef = db.ticketSlugs[slug];
    if (!ticketRef) return res.status(404).json({ error: 'Evento não encontrado.' });
    const ev = EVENTOS.find(e => e.id === ticketRef.eventoId);
    if (!ev || ev.status !== 'publicado') return res.status(404).json({ error: 'Vendas encerradas.' });
    if (!comprador?.nome || !comprador?.email) return res.status(400).json({ error: 'Nome e e-mail obrigatórios.' });
    if (!Array.isArray(itens) || !itens.length) return res.status(400).json({ error: 'Selecione ao menos um ingresso.' });

    const organizador = db.users.find(u => u.id === ev.organizadorId);
    const assentosOcupadosAtuais = ev.assentosOcupados || [];
    const assentosSelecionadosNestePedido = [];

    let subtotal = 0, itensDetalhados = [];
    for (const it of itens) {
      const lote = ev.lotes.find(l => l.id === it.loteId);
      if (!lote || !lote.ativo) return res.status(400).json({ error: 'Lote indisponível.' });
      if (it.assento) {
        // Compra com assento marcado — cada assento é único, sem quantidade agregada
        if (assentosOcupadosAtuais.includes(it.assento) || assentosSelecionadosNestePedido.includes(it.assento)) {
          return res.status(400).json({ error: `O assento ${it.assento} já foi vendido. Escolha outro.` });
        }
        assentosSelecionadosNestePedido.push(it.assento);
        subtotal += lote.preco;
        itensDetalhados.push({ loteId: lote.id, qtd: 1, precoUnit: lote.preco, loteNome: lote.nome, assento: it.assento });
        continue;
      }
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
    // valorIngressos é o que o produtor recebe integralmente (100%).
    // A taxa administrativa é cobrada À PARTE, como acréscimo pago pelo comprador — não sai do valor do produtor.
    const valorIngressos = Math.round((subtotal - desconto) * 100) / 100;
    const feePercent = db.marketplaceFeePercent || 10;
    const taxaAdministrativa = Math.round(valorIngressos * (feePercent/100) * 100) / 100;
    const total = Math.round((valorIngressos + taxaAdministrativa) * 100) / 100;

    // Promoter (referência de venda)
    let promoterObj = ref ? ev.promoters.find(p => p.codigoRef === ref && p.ativo) : null;

    const pedidoId = uuidv4();

    // CORTESIA / valor zero — não precisa Mercado Pago, aprova na hora (sem taxa, pois não há cobrança)
    if (valorIngressos <= 0) {
      const pedido = {
        id: pedidoId, eventoId: ev.id, status: 'pago', pagoEm: new Date().toISOString(),
        comprador: { nome: sanitize(comprador.nome,100), email: comprador.email, telefone: sanitize(comprador.telefone||'',30) },
        compradorUserId,
        itens: itensDetalhados, subtotal, desconto, valorIngressos: 0, taxaAdministrativa: 0, total: 0, cupomUsado: cupomObj?.codigo || null,
        promoterRef: promoterObj?.id || null, mpPaymentId: 'CORTESIA', tickets: [], createdAt: new Date().toISOString()
      };
      gerarTicketsEAtualizar(ev, pedido, cupomObj, promoterObj);
      PEDIDOS.push(pedido); persistPedidos(); persistEventos();
      await enviarEmailIngressos(pedido, ev);
      return res.json({ ok: true, pedidoId, cortesia: true });
    }

    if (!MP_PLATFORM_TOKEN) return res.status(500).json({ error: 'Pagamento indisponível no momento. Peça ao administrador para configurar o Mercado Pago.' });

    const { metodo, cpf, token, installments, paymentMethodId, issuerId } = req.body;
    const cpfLimpo = sanitize(cpf || '', 20).replace(/[^\d]/g, '');
    if (!cpfLimpo || cpfLimpo.length !== 11) return res.status(400).json({ error: 'CPF do comprador é obrigatório e deve ter 11 dígitos.' });

    // Garante um número "limpo" com exatamente 2 casas decimais — evita rejeição da API por formatação
    const valorCobranca = Number(total.toFixed(2));
    if (!(valorCobranca > 0)) return res.status(400).json({ error: 'Valor de cobrança inválido.' });

    const host = req.get('host'); const proto = req.get('x-forwarded-proto') || 'https';
    const baseUrl = `${proto}://${host}`;
    const descricao = `${ev.nome} — ${itensDetalhados.map(it => it.loteNome).join(', ')}`.slice(0, 250);

    const pedidoBase = {
      id: pedidoId, eventoId: ev.id, status: 'pendente',
      comprador: { nome: sanitize(comprador.nome,100), email: comprador.email, telefone: sanitize(comprador.telefone||'',30), cpf: cpfLimpo },
      compradorUserId,
      itens: itensDetalhados, subtotal, desconto, valorIngressos, taxaAdministrativa, total, cupomUsado: cupomObj?.codigo || null, promoterRef: promoterObj?.id || null,
      mpPaymentId: null, tickets: [], createdAt: new Date().toISOString()
    };

    if (metodo === 'pix') {
      const pixBody = {
        transaction_amount: valorCobranca, description: descricao, payment_method_id: 'pix',
        payer: { email: comprador.email, first_name: sanitize(comprador.nome,50), identification: { type: 'CPF', number: cpfLimpo } },
        external_reference: pedidoId, notification_url: `${baseUrl}/api/mp/webhook?ped=${pedidoId}`
      };
      console.log('Enviando pagamento PIX ao Mercado Pago:', JSON.stringify(pixBody));
      const pixResp = await fetch(`${MP_API}/v1/payments`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${MP_PLATFORM_TOKEN}`, 'X-Idempotency-Key': uuidv4() }, body: JSON.stringify(pixBody) });
      const pixData = await pixResp.json();
      if (!pixResp.ok) {
        console.error('Mercado Pago recusou o PIX:', pixResp.status, JSON.stringify(pixData));
        const detalhe = Array.isArray(pixData.cause) && pixData.cause[0]?.description ? pixData.cause[0].description : pixData.message;
        return res.status(400).json({ error: detalhe || 'Erro ao gerar PIX.' });
      }
      pedidoBase.mpPaymentId = String(pixData.id);
      PEDIDOS.push(pedidoBase); persistPedidos();
      const td = pixData.point_of_interaction?.transaction_data || {};
      return res.json({ ok: true, pedidoId, metodo: 'pix', qrCode: td.qr_code || '', qrCodeBase64: td.qr_code_base64 || '', testMode: isTestToken(MP_PLATFORM_TOKEN) });
    }

    // Cartão
    if (!token || !paymentMethodId) return res.status(400).json({ error: 'Dados do cartão incompletos.' });
    const cardBody = {
      transaction_amount: valorCobranca, token, description: descricao,
      installments: Math.max(1, parseInt(installments) || 1),
      payment_method_id: paymentMethodId, issuer_id: issuerId || undefined,
      payer: { email: comprador.email, identification: { type: 'CPF', number: cpfLimpo } },
      external_reference: pedidoId, notification_url: `${baseUrl}/api/mp/webhook?ped=${pedidoId}`
    };
    console.log('Enviando pagamento com cartão ao Mercado Pago:', JSON.stringify({ ...cardBody, token: '(oculto)' }));
    const cardResp = await fetch(`${MP_API}/v1/payments`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${MP_PLATFORM_TOKEN}`, 'X-Idempotency-Key': uuidv4() }, body: JSON.stringify(cardBody) });
    const cardData = await cardResp.json();
    if (!cardResp.ok) {
      console.error('Mercado Pago recusou o pagamento:', cardResp.status, JSON.stringify(cardData));
      const detalhe = Array.isArray(cardData.cause) && cardData.cause[0]?.description ? cardData.cause[0].description : cardData.message;
      return res.status(400).json({ error: detalhe || 'Erro ao processar pagamento.' });
    }

    pedidoBase.mpPaymentId = String(cardData.id);
    PEDIDOS.push(pedidoBase); persistPedidos();
    const pedidoSalvo = PEDIDOS.find(p => p.id === pedidoId);

    if (cardData.status === 'approved') {
      await processarPagamentoAprovado(pedidoSalvo, cardData.id);
      return res.json({ ok: true, pedidoId, status: 'approved', tickets: pedidoSalvo.tickets });
    } else if (cardData.status === 'in_process' || cardData.status === 'pending') {
      return res.json({ ok: true, pedidoId, status: 'pending' });
    } else {
      pedidoSalvo.status = 'recusado';
      persistPedidos();
      return res.json({ ok: false, pedidoId, status: 'rejected', motivo: traduzirMotivoRecusa(cardData.status_detail) });
    }
  } catch(e) { res.status(500).json({ error: e.message }); }
});

function traduzirMotivoRecusa(detalhe) {
  const mapa = {
    cc_rejected_insufficient_amount: 'Saldo ou limite insuficiente.',
    cc_rejected_bad_filled_security_code: 'CVV incorreto. Confira os 3 (ou 4) dígitos no verso do cartão.',
    cc_rejected_bad_filled_date: 'Data de validade incorreta.',
    cc_rejected_bad_filled_other: 'Dados do cartão incorretos. Revise e tente novamente.',
    cc_rejected_bad_filled_card_number: 'Número do cartão incorreto.',
    cc_rejected_call_for_authorize: 'Seu banco precisa autorizar essa compra. Ligue para o banco ou tente outro cartão.',
    cc_rejected_card_disabled: 'Cartão desabilitado. Entre em contato com seu banco.',
    cc_rejected_duplicated_payment: 'Pagamento duplicado — você já tentou pagar esse valor recentemente.',
    cc_rejected_high_risk: 'Pagamento recusado por segurança. Tente outro cartão.',
    cc_rejected_max_attempts: 'Você atingiu o limite de tentativas. Tente outro cartão.',
    cc_rejected_other_reason: 'Seu banco recusou o pagamento. Tente outro cartão.'
  };
  return mapa[detalhe] || 'Pagamento não aprovado. Tente outro cartão ou use o PIX.';
}

function gerarTicketsEAtualizar(ev, pedido, cupomObj, promoterObj) {
  pedido.tickets = [];
  if (!ev.assentosOcupados) ev.assentosOcupados = [];
  for (const it of pedido.itens) {
    const lote = ev.lotes.find(l => l.id === it.loteId);
    if (lote) lote.vendidos = (lote.vendidos || 0) + it.qtd;
    if (it.assento) {
      ev.assentosOcupados.push(it.assento);
      pedido.tickets.push({ codigo: gerarCodigoTicket(), loteNome: it.loteNome, assento: it.assento, usado: false, usadoEm: null });
    } else {
      for (let i = 0; i < it.qtd; i++) pedido.tickets.push({ codigo: gerarCodigoTicket(), loteNome: it.loteNome, usado: false, usadoEm: null });
    }
  }
  if (cupomObj) cupomObj.usosAtuais = (cupomObj.usosAtuais || 0) + 1;
  if (promoterObj) { promoterObj.vendas = (promoterObj.vendas || 0) + pedido.tickets.length; promoterObj.receita = (promoterObj.receita || 0) + pedido.total; }
  ev.updatedAt = new Date().toISOString();
}

async function gerarPdfIngressos(pedido, ev) {
  const doc = new PDFDocument({ size: 'A4', margin: 40 });
  const chunks = [];
  doc.on('data', c => chunks.push(c));
  const done = new Promise((resolve, reject) => { doc.on('end', () => resolve(Buffer.concat(chunks))); doc.on('error', reject); });

  const tickets = pedido.tickets || [];
  for (let i = 0; i < tickets.length; i++) {
    const t = tickets[i];
    if (i > 0) doc.addPage();
    doc.fontSize(20).fillColor('#C47B14').text('Lota Ticketeria', { align: 'left' });
    doc.moveDown(0.6);
    doc.fontSize(18).fillColor('#111').text(ev.nome || 'Evento', { align: 'left' });
    doc.moveDown(0.2);
    const dataStr = ev.dataEvento ? new Date(ev.dataEvento).toLocaleDateString('pt-BR', { weekday: 'long', day: '2-digit', month: 'long', year: 'numeric' }) : '';
    doc.fontSize(11).fillColor('#555').text(`${dataStr}${ev.horaEvento ? ' às ' + ev.horaEvento : ''}`);
    if (ev.local) doc.text(`${ev.local}${ev.cidade ? ', ' + ev.cidade : ''}`);
    doc.moveDown(1);

    doc.fontSize(12).fillColor('#111').text(`Comprador: ${pedido.comprador?.nome || ''}`);
    doc.fontSize(12).text(`Lote: ${t.loteNome || ''}${t.assento ? ' — Assento ' + t.assento : ''}`);
    doc.moveDown(1);

    try {
      const qrDataUrl = await QRCode.toDataURL(t.codigo, { width: 220, margin: 1 });
      const qrBuffer = Buffer.from(qrDataUrl.split(',')[1], 'base64');
      doc.image(qrBuffer, 40, doc.y, { width: 160 });
    } catch (e) {}

    doc.fontSize(13).fillColor('#C47B14').text(t.codigo, 220, doc.y - 100, { width: 300 });
    doc.moveDown(6);
    doc.fontSize(9).fillColor('#888').text('Apresente este QR Code (impresso ou no celular) na entrada do evento.', 40, doc.y);
    doc.text('Vendido com Lota Ticketeria.', 40, doc.y + 14);
  }
  doc.end();
  return done;
}

async function enviarEmailIngressos(pedido, ev) {
  if (!RESEND_API_KEY || !pedido.comprador?.email) return;
  const nomeEvento = ev.nome || 'Evento';
  const ticketsHtml = (pedido.tickets || []).map(t => `
    <div style="border:1px solid #2A2822;border-radius:10px;padding:16px;margin-bottom:10px;display:flex;align-items:center;gap:16px;background:#161410;">
      <img src="https://api.qrserver.com/v1/create-qr-code/?size=120x120&data=${encodeURIComponent(t.codigo)}" width="90" height="90" style="border-radius:8px;background:#fff;padding:4px" />
      <div><div style="font-family:monospace;font-weight:700;color:#C47B14;font-size:14px;">${t.codigo}</div><div style="font-size:12px;color:#A09880;margin-top:2px;">${esc(t.loteNome)}${t.assento?' · Assento '+esc(t.assento):''}</div></div>
    </div>`).join('');
  const html = `<div style="background:#0F0E0C;padding:32px 20px;font-family:Arial,sans-serif;color:#F0EDE8;"><div style="max-width:480px;margin:0 auto;">
    <div style="font-size:22px;font-weight:800;color:#C47B14;margin-bottom:4px;">🎟️ Lota Ticketeria</div>
    <p style="font-size:14px;color:#A09880;margin-bottom:24px;">Confirmação de compra</p>
    <h2 style="font-size:18px;margin-bottom:6px;">Seu ingresso para</h2>
    <p style="font-size:20px;font-weight:800;color:#fff;margin-bottom:20px;">${esc(nomeEvento)}</p>
    <p style="font-size:13px;color:#A09880;margin-bottom:16px;">Olá ${esc(pedido.comprador.nome)}, aqui estão seus ingressos:</p>
    ${ticketsHtml}
    <p style="font-size:11px;color:#605848;margin-top:20px;">Apresente o QR Code na entrada. Seu ingresso também está anexado em PDF neste e-mail.</p>
    </div></div>`;
  const payload = { from: RESEND_FROM, to: pedido.comprador.email, subject: `🎟️ Seus ingressos — ${nomeEvento}`, html };
  try {
    const pdfBuffer = await gerarPdfIngressos(pedido, ev);
    payload.attachments = [{ filename: `ingresso-${(ev.slug || 'lota')}.pdf`, content: pdfBuffer.toString('base64') }];
  } catch (e) { console.error('Erro ao gerar PDF do ingresso:', e.message); }
  try {
    const r = await fetch('https://api.resend.com/emails', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${RESEND_API_KEY}` }, body: JSON.stringify(payload) });
    if (!r.ok) { const errBody = await r.text().catch(()=>''); console.error('Resend recusou o envio do e-mail de ingressos:', r.status, errBody); }
  } catch(e) { console.error('Erro e-mail:', e.message); }
}

// ── WEBHOOK MERCADO PAGO ──
async function processarPagamentoAprovado(pedido, paymentId) {
  if (pedido.status === 'pago') return;
  pedido.status = 'pago'; pedido.pagoEm = new Date().toISOString();
  pedido.mpPaymentId = String(paymentId);
  const ev = EVENTOS.find(e => e.id === pedido.eventoId);
  if (ev) {
    const cupomObj = pedido.cupomUsado ? ev.cupons.find(c => c.codigo === pedido.cupomUsado) : null;
    const promoterObj = pedido.promoterRef ? ev.promoters.find(p => p.id === pedido.promoterRef) : null;
    gerarTicketsEAtualizar(ev, pedido, cupomObj, promoterObj);
    persistEventos();
    await enviarEmailIngressos(pedido, ev);
    pedido.emailEnviado = true;
  }
  persistPedidos();
}

app.post('/api/mp/webhook', async (req, res) => {
  try {
    // O Mercado Pago pode notificar em dois formatos diferentes:
    // novo:  type=payment  & data.id=X   (no corpo JSON ou na query)
    // antigo (IPN): topic=payment & id=X (só na query)
    const paymentId = req.body?.data?.id || req.query['data.id'] || (req.query.topic === 'payment' ? req.query.id : null);
    const isPaymentNotif = req.body?.type === 'payment' || req.query.type === 'payment' || req.query.topic === 'payment';
    if (!isPaymentNotif || !paymentId) return res.sendStatus(200);
    const { ped: pedidoId } = req.query;
    if (!MP_PLATFORM_TOKEN) return res.sendStatus(200);

    const payResp = await fetch(`${MP_API}/v1/payments/${paymentId}`, { headers: { 'Authorization': `Bearer ${MP_PLATFORM_TOKEN}` } });
    const payment = await payResp.json();
    if (!payResp.ok) return res.sendStatus(200);

    // Se o pedidoId não veio na URL (por algum motivo), localizamos pelo external_reference do próprio pagamento
    const pedido = PEDIDOS.find(p => p.id === (pedidoId || payment.external_reference));
    if (!pedido) return res.sendStatus(200);
    if (pedido.mpPaymentId === String(paymentId) && pedido.status === 'pago') return res.sendStatus(200);

    if (payment.status === 'approved') {
      await processarPagamentoAprovado(pedido, paymentId);
    } else if (['rejected','cancelled'].includes(payment.status)) {
      pedido.mpPaymentId = String(paymentId);
      pedido.status = 'recusado';
      persistPedidos();
    }
    res.sendStatus(200);
  } catch(e) { console.error('Erro no webhook do Mercado Pago:', e.message); res.sendStatus(200); }
});

app.get('/api/public/pedido/:pedidoId', rateLimit(60000, 60), async (req, res) => {
  const pedido = PEDIDOS.find(p => p.id === req.params.pedidoId);
  if (!pedido) return res.status(404).json({ error: 'Pedido não encontrado.' });
  // Rede de segurança: se o webhook do Mercado Pago não chegou por algum motivo (comum em PIX,
  // que pode demorar pra confirmar), consultamos ativamente o pagamento pelo ID que já guardamos.
  if (pedido.status === 'pendente' && pedido.mpPaymentId && MP_PLATFORM_TOKEN) {
    try {
      const payResp = await fetch(`${MP_API}/v1/payments/${pedido.mpPaymentId}`, { headers: { 'Authorization': `Bearer ${MP_PLATFORM_TOKEN}` } });
      const payData = await payResp.json();
      if (payResp.ok) {
        if (payData.status === 'approved') await processarPagamentoAprovado(pedido, payData.id);
        else if (['rejected','cancelled'].includes(payData.status)) { pedido.status = 'recusado'; persistPedidos(); }
      }
    } catch(e) { console.error('Erro ao verificar pagamento:', e.message); }
  }
  res.json({ status: pedido.status, total: pedido.total, tickets: pedido.tickets || [], comprador: { nome: pedido.comprador.nome } });
});

// Abre o ingresso como PDF dentro do navegador — mais fácil de mostrar no scanner da portaria
app.get('/api/public/pedido/:pedidoId/pdf', async (req, res) => {
  const pedido = PEDIDOS.find(p => p.id === req.params.pedidoId);
  if (!pedido) return res.status(404).send('Pedido não encontrado.');
  if (pedido.status !== 'pago') return res.status(400).send('Este pedido ainda não foi confirmado.');
  const ev = EVENTOS.find(e => e.id === pedido.eventoId);
  if (!ev) return res.status(404).send('Evento não encontrado.');
  try {
    const pdfBuffer = await gerarPdfIngressos(pedido, ev);
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `inline; filename="ingresso-${ev.slug || 'lota'}.pdf"`);
    res.send(pdfBuffer);
  } catch (e) {
    res.status(500).send('Erro ao gerar o PDF do ingresso.');
  }
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

app.patch('/api/admin/usuarios/:id/ativo', auth, adminOnly, (req, res) => {
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'Usuário não encontrado.' });
  if (user.isAdmin) return res.status(400).json({ error: 'Não é possível desativar uma conta de administrador.' });
  user.ativo = !!req.body.ativo;
  saveDB(db);
  res.json({ ok: true, usuario: safe(user) });
});

app.patch('/api/admin/usuarios/:id/verificado', auth, adminOnly, (req, res) => {
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'Usuário não encontrado.' });
  if (!user.isOrganizador) return res.status(400).json({ error: 'Somente produtores podem ser verificados.' });
  user.verificado = !!req.body.verificado;
  saveDB(db);
  res.json({ ok: true, usuario: safe(user) });
});

// ── VISÃO GERAL ──
app.get('/api/admin/overview', auth, adminOnly, (req, res) => {
  const totalUsuarios = db.users.length;
  const totalProdutores = db.users.filter(u => u.isOrganizador && !u.isAdmin).length;
  const totalClientes = db.users.filter(u => !u.isOrganizador && !u.isAdmin).length;
  const eventosPublicados = EVENTOS.filter(e => e.status === 'publicado').length;
  const pedidosPagos = PEDIDOS.filter(p => p.status === 'pago');
  const receitaTotal = pedidosPagos.reduce((s, p) => s + p.total, 0);
  const comissaoTotal = pedidosPagos.reduce((s, p) => s + ((p.taxaAdministrativa !== undefined ? p.taxaAdministrativa : (p.marketplaceFee || 0))), 0);
  const produtoresComPix = db.users.filter(u => u.isOrganizador && u.pagamentoInfo?.chavePix).length;
  const adiantamentosPendentes = ADIANTAMENTOS.filter(a => a.status === 'pendente').length;
  res.json({
    totalUsuarios, totalProdutores, totalClientes,
    totalEventos: EVENTOS.length, eventosPublicados,
    totalPedidosPagos: pedidosPagos.length, receitaTotal, comissaoTotal,
    produtoresComPix, adiantamentosPendentes, feePercent: db.marketplaceFeePercent
  });
});

// ── EVENTOS — lista e detalhe completo (visão de administrador) ──
app.get('/api/admin/eventos', auth, adminOnly, (req, res) => {
  const lista = EVENTOS.map(ev => {
    const organizador = db.users.find(u => u.id === ev.organizadorId);
    const pedidosPagos = PEDIDOS.filter(p => p.eventoId === ev.id && p.status === 'pago');
    const receita = pedidosPagos.reduce((s, p) => s + p.total, 0);
    const comissao = pedidosPagos.reduce((s, p) => s + ((p.taxaAdministrativa !== undefined ? p.taxaAdministrativa : (p.marketplaceFee || 0))), 0);
    const ingressos = pedidosPagos.reduce((s, p) => s + (p.tickets || []).length, 0);
    return {
      id: ev.id, nome: ev.nome, slug: ev.slug, status: ev.status, dataEvento: ev.dataEvento,
      cidade: ev.cidade, categoria: ev.categoria,
      organizadorNome: organizador?.nomePublico || organizador?.nome || '—',
      organizadorEmail: organizador?.email || '—',
      receita, comissao, ingressos, totalPedidos: pedidosPagos.length, createdAt: ev.createdAt
    };
  }).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json({ eventos: lista });
});

app.get('/api/admin/eventos/:id', auth, adminOnly, (req, res) => {
  const ev = EVENTOS.find(e => e.id === req.params.id);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  const organizador = db.users.find(u => u.id === ev.organizadorId);
  const pedidos = PEDIDOS.filter(p => p.eventoId === ev.id);
  res.json({ evento: ev, organizador: organizador ? { nome: organizador.nomePublico || organizador.nome, email: organizador.email } : null, pedidos });
});

// ── DOWNLOAD DE E-MAILS (participantes de um evento) — acesso irrestrito de admin ──
app.get('/api/admin/eventos/:id/participantes.csv', auth, adminOnly, (req, res) => {
  const ev = EVENTOS.find(e => e.id === req.params.id);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  const pedidos = PEDIDOS.filter(p => p.eventoId === ev.id && p.status === 'pago');
  const linhas = [['Nome', 'E-mail', 'Telefone', 'Lote', 'Código Ingresso', 'Usado', 'Data da Compra']];
  pedidos.forEach(p => (p.tickets || []).forEach(t => {
    linhas.push([p.comprador?.nome || '', p.comprador?.email || '', p.comprador?.telefone || '', t.loteNome || '', t.codigo, t.usado ? 'Sim' : 'Não', new Date(p.createdAt).toLocaleString('pt-BR')]);
  }));
  const csv = linhas.map(r => r.map(v => '"' + String(v).replace(/"/g, '""') + '"').join(';')).join('\r\n');
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="emails-${ev.slug}.csv"`);
  res.send('\uFEFF' + csv);
});

// ── TODOS OS E-MAILS DE TODOS OS EVENTOS EM UM ARQUIVO SÓ ──
app.get('/api/admin/emails-todos.csv', auth, adminOnly, (req, res) => {
  const linhas = [['Nome', 'E-mail', 'Telefone', 'Evento', 'Produtor', 'Lote', 'Data da Compra']];
  PEDIDOS.filter(p => p.status === 'pago').forEach(p => {
    const ev = EVENTOS.find(e => e.id === p.eventoId);
    const organizador = db.users.find(u => u.id === ev?.organizadorId);
    (p.tickets || []).forEach(t => {
      linhas.push([p.comprador?.nome || '', p.comprador?.email || '', p.comprador?.telefone || '', ev?.nome || '—', organizador?.nomePublico || organizador?.nome || '—', t.loteNome || '', new Date(p.createdAt).toLocaleString('pt-BR')]);
    });
  });
  const csv = linhas.map(r => r.map(v => '"' + String(v).replace(/"/g, '""') + '"').join(';')).join('\r\n');
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="emails-todos-eventos.csv"`);
  res.send('\uFEFF' + csv);
});

// ── RELATÓRIO FINANCEIRO — comissões recebidas pela plataforma ──
app.get('/api/admin/financeiro', auth, adminOnly, (req, res) => {
  const pedidosPagos = PEDIDOS.filter(p => p.status === 'pago');
  const totalReceita = pedidosPagos.reduce((s, p) => s + p.total, 0);
  const totalComissao = pedidosPagos.reduce((s, p) => s + ((p.taxaAdministrativa !== undefined ? p.taxaAdministrativa : (p.marketplaceFee || 0))), 0);

  // Por evento
  const porEventoMap = {};
  pedidosPagos.forEach(p => {
    if (!porEventoMap[p.eventoId]) porEventoMap[p.eventoId] = { receita: 0, comissao: 0, pedidos: 0 };
    porEventoMap[p.eventoId].receita += p.total;
    porEventoMap[p.eventoId].comissao += ((p.taxaAdministrativa !== undefined ? p.taxaAdministrativa : (p.marketplaceFee || 0)));
    porEventoMap[p.eventoId].pedidos += 1;
  });
  const porEvento = Object.entries(porEventoMap).map(([eventoId, d]) => {
    const ev = EVENTOS.find(e => e.id === eventoId);
    const organizador = db.users.find(u => u.id === ev?.organizadorId);
    return { eventoId, eventoNome: ev?.nome || '—', organizadorNome: organizador?.nomePublico || organizador?.nome || '—', ...d };
  }).sort((a, b) => b.comissao - a.comissao);

  // Por mês
  const porMesMap = {};
  pedidosPagos.forEach(p => {
    const mes = (p.pagoEm || p.createdAt).slice(0, 7); // YYYY-MM
    if (!porMesMap[mes]) porMesMap[mes] = { receita: 0, comissao: 0, pedidos: 0 };
    porMesMap[mes].receita += p.total;
    porMesMap[mes].comissao += ((p.taxaAdministrativa !== undefined ? p.taxaAdministrativa : (p.marketplaceFee || 0)));
    porMesMap[mes].pedidos += 1;
  });
  const porMes = Object.entries(porMesMap).map(([mes, d]) => ({ mes, ...d })).sort((a, b) => a.mes.localeCompare(b.mes));

  res.json({ totalReceita, totalComissao, totalPedidos: pedidosPagos.length, porEvento, porMes });
});

app.get('/api/admin/financeiro.csv', auth, adminOnly, (req, res) => {
  const pedidosPagos = PEDIDOS.filter(p => p.status === 'pago');
  const feePercent = db.marketplaceFeePercent || 10;
  const linhas = [
    ['RELATÓRIO FINANCEIRO — LOTA TICKETERIA'],
    ['Data de emissão', new Date().toLocaleString('pt-BR')],
    ['Comissão configurada', feePercent + '%'],
    [''],
    ['Evento', 'Produtor', 'Pedido', 'Comprador', 'Valor Bruto (R$)', 'Comissão Plataforma (R$)', 'Data']
  ];
  let totalBruto = 0, totalComissao = 0;
  pedidosPagos.forEach(p => {
    const ev = EVENTOS.find(e => e.id === p.eventoId);
    const organizador = db.users.find(u => u.id === ev?.organizadorId);
    const comissao = (p.taxaAdministrativa !== undefined ? p.taxaAdministrativa : (p.marketplaceFee || 0));
    totalBruto += p.total; totalComissao += comissao;
    linhas.push([ev?.nome || '—', organizador?.nomePublico || organizador?.nome || '—', p.id.slice(0, 8), p.comprador?.nome || '', p.total.toFixed(2).replace('.', ','), comissao.toFixed(2).replace('.', ','), new Date(p.createdAt).toLocaleDateString('pt-BR')]);
  });
  linhas.push(['']);
  linhas.push(['TOTAL', '', '', '', totalBruto.toFixed(2).replace('.', ','), totalComissao.toFixed(2).replace('.', ','), '']);
  const csv = linhas.map(r => r.map(v => '"' + String(v).replace(/"/g, '""') + '"').join(';')).join('\r\n');
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="financeiro-lota-ticketeria.csv"`);
  res.send('\uFEFF' + csv);
});


// ════════════════════════════════════════════════════════
app.get('/health', (req, res) => {
  res.json({
    status: 'ok', app: 'Lota Ticketeria', users: db.users.length, eventos: EVENTOS.length,
    mercadopago: MP_PLATFORM_TOKEN ? '✅' : '❌ (configure MP_ACCESS_TOKEN)',
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
  console.log(`   Mercado Pago: ${MP_PLATFORM_TOKEN ? '✅' : '❌'}`);
  console.log(`   Resend: ${RESEND_API_KEY ? '✅' : '❌'}\n`);
});
