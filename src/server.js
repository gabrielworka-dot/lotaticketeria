/**
 * LOTA — Plataforma de Ingressos e Comunidade
 * Inspirado em Tri.RS (marketplace) + Cheers (comunidade, promoters, cortesia)
 */

const express = require('express');
const bcrypt  = require('bcryptjs');
const crypto  = require('crypto');
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
const SUPORTE_WHATSAPP = process.env.SUPORTE_WHATSAPP || ''; // formato: 5511999998888 (só números, com DDI)
const SUPORTE_EMAIL = process.env.SUPORTE_EMAIL || '';
// Usado só em contextos sem uma requisição em andamento (como o job de limpeza abaixo), pra montar
// o link do PDF do ingresso no e-mail. Se não configurado, tenta adivinhar a partir do Railway.
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || (process.env.RAILWAY_PUBLIC_DOMAIN ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}` : '');

// ── Criptografia de dados sensíveis em repouso (CPF) ──
// Usa AES-256-GCM (padrão da indústria). A chave deve ter 32 bytes em hexadecimal (64 caracteres) —
// gere uma com: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
// Isso protege o CPF salvo nos arquivos de dados mesmo que alguém tenha acesso direto ao Volume —
// o resto do sistema continua funcionando normalmente com o valor decifrado em memória.
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '';
function criptografar(texto) {
  if (!ENCRYPTION_KEY || !texto || String(texto).startsWith('enc:')) return texto;
  try {
    const iv = crypto.randomBytes(12);
    const key = Buffer.from(ENCRYPTION_KEY, 'hex');
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    let encrypted = cipher.update(String(texto), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    return `enc:${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
  } catch (e) { console.error('Erro ao criptografar dado:', e.message); return texto; }
}
function descriptografar(valor) {
  if (!valor || !String(valor).startsWith('enc:') || !ENCRYPTION_KEY) return valor;
  try {
    const [, ivHex, authTagHex, encrypted] = String(valor).split(':');
    const key = Buffer.from(ENCRYPTION_KEY, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivHex, 'hex'));
    decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (e) { console.error('Erro ao descriptografar dado (chave pode ter mudado):', e.message); return valor; }
}
// Cifra/decifra só o CPF dos pedidos e usuários — no momento exato de salvar/carregar do disco.
// O resto do código nunca precisa saber disso: em memória, o valor sempre está em texto puro.
function cifrarCpfPedidos(pedidos) {
  if (!ENCRYPTION_KEY) return pedidos;
  return pedidos.map(p => (p.comprador?.cpf && !String(p.comprador.cpf).startsWith('enc:'))
    ? { ...p, comprador: { ...p.comprador, cpf: criptografar(p.comprador.cpf) } } : p);
}
function decifrarCpfPedidos(pedidos) {
  return pedidos.map(p => (p.comprador?.cpf && String(p.comprador.cpf).startsWith('enc:'))
    ? { ...p, comprador: { ...p.comprador, cpf: descriptografar(p.comprador.cpf) } } : p);
}
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const ASAAS_WEBHOOK_TOKEN = process.env.ASAAS_WEBHOOK_TOKEN || '';

// ── Security headers ──────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  // HSTS — força HTTPS em todas as visitas futuras (o navegador lembra por 1 ano)
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  // CSP — restringe de onde a página pode carregar scripts/imagens/etc, reduzindo bastante o risco
  // de um script malicioso injetado conseguir rodar. Listamos explicitamente todos os serviços
  // externos que a própria plataforma já usa (Mercado Pago, Google, QR Code, jsQR).
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    // Inclui os domínios de script dos pixels de rastreamento (Meta, Google Analytics/Ads, TikTok)
    // e do jsQR — sem isso, o CSP bloqueia silenciosamente esses scripts de carregar, mesmo que o
    // resto do código esteja certo (foi exatamente isso que quebrou os pixels antes).
    // O Card Payment Brick do Mercado Pago carrega recursos de VÁRIOS domínios além do sdk principal
    // (mlstatic.com pros arquivos do formulário, mercadolibre.com pra proteção antifraude, e também
    // o domínio "puro" mercadopago.com, sem nenhum subdomínio na frente — um *.mercadopago.com
    // com asterisco NÃO cobre o domínio sozinho, só cobre subdomínios dele) — faltando qualquer um
    // desses, o Brick falha silenciosamente ao montar.
    "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://sdk.mercadopago.com https://www.mercadopago.com https://mercadopago.com https://http2.mlstatic.com https://www.mercadolibre.com https://accounts.google.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net https://connect.facebook.net https://www.googletagmanager.com https://analytics.tiktok.com https://www.googleadservices.com https://googleads.g.doubleclick.net",
    "style-src 'self' 'unsafe-inline' https://http2.mlstatic.com https://www.mercadopago.com https://mercadopago.com https://fonts.googleapis.com https://accounts.google.com",
    "img-src 'self' data: https: blob:",
    "connect-src 'self' https://api.mercadopago.com https://www.mercadopago.com https://mercadopago.com https://*.mercadopago.com https://http2.mlstatic.com https://www.mercadolibre.com https://*.mercadolibre.com https://api.asaas.com https://api-sandbox.asaas.com https://oauth2.googleapis.com https://accounts.google.com https://api.qrserver.com https://www.facebook.com https://connect.facebook.net https://www.google-analytics.com https://analytics.google.com https://region1.google-analytics.com https://analytics.tiktok.com",
    // Inclui o YouTube e o mercadolibre.com (usado pelo Brick pra verificação antifraude via iframe)
    "frame-src 'self' https://sdk.mercadopago.com https://accounts.google.com https://*.mercadopago.com https://mercadopago.com https://www.mercadolibre.com https://www.youtube.com https://www.youtube-nocookie.com",
    "font-src 'self' data: https://http2.mlstatic.com https://fonts.gstatic.com",
  ].join('; '));
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
// IMPORTANTE: os dados (eventos, usuários, pedidos) NÃO podem morar em /app — essa pasta é o
// próprio código da aplicação e é substituída inteira a cada novo deploy no Railway.
// Por isso usamos uma pasta separada (/data), que deve ser configurada como Volume persistente
// no Railway — veja instruções no README/conversa com o suporte.
const DATA_DIR = process.env.DATA_DIR || (fs.existsSync('/data') ? '/data' : path.join(__dirname, '..'));
if (!fs.existsSync(DATA_DIR)) { try { fs.mkdirSync(DATA_DIR, { recursive: true }); } catch(e) {} }
console.log(`[Lota] Usando DATA_DIR = ${DATA_DIR}${DATA_DIR === '/data' ? ' (Volume persistente detectado ✅)' : ' (⚠️ ATENÇÃO: sem Volume persistente configurado — dados podem ser perdidos em redeploys!)'}`);
const POSSIBLE_PUBLIC = [ path.join(__dirname, '../public'), path.join(process.cwd(), 'public'), '/app/public' ];
const PUBLIC_DIR = POSSIBLE_PUBLIC.find(p => { try { return fs.existsSync(path.join(p,'index.html')); } catch(e) { return false; }}) || path.join(__dirname,'../public');

app.use(express.json({ limit: '10mb' }));

// Proteção contra "prototype pollution" — um tipo de ataque de injeção onde alguém manda um JSON
// com chaves especiais (__proto__, constructor, prototype) tentando corromper o comportamento
// interno do JavaScript em todo o servidor. Removemos essas chaves de qualquer requisição recebida,
// em qualquer nível de profundidade do objeto.
function removerChavesPerigosas(obj, profundidade = 0) {
  if (profundidade > 10 || obj === null || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) { obj.forEach(item => removerChavesPerigosas(item, profundidade + 1)); return obj; }
  for (const chave of ['__proto__', 'constructor', 'prototype']) {
    if (Object.prototype.hasOwnProperty.call(obj, chave)) delete obj[chave];
  }
  for (const k in obj) { if (Object.prototype.hasOwnProperty.call(obj, k)) removerChavesPerigosas(obj[k], profundidade + 1); }
  return obj;
}
app.use((req, res, next) => {
  if (req.body && typeof req.body === 'object') removerChavesPerigosas(req.body);
  next();
});
app.use(express.static(PUBLIC_DIR));

function esc(s) { return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
// Datas no formato "AAAA-MM-DD" (sem hora) NÃO devem ser parseadas com `new Date(str)` puro —
// isso é interpretado como meia-noite UTC e, ao exibir no fuso do Brasil, "volta" um dia.
// Essa função monta a data usando os componentes locais, sem esse problema.
function parseDataLocal(dataStr) {
  if (!dataStr) return new Date();
  const [y, m, d] = String(dataStr).split('-').map(Number);
  return new Date(y, (m || 1) - 1, d || 1);
}
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
// Detecta quantas PESSOAS um lote admite, pelo nome (não temos campo estruturado pra isso ainda).
// "Duplo" admite 2, "Quádruplo/Quadruplo" admite 4 — cada pessoa recebe seu próprio ingresso com
// QR Code individual, mesmo comprados juntos numa única unidade do lote.
function pessoasPorUnidadeLote(nomeLote) {
  const nome = (nomeLote || '').toLowerCase();
  if (/qu[aá]druplo|quadrupla/.test(nome)) return 4;
  if (/\bduplo\b|\bdupla\b/.test(nome)) return 2;
  return 1;
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
  try {
    if (fs.existsSync(DB_FILE)) {
      const dados = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
      if (dados.users) dados.users = dados.users.map(u => (u.cpfCnpj && String(u.cpfCnpj).startsWith('enc:')) ? { ...u, cpfCnpj: descriptografar(u.cpfCnpj) } : u);
      return dados;
    }
  } catch(e) {}
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
function saveDB(d) {
  const paraSalvar = ENCRYPTION_KEY && d.users
    ? { ...d, users: d.users.map(u => (u.cpfCnpj && !String(u.cpfCnpj).startsWith('enc:')) ? { ...u, cpfCnpj: criptografar(u.cpfCnpj) } : u) }
    : d;
  fs.writeFile(DB_FILE, JSON.stringify(paraSalvar, null, 2), (err) => { if (err) console.error('Erro ao salvar db.json:', err.message); });
}
let db = loadDB();
if (!db.loginAttempts) db.loginAttempts = {};
if (!db.ticketSlugs) db.ticketSlugs = {};
if (db.marketplaceFeePercent === undefined) db.marketplaceFeePercent = 10;
if (db.provedorPagamento === undefined) db.provedorPagamento = 'mercadopago'; // 'mercadopago' | 'asaas'
console.log(`✅ Banco carregado: ${db.users.length} usuário(s)`);

// ── Coleções em arquivo (eventos, pedidos, posts, follows) ──
function loadColecao(nome) {
  try { const f = path.join(DATA_DIR, nome + '.json'); if (fs.existsSync(f)) return JSON.parse(fs.readFileSync(f, 'utf8')); } catch(e) {}
  return [];
}
function saveColecao(nome, arr) { fs.writeFile(path.join(DATA_DIR, nome + '.json'), JSON.stringify(arr), (err) => { if (err) console.error(`Erro ao salvar ${nome}.json:`, err.message); }); }
// Versão síncrona — usada só no momento mais crítico (criação de um pedido novo), garantindo que o
// registro esteja de verdade gravado em disco ANTES de responder ao comprador e ele ser redirecionado
// pro provedor de pagamento. Sem isso, existia uma janela pequena (mas real) onde, se o servidor
// reiniciasse bem nesse intervalo, o pedido podia se perder mesmo com o pagamento sendo concluído
// normalmente do lado do Asaas/Mercado Pago — explicando pedidos que "sumiam" sem nenhum rastro.
function saveColecaoSync(nome, arr) {
  try { fs.writeFileSync(path.join(DATA_DIR, nome + '.json'), JSON.stringify(arr)); return true; }
  catch (e) { console.error(`Erro ao salvar ${nome}.json (síncrono):`, e.message); return false; }
}
function persistPedidosSync() { return saveColecaoSync('pedidos', cifrarCpfPedidos(PEDIDOS)); }
let EVENTOS  = loadColecao('eventos');
let PEDIDOS  = decifrarCpfPedidos(loadColecao('pedidos'));
let MENSAGENS = loadColecao('mensagens');
let CONSUMOS_BAR = loadColecao('consumos_bar');
function persistConsumosBar() { saveColecao('consumos_bar', CONSUMOS_BAR); }
let AUDITORIA = loadColecao('auditoria');
function persistAuditoria() { saveColecao('auditoria', AUDITORIA); }
// Registra uma ação sensível feita por um admin — quem, o quê, quando. Útil pra investigar depois
// se algo inesperado acontecer (reembolso indevido, edição de dados, etc). Nunca bloqueia a ação
// em si — só guarda o registro em paralelo, silenciosamente.
function registrarAuditoria(user, acao, detalhes) {
  try {
    AUDITORIA.push({ id: uuidv4(), userId: user.id, userNome: user.nome, userEmail: user.email, acao, detalhes: detalhes || {}, createdAt: new Date().toISOString() });
    if (AUDITORIA.length > 5000) AUDITORIA = AUDITORIA.slice(-5000); // evita crescer sem limite
    persistAuditoria();
  } catch (e) { console.error('Erro ao registrar auditoria:', e.message); }
}
function persistMensagens() { saveColecao('mensagens', MENSAGENS); }
let FOLLOWS  = loadColecao('follows');
let ADIANTAMENTOS = loadColecao('adiantamentos');
function persistEventos() { saveColecao('eventos', EVENTOS); }
function persistPedidos() { saveColecao('pedidos', cifrarCpfPedidos(PEDIDOS)); }
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
  // Bug corrigido: essa checagem só reconhecia o sistema antigo (colaboradorDe, vínculo com TODOS
  // os eventos de um produtor) — quem foi adicionado só a um evento específico (sistema novo) nunca
  // passava daqui, e a plataforma aparecia vazia mesmo com o acesso concedido corretamente.
  const ehColaboradorDeAlgumEvento = EVENTOS.some(e => (e.colaboradoresIds || []).includes(req.user.id));
  if (!req.user.isOrganizador && !req.user.colaboradorDe && !ehColaboradorDeAlgumEvento) {
    return res.status(403).json({ error: 'Acesso restrito a produtores e sua equipe.' });
  }
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
// Usado só em rotas de LEITURA — permite dono do evento, colaborador adicionado NESSE evento
// específico, ou (compatibilidade com quem já foi adicionado do jeito antigo) colaborador geral
// do produtor.
function eventoVisivelPara(eventoId, user) {
  const ev = EVENTOS.find(e => e.id === eventoId);
  if (!ev) return null;
  if (user.isAdmin) return ev;
  if (ev.organizadorId === user.id) return ev;
  if ((ev.colaboradoresIds || []).includes(user.id)) return ev;
  if (user.colaboradorDe && ev.organizadorId === user.colaboradorDe) return ev; // compatibilidade
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
  const codigoIndicacaoUsado = sanitize(req.body.codigoIndicacao || '', 12).toUpperCase();
  if (!nome || !email || !senha) return res.status(400).json({ error: 'Preencha todos os campos.' });
  if (senha.length < 6) return res.status(400).json({ error: 'Senha deve ter pelo menos 6 caracteres.' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'E-mail inválido.' });
  if (ehProdutor && !nomePublicoInformado) return res.status(400).json({ error: 'Nome público obrigatório para produtores.' });
  if (ehProdutor && !cpfCnpj) return res.status(400).json({ error: 'CPF ou CNPJ obrigatório para produtores.' });
  if (db.users.find(u => u.email === email)) return res.status(400).json({ error: 'E-mail já cadastrado.' });
  const slugsExistentes = db.users.filter(u => u.organizadorSlug).map(u => u.organizadorSlug);
  let indicadoPor = null;
  if (codigoIndicacaoUsado) {
    const quemIndicou = db.users.find(u => u.codigoIndicacao === codigoIndicacaoUsado);
    if (quemIndicou) indicadoPor = quemIndicou.id;
  }
  const user = {
    id: uuidv4(), nome, email, senha: bcrypt.hashSync(senha, 12),
    isAdmin: false, ativo: true, emailVerificado: false, verificado: false, colaboradorDe: null,
    isOrganizador: ehProdutor,
    nomePublico: ehProdutor ? nomePublicoInformado : '',
    organizadorSlug: ehProdutor ? gerarSlugUnico(nomePublicoInformado, slugsExistentes) : '',
    cpfCnpj: ehProdutor ? cpfCnpj : '', tipoDocumento: ehProdutor ? tipoDocumento : '',
    pagamentoInfo: { chavePix: '', tipoChavePix: '', nomeTitular: '', nomeBanco: '', numeroAgencia: '', tipoConta: '' },
    bio: '', avatarUrl: '', bannerUrl: '', redesSociais: {},
    codigoIndicacao: gerarCodigoIndicacaoUnico(), indicadoPor, saldoCredito: 0, boasVindasCreditoConcedido: false,
    createdAt: new Date().toISOString()
  };
  db.users.push(user); saveDB(db);
  const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '30d' });
  const host = req.get('host'); const proto = req.get('x-forwarded-proto') || 'https';
  enviarEmailVerificacao(user, proto, host).catch(() => {});
  res.status(201).json({ token, user: safe(user) });
});
function gerarCodigoIndicacaoUnico() {
  let codigo;
  do { codigo = Math.random().toString(36).slice(2, 8).toUpperCase(); } while (db.users.find(u => u.codigoIndicacao === codigo));
  return codigo;
}

// Login/cadastro com Google — confirma o token direto com o Google (sem precisar de biblioteca
// própria de verificação de JWT), e cria ou reconhece a conta pelo e-mail automaticamente.
app.post('/api/auth/google', rateLimit(60000, 20), async (req, res) => {
  const { credential } = req.body;
  if (!credential) return res.status(400).json({ error: 'Token do Google ausente.' });
  if (!GOOGLE_CLIENT_ID) return res.status(500).json({ error: 'Login com Google não está configurado no servidor.' });
  try {
    const verResp = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(credential)}`);
    const verData = await verResp.json();
    if (!verResp.ok || verData.aud !== GOOGLE_CLIENT_ID) {
      return res.status(401).json({ error: 'Token do Google inválido.' });
    }
    if (verData.email_verified !== 'true' && verData.email_verified !== true) {
      return res.status(401).json({ error: 'E-mail do Google não verificado.' });
    }
    const email = sanitize(verData.email || '', 150).toLowerCase();
    let user = db.users.find(u => u.email === email);
    if (!user) {
      user = {
        id: uuidv4(), nome: sanitize(verData.name || email.split('@')[0], 100), email,
        senha: bcrypt.hashSync(uuidv4(), 12), // senha aleatória — essa conta só entra via Google
        isAdmin: false, ativo: true, emailVerificado: true, verificado: false, colaboradorDe: null,
        isOrganizador: false, nomePublico: '', organizadorSlug: '', cpfCnpj: '', tipoDocumento: '',
        pagamentoInfo: { chavePix: '', tipoChavePix: '', nomeTitular: '', nomeBanco: '', numeroAgencia: '', tipoConta: '' },
        bio: '', avatarUrl: '', bannerUrl: '', redesSociais: {}, contaGoogle: true,
        codigoIndicacao: gerarCodigoIndicacaoUnico(), indicadoPor: null, saldoCredito: 0, boasVindasCreditoConcedido: false,
        createdAt: new Date().toISOString()
      };
      db.users.push(user); saveDB(db);
    } else if (user.ativo === false) {
      return res.status(403).json({ error: 'Esta conta foi desativada. Entre em contato com o suporte.' });
    }
    if (user.twoFactorAtivo) {
      const preAuthToken = jwt.sign({ id: user.id, tipo: 'pre2fa' }, JWT_SECRET, { expiresIn: '5m' });
      return res.json({ precisa2FA: true, preAuthToken });
    }
    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: safe(user) });
  } catch (e) { res.status(500).json({ error: 'Erro ao verificar login do Google: ' + e.message }); }
});

async function enviarEmailVerificacao(user, proto, host) {
  const verifyToken = jwt.sign({ uid: user.id, tipo: 'verificacao' }, JWT_SECRET, { expiresIn: '3d' });
  const link = `${proto}://${host}/verificar-email.html?token=${verifyToken}`;
  const html = `<div style="background:#0F0E0C;padding:32px 20px;font-family:Arial,sans-serif;color:#F0EDE8;"><div style="max-width:480px;margin:0 auto;">
    <div style="margin-bottom:20px;"><img src="${proto}://${host}/logo-header.png" alt="Lota" height="28" style="vertical-align:middle;margin-right:8px"><span style="font-size:20px;font-weight:800;color:#C47B14;vertical-align:middle;">Lota</span></div>
    <h2 style="font-size:18px;margin-bottom:12px;">Confirme seu e-mail</h2>
    <p style="font-size:13px;color:#A09880;margin-bottom:20px;">Olá ${esc(user.nome)}! Clique no botão abaixo para confirmar seu cadastro. O link expira em 3 dias.</p>
    <a href="${link}" style="display:inline-block;background:#E8961A;color:#18160F;font-weight:800;padding:12px 24px;border-radius:9px;text-decoration:none;font-size:14px;">Confirmar e-mail →</a>
    <p style="font-size:11px;color:#605848;margin-top:24px;">Se não foi você quem se cadastrou, ignore este e-mail.</p>
    </div></div>`;
  return enviarEmailGenerico(user.email, '✅ Confirme seu e-mail — Lota', html);
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
  const secret = speakeasy.generateSecret({ name: `Lota (${req.user.email})`, length: 20 });
  const user = db.users.find(u => u.id === req.user.id);
  user.twoFactorSecretPendente = secret.base32;
  saveDB(db);
  QRCode.toDataURL(secret.otpauth_url).then(qr => {
    res.json({ qrCode: qr, secretManual: secret.base32 });
  }).catch(() => res.status(500).json({ error: 'Erro ao gerar QR Code.' }));
});

app.post('/api/auth/2fa/ativar', auth, (req, res) => {
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

// ── FERRAMENTAS DE PRIVACIDADE (LGPD) ──
// Exporta todos os dados pessoais que temos sobre o usuário logado — perfil e pedidos onde ele foi
// o comprador. Atende ao direito de acesso/portabilidade previsto na LGPD.
app.get('/api/auth/meus-dados', auth, (req, res) => {
  const meusPedidos = PEDIDOS.filter(p => p.compradorUserId === req.user.id || (p.comprador?.email || '').toLowerCase() === req.user.email.toLowerCase());
  res.setHeader('Content-Disposition', 'attachment; filename="meus-dados-lota-ticketeria.json"');
  res.json({
    exportadoEm: new Date().toISOString(),
    perfil: safe(req.user),
    pedidos: meusPedidos.map(p => ({ evento: EVENTOS.find(e => e.id === p.eventoId)?.nome || p.eventoId, status: p.status, total: p.total, data: p.createdAt, ingressos: (p.tickets || []).map(t => t.codigo) }))
  });
});

// Exclui/anonimiza a conta do usuário — atende ao direito de eliminação previsto na LGPD. Não
// apaga pedidos já pagos (obrigação legal de manter registro fiscal/financeiro por um tempo), mas
// remove os dados pessoais identificáveis, mantendo só o necessário pra histórico financeiro.
app.post('/api/auth/excluir-conta', auth, async (req, res) => {
  const { senha } = req.body;
  if (!senha || !bcrypt.compareSync(senha, req.user.senha)) return res.status(401).json({ error: 'Senha incorreta.' });
  if (req.user.isAdmin) return res.status(400).json({ error: 'Não é possível excluir a conta de administrador por aqui.' });
  const anonimo = `usuario-removido-${req.user.id.slice(0, 8)}@removido.local`;
  req.user.nome = 'Usuário removido';
  req.user.email = anonimo;
  req.user.senha = bcrypt.hashSync(uuidv4(), 12);
  req.user.ativo = false;
  req.user.cpfCnpj = '';
  req.user.bio = ''; req.user.avatarUrl = ''; req.user.bannerUrl = ''; req.user.redesSociais = {};
  req.user.pagamentoInfo = { chavePix: '', tipoChavePix: '', nomeTitular: '', nomeBanco: '', numeroAgencia: '', tipoConta: '' };
  saveDB(db);
  res.json({ ok: true });
});

// Exclusão de conta específica pra PRODUTORES — com proteções extras que a exclusão genérica não
// tem, já que aqui existe evento, dinheiro de comprador e obrigações financeiras envolvidas.
app.get('/api/produtor/posso-excluir-conta', auth, organizadorOnly, (req, res) => {
  const agora = new Date().toISOString().slice(0, 10);
  const eventosFuturos = EVENTOS.filter(e => e.organizadorId === req.user.id && e.status === 'publicado' && e.dataEvento >= agora);
  const saldo = calcularSaldoProdutor(req.user.id);
  const bloqueios = [];
  if (eventosFuturos.length > 0) bloqueios.push(`Você tem ${eventosFuturos.length} evento(s) publicado(s) que ainda não aconteceu(ram). Cancele ou espere eles passarem antes de excluir a conta.`);
  if (saldo.saldoDisponivel > 0) bloqueios.push(`Você tem R$ ${saldo.saldoDisponivel.toFixed(2)} de saldo disponível ainda não recebido. Solicite o adiantamento desse valor antes de excluir a conta.`);
  res.json({ podeExcluir: bloqueios.length === 0, bloqueios, eventosFuturos: eventosFuturos.length, saldoDisponivel: saldo.saldoDisponivel });
});
app.post('/api/produtor/excluir-conta', auth, organizadorOnly, async (req, res) => {
  const { senha } = req.body;
  if (!senha || !bcrypt.compareSync(senha, req.user.senha)) return res.status(401).json({ error: 'Senha incorreta.' });
  const agora = new Date().toISOString().slice(0, 10);
  const eventosFuturos = EVENTOS.filter(e => e.organizadorId === req.user.id && e.status === 'publicado' && e.dataEvento >= agora);
  if (eventosFuturos.length > 0) return res.status(400).json({ error: 'Você ainda tem eventos publicados que não aconteceram. Cancele-os ou espere a data passar antes de excluir a conta.' });
  const saldo = calcularSaldoProdutor(req.user.id);
  if (saldo.saldoDisponivel > 0) return res.status(400).json({ error: `Você ainda tem R$ ${saldo.saldoDisponivel.toFixed(2)} de saldo disponível. Solicite o adiantamento antes de excluir a conta.` });
  // Não apagamos os eventos nem os pedidos — quem já comprou ingresso continua com acesso normal.
  // Só anonimizamos os dados pessoais do produtor, igual fazemos com contas de cliente.
  const anonimo = `produtor-removido-${req.user.id.slice(0, 8)}@removido.local`;
  req.user.nome = 'Produtor removido';
  req.user.nomePublico = 'Produtor removido';
  req.user.email = anonimo;
  req.user.senha = bcrypt.hashSync(uuidv4(), 12);
  req.user.ativo = false;
  req.user.cpfCnpj = '';
  req.user.bio = ''; req.user.avatarUrl = ''; req.user.bannerUrl = ''; req.user.redesSociais = {};
  req.user.pagamentoInfo = { chavePix: '', tipoChavePix: '', nomeTitular: '', nomeBanco: '', numeroAgencia: '', tipoConta: '' };
  req.user.twoFactorAtivo = false; req.user.twoFactorSecret = undefined;
  saveDB(db);
  registrarAuditoria(req.user, 'produtor_excluiu_propria_conta', { userId: req.user.id });
  res.json({ ok: true });
});

// ════════════════════════════════════════════════════════
// RECUPERAÇÃO DE EMERGÊNCIA DO ADMIN — não depende de e-mail.
// Só funciona se ADMIN_RECOVERY_SECRET estiver configurado no Railway,
// e só altera a conta de administrador — nunca toca em eventos, pedidos ou outros usuários.
// ════════════════════════════════════════════════════════
app.post('/api/admin/recuperar-acesso', rateLimit(300000, 5), (req, res) => {
  const secretConfigurado = process.env.ADMIN_RECOVERY_SECRET;
  if (!secretConfigurado) return res.status(503).json({ error: 'Recuperação de emergência não configurada. Defina ADMIN_RECOVERY_SECRET nas variáveis de ambiente.' });
  const secretEnviado = req.headers['x-recovery-secret'] || '';
  if (secretEnviado !== secretConfigurado) return res.status(403).json({ error: 'Chave de recuperação incorreta.' });
  const admin = db.users.find(u => u.isAdmin);
  if (!admin) return res.status(404).json({ error: 'Nenhuma conta de administrador encontrada.' });
  const { novoEmail, novaSenha } = req.body;
  if (novoEmail) {
    const emailLimpo = sanitize(novoEmail, 150).toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailLimpo)) return res.status(400).json({ error: 'E-mail inválido.' });
    if (db.users.find(u => u.email === emailLimpo && u.id !== admin.id)) return res.status(400).json({ error: 'Esse e-mail já está em uso por outra conta.' });
    admin.email = emailLimpo;
    admin.emailVerificado = true;
  }
  if (novaSenha) {
    if (novaSenha.length < 6) return res.status(400).json({ error: 'Nova senha muito curta (mínimo 6 caracteres).' });
    admin.senha = bcrypt.hashSync(novaSenha, 12);
  }
  saveDB(db);
  res.json({ ok: true, email: admin.email });
});

app.get('/api/auth/indicacao', auth, (req, res) => {
  const totalIndicados = db.users.filter(u => u.indicadoPor === req.user.id).length;
  const totalIndicadosComprando = db.users.filter(u => u.indicadoPor === req.user.id && u.boasVindasCreditoConcedido).length;
  res.json({ codigoIndicacao: req.user.codigoIndicacao, saldoCredito: req.user.saldoCredito || 0, totalIndicados, totalIndicadosComprando });
});

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
  const { nome, bio, avatarUrl, bannerUrl, redesSociais, senhaAtual, novaSenha, novoEmail, cpfCnpj, tipoDocumento, pagamentoInfo } = req.body;
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
  // Trocar e-mail ou senha exige confirmar a senha atual — proteção contra alguém mexer na conta sem autorização
  if (novoEmail) {
    if (!senhaAtual || !bcrypt.compareSync(senhaAtual, user.senha)) return res.status(401).json({ error: 'Senha atual incorreta.' });
    const emailNormalizado = sanitize(novoEmail, 150).toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailNormalizado)) return res.status(400).json({ error: 'E-mail inválido.' });
    if (emailNormalizado !== user.email && db.users.find(u => u.email === emailNormalizado)) return res.status(400).json({ error: 'Esse e-mail já está em uso por outra conta.' });
    user.email = emailNormalizado;
    user.emailVerificado = false;
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
  const { nomePublico, bio, aceitouTermos } = req.body;
  if (!nomePublico) return res.status(400).json({ error: 'Nome público obrigatório.' });
  // Aceite explícito e obrigatório dos Termos de Responsabilidade do Produtor — sem isso, ninguém
  // vira produtor. Guardamos a data/hora exata como prova de que o aceite aconteceu.
  if (!aceitouTermos) return res.status(400).json({ error: 'É necessário aceitar os Termos de Responsabilidade do Produtor.' });
  const slugsExistentes = db.users.filter(u => u.organizadorSlug).map(u => u.organizadorSlug);
  user.isOrganizador = true;
  user.nomePublico = sanitize(nomePublico, 100);
  user.organizadorSlug = gerarSlugUnico(nomePublico, slugsExistentes);
  user.bio = sanitize(bio || '', 500);
  user.aceitouTermosProdutorEm = new Date().toISOString();
  user.podeAntecipar = false; // só quem tem contrato com a gente pode solicitar adiantamento — ver rota de admin
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

// ── Colaboradores POR EVENTO — cada pessoa só acompanha as vendas do evento em que foi
// adicionada, não de todos os eventos do produtor de uma vez.
app.get('/api/eventos/:id/colaboradores', auth, (req, res) => {
  const ev = eventoDoUsuario(req.params.id, req.user.id);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  const membros = (ev.colaboradoresIds || []).map(id => db.users.find(u => u.id === id)).filter(Boolean).map(u => ({ id: u.id, nome: u.nome, email: u.email }));
  res.json({ colaboradores: membros });
});
app.post('/api/eventos/:id/colaboradores', auth, (req, res) => {
  const ev = eventoDoUsuario(req.params.id, req.user.id);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  const email = sanitize(req.body.email || '', 150).toLowerCase();
  if (!email) return res.status(400).json({ error: 'Informe o e-mail da pessoa.' });
  const pessoa = db.users.find(u => u.email === email);
  if (!pessoa) return res.status(404).json({ error: 'Não existe conta cadastrada com esse e-mail. Peça para a pessoa criar uma conta primeiro.' });
  if (pessoa.id === req.user.id) return res.status(400).json({ error: 'Você não pode se adicionar como colaborador de si mesmo.' });
  if (pessoa.isOrganizador) return res.status(400).json({ error: 'Essa conta já é de um produtor e não pode ser adicionada como colaboradora.' });
  if (!ev.colaboradoresIds) ev.colaboradoresIds = [];
  if (ev.colaboradoresIds.includes(pessoa.id)) return res.status(400).json({ error: 'Essa pessoa já é colaboradora deste evento.' });
  ev.colaboradoresIds.push(pessoa.id);
  persistEventos();
  res.status(201).json({ ok: true, colaborador: { id: pessoa.id, nome: pessoa.nome, email: pessoa.email } });
});
app.delete('/api/eventos/:id/colaboradores/:userId', auth, (req, res) => {
  const ev = eventoDoUsuario(req.params.id, req.user.id);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  if (!ev.colaboradoresIds || !ev.colaboradoresIds.includes(req.params.userId)) return res.status(404).json({ error: 'Colaborador não encontrado neste evento.' });
  ev.colaboradoresIds = ev.colaboradoresIds.filter(id => id !== req.params.userId);
  persistEventos();
  res.json({ ok: true });
});


// (MP_CLIENT_ID/MP_CLIENT_SECRET não são mais necessários — pagamento único via MP_ACCESS_TOKEN)
const MP_API = 'https://api.mercadopago.com';
const ASAAS_API_KEY = process.env.ASAAS_API_KEY || '';
const ASAAS_SANDBOX = process.env.ASAAS_SANDBOX === 'true';
const ASAAS_API = ASAAS_SANDBOX ? 'https://api-sandbox.asaas.com/v3' : 'https://api.asaas.com/v3';
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const RESEND_FROM    = process.env.RESEND_FROM_EMAIL || 'Lota <onboarding@resend.dev>';

async function enviarEmailGenerico(destinatario, assunto, html) {
  if (!RESEND_API_KEY || !destinatario) { console.error('Resend não configurado ou destinatário ausente ao tentar enviar:', assunto); return false; }
  try {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${RESEND_API_KEY}` },
      body: JSON.stringify({ from: RESEND_FROM, to: destinatario, subject: assunto, html })
    });
    const data = await r.json().catch(()=>({}));
    if (!r.ok) { console.error('Resend recusou o e-mail:', assunto, '| destinatário:', destinatario, '| status:', r.status, '| resposta:', JSON.stringify(data)); }
    else { console.log('Resend aceitou o e-mail com sucesso:', assunto, '| destinatário:', destinatario, '| id:', data.id); }
    return r.ok;
  } catch(e) { console.error('Erro e-mail:', e.message); return false; }
}

async function notificarSeguidoresNovoEvento(ev, organizador, baseUrl) {
  const seguidores = FOLLOWS.filter(f => f.organizadorId === organizador.id);
  if (!seguidores.length) return;
  const nomeExibicao = organizador.nomePublico || organizador.nome;
  const linkEvento = `${baseUrl}/e/${ev.slug}`;
  const dataStr = ev.dataEvento ? parseDataLocal(ev.dataEvento).toLocaleDateString('pt-BR', { day: '2-digit', month: 'long', year: 'numeric' }) : '';
  console.log(`Notificando ${seguidores.length} seguidor(es) de ${nomeExibicao} sobre o novo evento "${ev.nome}"`);
  for (const f of seguidores) {
    const seguidor = db.users.find(u => u.id === f.userId);
    if (!seguidor?.email) continue;
    const html = `<div style="background:#0F0E0C;padding:32px 20px;font-family:Arial,sans-serif;color:#F0EDE8;"><div style="max-width:480px;margin:0 auto;">
      <div style="margin-bottom:20px;"><img src="${baseUrl}/logo-header.png" alt="Lota" height="28" style="vertical-align:middle;margin-right:8px"><span style="font-size:20px;font-weight:800;color:#C47B14;vertical-align:middle;">Lota</span></div>
      <p style="font-size:13px;color:#A09880;margin-bottom:6px;">${esc(nomeExibicao)} acabou de publicar um novo evento</p>
      <h2 style="font-size:20px;font-weight:800;color:#fff;margin-bottom:10px;">${esc(ev.nome)}</h2>
      ${dataStr ? `<p style="font-size:13px;color:#A09880;margin-bottom:20px;">📅 ${dataStr}${ev.cidade ? ' · ' + esc(ev.cidade) : ''}</p>` : ''}
      <a href="${linkEvento}" style="display:inline-block;background:#E8961A;color:#18160F;font-weight:800;padding:12px 24px;border-radius:9px;text-decoration:none;font-size:14px;">Ver evento e comprar →</a>
      <p style="font-size:11px;color:#605848;margin-top:24px;">Você está recebendo esse e-mail porque segue ${esc(nomeExibicao)} na Lota.</p>
      </div></div>`;
    await enviarEmailGenerico(seguidor.email, `${nomeExibicao} publicou: ${ev.nome}`, html);
  }
}

// ════════════════════════════════════════════════════════
// RECUPERAÇÃO DE SENHA
// ════════════════════════════════════════════════════════
app.post('/api/auth/esqueci-senha', rateLimit(60000, 5), async (req, res) => {
  const email = sanitize(req.body.email || '', 150).toLowerCase();
  // Sempre responde sucesso, mesmo se o e-mail não existir — evita expor quais e-mails estão cadastrados
  const user = db.users.find(u => u.email === email);
  console.log(`Recuperação de senha solicitada para "${email}" — conta encontrada: ${user ? 'sim' : 'NÃO'}`);
  if (user) {
    const token = jwt.sign({ uid: user.id, tipo: 'reset' }, JWT_SECRET, { expiresIn: '30m' });
    const host = req.get('host'); const proto = req.get('x-forwarded-proto') || 'https';
    const link = `${proto}://${host}/redefinir-senha.html?token=${token}`;
    const html = `<div style="background:#0F0E0C;padding:32px 20px;font-family:Arial,sans-serif;color:#F0EDE8;"><div style="max-width:480px;margin:0 auto;">
      <div style="margin-bottom:20px;"><img src="${proto}://${host}/logo-header.png" alt="Lota" height="28" style="vertical-align:middle;margin-right:8px"><span style="font-size:20px;font-weight:800;color:#C47B14;vertical-align:middle;">Lota</span></div>
      <h2 style="font-size:18px;margin-bottom:12px;">Redefinir sua senha</h2>
      <p style="font-size:13px;color:#A09880;margin-bottom:20px;">Clique no botão abaixo para criar uma nova senha. Este link expira em 30 minutos.</p>
      <a href="${link}" style="display:inline-block;background:#E8961A;color:#18160F;font-weight:800;padding:12px 24px;border-radius:9px;text-decoration:none;font-size:14px;">Redefinir senha →</a>
      <p style="font-size:11px;color:#605848;margin-top:24px;">Se você não pediu isso, pode ignorar este e-mail com segurança.</p>
      </div></div>`;
    await enviarEmailGenerico(user.email, '🔑 Redefinir sua senha — Lota', html);
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
    // Se o evento tem o sistema de bar ativo, mostra o saldo/conta em aberto de cada ingresso —
    // assim o comprador acompanha isso sem precisar perguntar pro staff do bar.
    const tickets = (p.tickets || []).map(t => {
      if (ev?.barConfig?.ativo) {
        const conta = calcularContaBar(ev.id, t.codigo);
        return { ...t, barAtivo: true, saldoCashless: conta.saldoCashless, contaAbertaPosPago: conta.contaAbertaPosPago };
      }
      return t;
    });
    return { pedidoId: p.id, eventoId: p.eventoId, eventoNome: ev?.nome || 'Evento', eventoSlug: ev?.slug || '', dataEvento: ev?.dataEvento || null, imagemCapa: ev?.imagemCapa || '', total: p.total, tickets, createdAt: p.createdAt };
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
  let eventos;
  if (req.user.isOrganizador) {
    eventos = EVENTOS.filter(e => e.organizadorId === req.user.id);
  } else {
    // Colaborador puro: vê só os eventos em que foi adicionado especificamente, mais os eventos do
    // produtor a quem ainda está vinculado pelo jeito antigo (compatibilidade com quem já usava isso).
    eventos = EVENTOS.filter(e => (e.colaboradoresIds || []).includes(req.user.id) || (req.user.colaboradorDe && e.organizadorId === req.user.colaboradorDe));
  }
  res.json({ eventos, modoVisualizacao: !req.user.isOrganizador });
});

app.post('/api/eventos', auth, organizadorOnly, (req, res) => {
  const { nome, descricao, dataEvento, horaEvento, local, cidade, categoria, imagemCapa, videoUrl, capacidadeMaxima } = req.body;
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
    // Limite total de ingressos do evento (soma de todos os lotes) — 0 ou vazio significa sem limite.
    capacidadeMaxima: Math.max(0, parseInt(capacidadeMaxima) || 0),
    destaque: false,
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
  if (req.body.capacidadeMaxima !== undefined) {
    const novoLimite = Math.max(0, parseInt(req.body.capacidadeMaxima) || 0);
    const totalAtual = (ev.lotes || []).reduce((s, l) => s + l.qtdTotal, 0);
    if (novoLimite > 0 && totalAtual > novoLimite) {
      return res.status(400).json({ error: `Já existem ${totalAtual} ingressos configurados nos lotes — reduza os lotes antes de diminuir o limite pra ${novoLimite}.` });
    }
    ev.capacidadeMaxima = novoLimite;
  }
  if (req.body.imagemCapa !== undefined) ev.imagemCapa = sanitizeImagem(req.body.imagemCapa);
  if (req.body.bannerLargo !== undefined) ev.bannerLargo = sanitizeImagem(req.body.bannerLargo);
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

app.patch('/api/eventos/:id/publicar', auth, async (req, res) => {
  const ev = eventoDoUsuario(req.params.id, req.user.id);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  const estavaPublicado = ev.status === 'publicado';
  ev.status = req.body.publicar ? 'publicado' : 'rascunho';
  ev.updatedAt = new Date().toISOString();
  // Avisa os seguidores só na primeira vez que o evento é publicado — evita notificar de novo
  // toda vez que o produtor despublica/republica o mesmo evento.
  if (ev.status === 'publicado' && !estavaPublicado && !ev.notificacaoSeguidoresEnviada) {
    ev.notificacaoSeguidoresEnviada = true;
    persistEventos();
    res.json({ evento: ev });
    const proto = req.get('x-forwarded-proto') || 'https';
    const baseUrl = `${proto}://${req.get('host')}`;
    notificarSeguidoresNovoEvento(ev, req.user, baseUrl).catch(e => console.error('Erro ao notificar seguidores:', e.message));
    return;
  }
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
  // Imagem opcional por lote — útil pra vender merchandising (camiseta, produto, etc) junto com o
  // ingresso. Limite de tamanho generoso (~2MB em base64) pra não pesar demais no armazenamento.
  for (const l of req.body.lotes) {
    if (l.imagemUrl && l.imagemUrl.length > 2_800_000) return res.status(400).json({ error: `Imagem do lote "${l.nome || ''}" muito grande. Tente uma imagem menor.` });
  }
  const novosLotes = req.body.lotes.map(l => ({
    id: l.id || uuidv4(), nome: sanitize(l.nome || 'Lote', 60),
    preco: l.cortesia ? 0 : Math.max(0, parseFloat(l.preco) || 0),
    qtdTotal: Math.max(0, parseInt(l.qtdTotal) || 0), vendidos: parseInt(l.vendidos) || 0,
    ativo: l.ativo !== false, cortesia: !!l.cortesia, exclusivoPromoter: !!l.exclusivoPromoter,
    imagemUrl: (l.imagemUrl && l.imagemUrl.startsWith('data:image/')) ? l.imagemUrl : (l.imagemUrl || '')
  }));
  if (ev.capacidadeMaxima > 0) {
    const totalNovo = novosLotes.reduce((s, l) => s + l.qtdTotal, 0);
    if (totalNovo > ev.capacidadeMaxima) {
      return res.status(400).json({ error: `A soma dos lotes (${totalNovo}) ultrapassa o limite máximo de ${ev.capacidadeMaxima} ingressos definido para este evento.` });
    }
  }
  ev.lotes = novosLotes;
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
// Mesmo cálculo, mas restrito a UM evento específico — é o que passou a valer pra pedir
// adiantamento, já que agora a solicitação é feita dentro de cada evento, não mais de forma geral
// somando todos os eventos do produtor de uma vez.
function calcularSaldoEvento(eventoId) {
  const pedidosPagos = PEDIDOS.filter(p => p.eventoId === eventoId && p.status === 'pago');
  const totalVendido = pedidosPagos.reduce((s, p) => s + (p.valorIngressos !== undefined ? p.valorIngressos : (p.total - ((p.taxaAdministrativa !== undefined ? p.taxaAdministrativa : (p.marketplaceFee || 0))))), 0);
  const adiantamentosDoEvento = ADIANTAMENTOS.filter(a => a.eventoId === eventoId);
  const totalJaPago = adiantamentosDoEvento.filter(a => a.status === 'pago').reduce((s, a) => s + a.valor, 0);
  const totalPendente = adiantamentosDoEvento.filter(a => a.status === 'pendente').reduce((s, a) => s + a.valor, 0);
  const saldoDisponivel = Math.max(0, Math.round((totalVendido - totalJaPago - totalPendente) * 100) / 100);
  return { totalVendido: Math.round(totalVendido * 100) / 100, totalJaPago, totalPendente, saldoDisponivel };
}

app.get('/api/produtor/saldo', auth, organizadorOnly, (req, res) => {
  res.json(calcularSaldoProdutor(req.user.id));
});

app.get('/api/produtor/adiantamentos', auth, organizadorOnly, (req, res) => {
  const lista = ADIANTAMENTOS.filter(a => a.produtorId === req.user.id).sort((a, b) => new Date(b.solicitadoEm) - new Date(a.solicitadoEm));
  res.json({ adiantamentos: lista });
});

app.post('/api/produtor/adiantamento', auth, organizadorOnly, (req, res) => {
  // Antecipação só é liberada pra produtores que têm contrato com a gente — precisa ter sido
  // habilitado manualmente pelo admin (aba Produtores). Sem isso, a rota fica bloqueada mesmo pra
  // quem tenta chamar direto pela API.
  if (!req.user.podeAntecipar) return res.status(403).json({ error: 'A antecipação de recebíveis está disponível apenas para produtores com contrato ativo com a Lota. Entre em contato com o suporte pra saber mais.' });
  const ev = eventoDoUsuario(req.body.eventoId, req.user.id);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  const valor = Math.round((parseFloat(req.body.valor) || 0) * 100) / 100;
  if (valor <= 0) return res.status(400).json({ error: 'Informe um valor válido.' });
  if (!req.user.pagamentoInfo?.chavePix) return res.status(400).json({ error: 'Cadastre sua chave PIX no perfil antes de solicitar um adiantamento.' });
  if (!req.user.cpfCnpj) return res.status(400).json({ error: 'Cadastre seu CPF/CNPJ no perfil antes de solicitar um adiantamento.' });
  // A partir de agora, o saldo disponível é calculado só com base nesse evento específico — não
  // soma mais as vendas de todos os eventos do produtor juntas.
  const { saldoDisponivel } = calcularSaldoEvento(ev.id);
  if (valor > saldoDisponivel) return res.status(400).json({ error: `Valor solicitado maior que o saldo disponível deste evento (R$ ${saldoDisponivel.toFixed(2)}).` });
  const agora = new Date();
  const prazoLimite = new Date(agora.getTime() + 2 * 24 * 60 * 60 * 1000); // 2 dias
  const adiantamento = {
    id: uuidv4(), produtorId: req.user.id, eventoId: ev.id, eventoNome: ev.nome, valor,
    chavePix: req.user.pagamentoInfo.chavePix, tipoChavePix: req.user.pagamentoInfo.tipoChavePix,
    nomeTitular: req.user.pagamentoInfo.nomeTitular, cpfCnpj: req.user.cpfCnpj,
    nomeBanco: req.user.pagamentoInfo.nomeBanco || '', numeroAgencia: req.user.pagamentoInfo.numeroAgencia || '', tipoConta: req.user.pagamentoInfo.tipoConta || '',
    status: 'pendente', solicitadoEm: agora.toISOString(), prazoLimite: prazoLimite.toISOString(),
    pagoEm: null, observacoesAdmin: '', comprovanteUrl: ''
  };
  ADIANTAMENTOS.push(adiantamento);
  persistAdiantamentos();
  res.status(201).json({ adiantamento });
});
// Visão de adiantamentos e saldo restrita a UM evento — usada dentro da própria página do evento.
app.get('/api/eventos/:id/saldo', auth, (req, res) => {
  const ev = eventoDoUsuario(req.params.id, req.user.id);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  res.json(calcularSaldoEvento(ev.id));
});
app.get('/api/eventos/:id/adiantamentos', auth, (req, res) => {
  const ev = eventoDoUsuario(req.params.id, req.user.id);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  const lista = ADIANTAMENTOS.filter(a => a.eventoId === ev.id).sort((a, b) => new Date(b.solicitadoEm) - new Date(a.solicitadoEm));
  res.json({ adiantamentos: lista });
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
  const { status, observacoes, comprovanteUrl } = req.body;
  if (!['pago', 'recusado'].includes(status)) return res.status(400).json({ error: 'Status inválido.' });
  if (status === 'pago' && comprovanteUrl) a.comprovanteUrl = sanitizeImagem(comprovanteUrl);
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
  const ev = req.user.isAdmin ? EVENTOS.find(e => e.id === req.params.id) : eventoDoUsuario(req.params.id, req.user.id);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  const pedido = PEDIDOS.find(p => p.id === req.params.pedidoId && p.eventoId === ev.id);
  if (!pedido) return res.status(404).json({ error: 'Pedido não encontrado.' });
  if (pedido.status !== 'pago') return res.status(400).json({ error: 'Somente pedidos pagos podem ser reembolsados.' });

  // Cortesia ou pagamento simulado — não envolve dinheiro real, só cancela localmente
  const semPagamentoReal = pedido.mpPaymentId === 'CORTESIA' || String(pedido.mpPaymentId || '').startsWith('SIMULADO');

  if (!semPagamentoReal) {
    if (pedido.provedorPagamento === 'asaas') {
      if (!ASAAS_API_KEY) return res.status(500).json({ error: 'Asaas não configurado no servidor.' });
      // Se o pagamento foi feito parcelado no cartão, o Asaas trata cada parcela como uma "cobrança"
      // vinculada a um grupo maior (parcelamento) — e recusa estornar uma cobrança individual dentro
      // desse grupo, exigindo o endpoint específico de estorno de PARCELAMENTO em vez do de cobrança
      // avulsa. Por isso, primeiro consultamos o pagamento pra saber se ele pertence a um parcelamento.
      const consultaPagamento = await asaasFetch(`/payments/${pedido.mpPaymentId}`);
      const idParcelamento = consultaPagamento.ok ? consultaPagamento.data.installment : null;
      const endpointEstorno = idParcelamento ? `/installments/${idParcelamento}/refund` : `/payments/${pedido.mpPaymentId}/refund`;
      const estorno = await asaasFetch(endpointEstorno, { method: 'POST' });
      if (!estorno.ok) return res.status(400).json({ error: estorno.data.errors?.[0]?.description || 'Erro ao processar reembolso no Asaas.' });
    } else {
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
  }

  marcarPedidoComoReembolsado(pedido, ev);
  persistPedidos(); persistEventos();
  registrarAuditoria(req.user, 'reembolso_pedido', { pedidoId: pedido.id, eventoId: ev.id, eventoNome: ev.nome, valor: pedido.total, compradorEmail: pedido.comprador?.email });
  res.json({ ok: true, reembolsoReal: !semPagamentoReal });
});

// Atualiza o estado local (relatórios, vagas, cupons, promoters) quando um pedido é reembolsado —
// usada tanto quando reembolsamos pela nossa plataforma quanto quando detectamos, via webhook,
// que o estorno foi feito direto no site do Mercado Pago.
// Libera a reserva de estoque (vagas do lote / assento) de um pedido que NUNCA chegou a ser pago —
// recusado, cancelado ou expirado sem confirmação. Sem isso, ingressos "reservados" por tentativas
// de pagamento que não vingaram ficariam bloqueados pra sempre, mesmo sem ninguém ter pago por eles.
function liberarReservaPedido(pedido, ev) {
  if (!ev || pedido.reservaLiberada) return;
  for (const it of (pedido.itens || [])) {
    if (it.assento) {
      if (ev.assentosOcupados) ev.assentosOcupados = ev.assentosOcupados.filter(a => a !== it.assento);
    } else {
      const lote = ev.lotes.find(l => l.id === it.loteId);
      if (lote) lote.vendidos = Math.max(0, (lote.vendidos || 0) - it.qtd * pessoasPorUnidadeLote(lote.nome));
    }
  }
  pedido.reservaLiberada = true;
  persistEventos();
}

function marcarPedidoComoReembolsado(pedido, ev) {
  pedido.status = 'reembolsado';
  pedido.reembolsadoEm = new Date().toISOString();
  (pedido.tickets || []).forEach(t => { t.cancelado = true; });
  const qtdTotal = (pedido.itens || []).reduce((s, it) => s + it.qtd, 0);
  for (const it of (pedido.itens || [])) {
    const lote = ev.lotes.find(l => l.id === it.loteId);
    if (lote) lote.vendidos = Math.max(0, (lote.vendidos || 0) - it.qtd * pessoasPorUnidadeLote(lote.nome));
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
}

// Sincroniza manualmente o status de um pedido específico com o Mercado Pago — útil quando um
// estorno (ou outra mudança) foi feito direto no site/app deles, e nosso relatório ficou desatualizado.
app.post('/api/eventos/:id/pedidos/:pedidoId/sincronizar', auth, async (req, res) => {
  const ev = req.user.isAdmin ? EVENTOS.find(e => e.id === req.params.id) : eventoDoUsuario(req.params.id, req.user.id);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  const pedido = PEDIDOS.find(p => p.id === req.params.pedidoId && p.eventoId === ev.id);
  if (!pedido) return res.status(404).json({ error: 'Pedido não encontrado.' });
  if (!pedido.mpPaymentId || pedido.mpPaymentId === 'CORTESIA' || String(pedido.mpPaymentId).startsWith('SIMULADO')) {
    return res.status(400).json({ error: 'Esse pedido não tem um pagamento real pra sincronizar.' });
  }
  try {
    if (pedido.provedorPagamento === 'asaas') {
      if (!ASAAS_API_KEY) return res.status(500).json({ error: 'Asaas não configurado no servidor.' });
      if (pedido.status === 'pago') {
        // Nesse ponto, mpPaymentId já foi resolvido pro ID do pagamento real (não do checkout) —
        // consultamos ele diretamente pra ver se foi estornado.
        const consultaPagamento = await asaasFetch(`/payments/${pedido.mpPaymentId}`);
        if (!consultaPagamento.ok) return res.status(400).json({ error: 'Erro ao consultar o pagamento no Asaas.' });
        if (['REFUNDED', 'CHARGEBACK_REQUESTED'].includes(consultaPagamento.data.status)) {
          marcarPedidoComoReembolsado(pedido, ev);
          persistPedidos(); persistEventos();
          return res.json({ ok: true, atualizado: true, novoStatus: 'reembolsado' });
        }
        return res.json({ ok: true, atualizado: false, statusMercadoPago: consultaPagamento.data.status, statusAtual: pedido.status });
      }
      // Pedido ainda pendente — mpPaymentId aqui é o ID do CHECKOUT. O status do próprio Checkout é
      // o sinal mais confiável (descobrimos que o filtro "checkoutSession" às vezes não retorna
      // resultado mesmo com o pagamento já confirmado do lado do Asaas).
      const consultaCheckout = await asaasFetch(`/checkouts/${pedido.mpPaymentId}`);
      if (consultaCheckout.ok && consultaCheckout.data.status === 'PAID') {
        const proto = req.get('x-forwarded-proto') || 'https';
        await processarPagamentoAprovado(pedido, pedido.mpPaymentId, `${proto}://${req.get('host')}`);
        return res.json({ ok: true, atualizado: true, novoStatus: 'pago' });
      }
      if (consultaCheckout.ok && ['CANCELED', 'EXPIRED'].includes(consultaCheckout.data.status)) {
        return res.json({ ok: true, atualizado: false, statusMercadoPago: consultaCheckout.data.status, statusAtual: pedido.status });
      }
      // Reforço: tenta também pelo filtro antigo, caso o Checkout já não exista mais como registro ativo
      const buscaPagamento = await asaasFetch(`/payments?checkoutSession=${pedido.mpPaymentId}`);
      const pagamentoReal = (buscaPagamento.ok && buscaPagamento.data.data && buscaPagamento.data.data[0]) || null;
      if (pagamentoReal && ['CONFIRMED', 'RECEIVED'].includes(pagamentoReal.status)) {
        const proto = req.get('x-forwarded-proto') || 'https';
        await processarPagamentoAprovado(pedido, pedido.mpPaymentId, `${proto}://${req.get('host')}`);
        return res.json({ ok: true, atualizado: true, novoStatus: 'pago' });
      }
      return res.json({ ok: true, atualizado: false, statusMercadoPago: pagamentoReal?.status || consultaCheckout.data?.status || 'sem pagamento ainda', statusAtual: pedido.status });
    }

    if (!MP_PLATFORM_TOKEN) return res.status(500).json({ error: 'Mercado Pago não configurado no servidor.' });
    const payResp = await fetch(`${MP_API}/v1/payments/${pedido.mpPaymentId}`, { headers: { 'Authorization': `Bearer ${MP_PLATFORM_TOKEN}` } });
    const payment = await payResp.json();
    if (!payResp.ok) return res.status(400).json({ error: 'Erro ao consultar o pagamento no Mercado Pago.' });

    if (['refunded','charged_back'].includes(payment.status) && pedido.status === 'pago') {
      marcarPedidoComoReembolsado(pedido, ev);
      persistPedidos(); persistEventos();
      return res.json({ ok: true, atualizado: true, novoStatus: 'reembolsado' });
    }
    if (payment.status === 'approved' && pedido.status !== 'pago') {
      const proto = req.get('x-forwarded-proto') || 'https';
      await processarPagamentoAprovado(pedido, payment.id, `${proto}://${req.get('host')}`);
      return res.json({ ok: true, atualizado: true, novoStatus: 'pago' });
    }
    res.json({ ok: true, atualizado: false, statusMercadoPago: payment.status, statusAtual: pedido.status });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/eventos/:id/relatorio', auth, (req, res) => {
  const ev = eventoVisivelPara(req.params.id, req.user);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  const todosPedidosPagos = PEDIDOS.filter(p => p.eventoId === ev.id && p.status === 'pago');

  // ── Filtro de período (Geral / Últimos 30 dias / Hoje / Ontem / Personalizado) — afeta só os
  // números-resumo abaixo. O bloco "Vendas por Período" (hoje/7d/30d) e o gráfico diário continuam
  // sempre olhando pra tudo, sem esse filtro — como foi pedido pra manter aquele bloco congelado.
  const periodo = req.query.periodo || 'geral';
  const agora = new Date();
  let inicioFiltro = null, fimFiltro = null;
  if (periodo === '30dias') { inicioFiltro = new Date(agora.getTime() - 30 * 24 * 60 * 60 * 1000); }
  else if (periodo === 'hoje') { inicioFiltro = new Date(agora); inicioFiltro.setHours(0, 0, 0, 0); }
  else if (periodo === 'ontem') {
    inicioFiltro = new Date(agora); inicioFiltro.setDate(inicioFiltro.getDate() - 1); inicioFiltro.setHours(0, 0, 0, 0);
    fimFiltro = new Date(agora); fimFiltro.setHours(0, 0, 0, 0);
  }
  if (periodo === 'personalizado') {
    if (req.query.dataInicio) inicioFiltro = new Date(req.query.dataInicio + 'T00:00:00');
    if (req.query.dataFim) fimFiltro = new Date(req.query.dataFim + 'T23:59:59');
  }
  const pedidos = todosPedidosPagos.filter(p => {
    const dataP = new Date(p.pagoEm || p.createdAt);
    if (inicioFiltro && dataP < inicioFiltro) return false;
    if (fimFiltro && dataP >= fimFiltro) return false;
    return true;
  });

  // Usamos valorIngressos (não total) — é o valor líquido que o produtor recebe, sem a taxa
  // administrativa que é cobrada à parte do comprador e fica com a plataforma.
  const totalReceita = pedidos.reduce((s,p) => s + (p.valorIngressos !== undefined ? p.valorIngressos : p.total), 0);
  const totalIngressos = pedidos.reduce((s,p) => s + (p.tickets||[]).length, 0);
  // Bug corrigido: antes, a quantidade vinha de "lote.vendidos" (contagem acumulada DESDE SEMPRE,
  // nunca filtrada), enquanto a receita já vinha corretamente filtrada pelo período escolhido —
  // por isso o valor batia mas a quantidade não, exceto quando o filtro era "Geral". Agora as duas
  // vêm da MESMA fonte (os pedidos já filtrados pelo período).
  const porLote = {};
  ev.lotes.forEach(l => { porLote[l.nome] = { vendidos: 0, receita: 0 }; });
  pedidos.forEach(p => (p.itens||[]).forEach(it => {
    const lote = ev.lotes.find(l => l.id === it.loteId);
    if (lote && porLote[lote.nome]) { porLote[lote.nome].receita += (it.precoUnit || 0) * (it.qtd || 0); porLote[lote.nome].vendidos += (it.qtd || 0); }
  }));
  const porPromoter = ev.promoters.map(pr => ({ nome: pr.nome, vendas: pr.vendas || 0, receita: pr.receita || 0 }));
  const porCupom = ev.cupons.map(c => ({ codigo: c.codigo, usos: c.usosAtuais }));

  // Ticket médio — por ingresso individual, e por pedido (que pode ter vários ingressos)
  const ticketMedioIngresso = totalIngressos > 0 ? totalReceita / totalIngressos : 0;
  const ticketMedioPedido = pedidos.length > 0 ? totalReceita / pedidos.length : 0;

  // Ingressos vendidos vs limite do evento — aqui conta TUDO (pago + cortesia), já que capacidade
  // é sobre lugares ocupados, não sobre receita.
  const capacidadeMaxima = ev.capacidadeMaxima || 0;
  // Contamos os ingressos de verdade (direto dos pedidos pagos), em vez de confiar no contador
  // "lote.vendidos" — esse contador é atualizado em vários pontos diferentes do sistema (reserva,
  // liberação, recuperação manual, bar) e pode ter ficado dessincronizado da realidade ao longo do
  // tempo. Contar direto dos ingressos gerados é a fonte da verdade mais confiável.
  const totalVendidoGeral = todosPedidosPagos.reduce((s, p) => s + (p.tickets || []).length, 0);
  const capacidade = { vendidos: totalVendidoGeral, limite: capacidadeMaxima, percentual: capacidadeMaxima > 0 ? Math.round((totalVendidoGeral / capacidadeMaxima) * 1000) / 10 : null };
  // Só ingressos PAGOS (sem cortesia) — usado na tendência/média de VENDAS especificamente, pra não
  // inflar a média com ingressos que não geraram receita nenhuma.
  const totalVendidoPago = todosPedidosPagos.reduce((s, p) => s + (p.itens || []).filter(it => !ev.lotes.find(l => l.id === it.loteId)?.cortesia).reduce((s2, it) => s2 + (it.qtd || 0), 0), 0);

  // Online vs física vs cortesia — hoje a Lota só vende online, então "física" fica sempre 0%
  // (mantido aqui já preparado pra quando/se um dia existir venda presencial).
  let ingressosCortesia = 0, ingressosPagos = 0;
  pedidos.forEach(p => (p.itens || []).forEach(it => {
    const lote = ev.lotes.find(l => l.id === it.loteId);
    if (lote?.cortesia) ingressosCortesia += it.qtd; else ingressosPagos += it.qtd;
  }));
  const totalParaPercentual = ingressosCortesia + ingressosPagos;
  const origemVendas = {
    online: totalParaPercentual > 0 ? Math.round((ingressosPagos / totalParaPercentual) * 1000) / 10 : 0,
    fisica: 0,
    cortesia: totalParaPercentual > 0 ? Math.round((ingressosCortesia / totalParaPercentual) * 1000) / 10 : 0
  };

  // Por tipo de ingresso — categoriza pelo nome do lote (não temos um campo estruturado de tipo,
  // então usamos palavras-chave comuns; o que não bater com nenhuma vai pra "Outro").
  const categorias = [
    { chave: 'meia', termos: ['meia'] }, { chave: 'inteira', termos: ['inteira', 'inteiro'] },
    { chave: 'solidaria', termos: ['solidári', 'solidari'] }, { chave: 'duplo', termos: ['duplo', 'dupla'] },
    { chave: 'quadruplo', termos: ['quádruplo', 'quadruplo', 'quadrupla'] }
  ];
  const porTipoMap = {};
  pedidos.forEach(p => (p.itens || []).forEach(it => {
    const lote = ev.lotes.find(l => l.id === it.loteId);
    const nomeL = (lote?.nome || '').toLowerCase();
    const cat = categorias.find(c => c.termos.some(t => nomeL.includes(t)));
    const chave = cat ? cat.chave : 'outro';
    porTipoMap[chave] = (porTipoMap[chave] || 0) + it.qtd;
  }));
  const totalTipo = Object.values(porTipoMap).reduce((s, v) => s + v, 0);
  const porTipoIngresso = Object.entries(porTipoMap).map(([tipo, qtd]) => ({ tipo, qtd, percentual: totalTipo > 0 ? Math.round((qtd / totalTipo) * 1000) / 10 : 0 })).sort((a, b) => b.qtd - a.qtd);

  // ── Bloco congelado: vendas por período (hoje/7d/30d) e vendas por dia — sempre olhando pra
  // TODOS os pedidos pagos, sem aplicar o filtro de período escolhido acima.
  const inicioHoje = new Date(); inicioHoje.setHours(0,0,0,0);
  const limite7dias = agora.getTime() - 7 * 24 * 60 * 60 * 1000;
  const limite30dias = agora.getTime() - 30 * 24 * 60 * 60 * 1000;
  const janela = (limiteMs) => todosPedidosPagos.reduce((acc, p) => {
    const dataPedido = new Date(p.pagoEm || p.createdAt).getTime();
    if (dataPedido >= limiteMs) { acc.ingressos += (p.tickets || []).length; acc.receita += (p.valorIngressos !== undefined ? p.valorIngressos : p.total); }
    return acc;
  }, { ingressos: 0, receita: 0 });
  const vendasPorPeriodo = { hoje: janela(inicioHoje.getTime()), ultimos7dias: janela(limite7dias), ultimos30dias: janela(limite30dias) };

  const porDiaMap = {};
  todosPedidosPagos.forEach(p => { const d = p.pagoEm ? p.pagoEm.slice(0,10) : p.createdAt.slice(0,10); if (!porDiaMap[d]) porDiaMap[d] = { qtd: 0, receita: 0 }; porDiaMap[d].qtd += (p.tickets||[]).length; porDiaMap[d].receita += (p.valorIngressos !== undefined ? p.valorIngressos : p.total); });
  const NOMES_DIA_SEMANA = ['dom', 'seg', 'ter', 'qua', 'qui', 'sex', 'sáb'];
  const diasOrdenados = Object.keys(porDiaMap).sort();
  const porDia = diasOrdenados.map(dia => ({ dia, diaSemana: NOMES_DIA_SEMANA[new Date(dia + 'T12:00:00').getDay()], qtd: porDiaMap[dia].qtd, receita: Math.round(porDiaMap[dia].receita * 100) / 100 }));

  // Percentual de vendas por dia da semana (agregando TODOS os dias do mesmo tipo — ex: soma de
  // todas as segundas-feiras) — ajuda a ver quais dias da semana vendem mais, não dia a dia.
  const porDiaSemanaMap = { dom: 0, seg: 0, ter: 0, qua: 0, qui: 0, sex: 0, sáb: 0 };
  todosPedidosPagos.forEach(p => {
    const dataP = new Date((p.pagoEm || p.createdAt).slice(0, 10) + 'T12:00:00');
    porDiaSemanaMap[NOMES_DIA_SEMANA[dataP.getDay()]] += (p.tickets || []).length;
  });
  const totalPorDiaSemana = Object.values(porDiaSemanaMap).reduce((s, v) => s + v, 0);
  const porDiaSemana = ['seg','ter','qua','qui','sex','sáb','dom'].map(dia => ({ dia, qtd: porDiaSemanaMap[dia], percentual: totalPorDiaSemana > 0 ? Math.round((porDiaSemanaMap[dia] / totalPorDiaSemana) * 1000) / 10 : 0 }));

  // Tendência simples — projeção linear baseada na média diária de VENDAS PAGAS (sem contar
  // cortesias, senão a média fica inflada com ingressos que não geraram receita) até agora, e nos
  // dias que faltam pro evento. NÃO é um modelo preditivo sofisticado (não considera sazonalidade,
  // picos de divulgação, etc), é só uma estimativa direta: "se continuar vendendo nesse ritmo".
  let tendencia = null;
  if (ev.dataEvento && diasOrdenados.length >= 2) {
    const dataEventoObj = new Date(ev.dataEvento + 'T23:59:59');
    const diasRestantes = Math.max(0, Math.ceil((dataEventoObj - agora) / (24 * 60 * 60 * 1000)));
    const primeiroDia = new Date(diasOrdenados[0]);
    const diasDeVendaDecorridos = Math.max(1, Math.ceil((agora - primeiroDia) / (24 * 60 * 60 * 1000)));
    const mediaIngressosDia = totalVendidoPago / diasDeVendaDecorridos;
    const projecaoIngressos = Math.round(totalVendidoGeral + mediaIngressosDia * diasRestantes);
    tendencia = {
      mediaIngressosPorDia: Math.round(mediaIngressosDia * 10) / 10, diasRestantes,
      projecaoIngressosNoEvento: capacidadeMaxima > 0 ? Math.min(projecaoIngressos, capacidadeMaxima) : projecaoIngressos,
      atingeCapacidade: capacidadeMaxima > 0 && projecaoIngressos >= capacidadeMaxima
    };
  }

  // Visualizações da página e taxa de conversão (visualização → pedido pago) — não temos rastreio
  // de visitante único, então essa taxa é sobre o total de visualizações, não pessoas distintas.
  const visualizacoes = ev.visualizacoes || 0;
  // Taxa de conversão: visualizações da página ÷ ingressos vendidos — mostra quantas visualizações
  // em média "custam" um ingresso vendido (quanto menor, melhor a conversão).
  const taxaConversao = totalVendidoGeral > 0 ? Math.round((visualizacoes / totalVendidoGeral) * 10) / 10 : null;

  res.json({
    periodo, totalReceita, totalIngressos, totalPedidos: pedidos.length, porLote, porDia, porPromoter, porCupom, vendasPorPeriodo,
    ticketMedioIngresso: Math.round(ticketMedioIngresso * 100) / 100, ticketMedioPedido: Math.round(ticketMedioPedido * 100) / 100,
    capacidade, origemVendas, porTipoIngresso, tendencia,
    visualizacoes, taxaConversao, porDiaSemana
  });
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
  const linhas = [
    ['BORDERÔ DE VENDAS — ' + ev.nome],
    ['Data de emissão', new Date().toLocaleString('pt-BR')],
    [''],
    ['Pedido','Comprador','E-mail','Itens','Valor Recebido (R$)','Status','Data']
  ];
  let totalRecebido = 0;
  pedidos.forEach(p => {
    const liquido = p.valorIngressos !== undefined ? p.valorIngressos : (p.total - (p.taxaAdministrativa || 0));
    totalRecebido += liquido;
    linhas.push([p.id.slice(0,8), p.comprador?.nome||'', p.comprador?.email||'', (p.tickets||[]).length, liquido.toFixed(2).replace('.',','), p.status, new Date(p.createdAt).toLocaleDateString('pt-BR')]);
  });
  linhas.push(['']);
  linhas.push(['TOTAL', '', '', '', totalRecebido.toFixed(2).replace('.',','), '', '']);
  const csv = linhas.map(r => r.map(v => '"'+String(v).replace(/"/g,'""')+'"').join(';')).join('\r\n');
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="bordero-${ev.slug}.csv"`);
  res.send('\uFEFF' + csv);
});

app.get('/api/eventos/:id/bordero.pdf', auth, async (req, res) => {
  const ev = eventoVisivelPara(req.params.id, req.user);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  const pedidos = PEDIDOS.filter(p => p.eventoId === ev.id && p.status === 'pago');
  try {
    const pdfBuffer = await gerarPdfBordero(ev, pedidos);
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `inline; filename="bordero-${ev.slug}.pdf"`);
    res.send(pdfBuffer);
  } catch (e) { res.status(500).json({ error: 'Erro ao gerar o borderô em PDF.' }); }
});

async function gerarPdfBordero(ev, pedidos) {
  const doc = new PDFDocument({ size: 'A4', margin: 0 });
  const chunks = [];
  doc.on('data', c => chunks.push(c));
  const done = new Promise((resolve, reject) => { doc.on('end', () => resolve(Buffer.concat(chunks))); doc.on('error', reject); });

  const PAGE_W = doc.page.width;
  const MARGIN = 40;
  const CONTENT_W = PAGE_W - MARGIN * 2;
  const LARANJA = '#C47B14';
  const ESCURO = '#18160F';
  const CINZA = '#555555';
  const CINZA_CLARO = '#8A8378';
  const BORDA = '#E4DDD1';
  const VERDE = '#16A34A';

  doc.rect(0, 0, PAGE_W, 80).fill(ESCURO);
  try {
    const logoPath = path.join(PUBLIC_DIR, 'logo.png');
    if (fs.existsSync(logoPath)) doc.image(logoPath, MARGIN, 14, { height: 36 });
  } catch (e) { console.error('Erro ao carregar logo no PDF:', e.message); }
  doc.fillColor('#FFFFFF').fontSize(19).font('Helvetica-Bold').text('LOTA', MARGIN + 44, 24);
  doc.fontSize(11).font('Helvetica').text('Borderô de Vendas', MARGIN + 44, 50);

  let y = 100;
  doc.fillColor(ESCURO).fontSize(17).font('Helvetica-Bold').text(ev.nome, MARGIN, y, { width: CONTENT_W });
  y = doc.y + 8;
  const dataStr = ev.dataEvento ? parseDataLocal(ev.dataEvento).toLocaleDateString('pt-BR', { day: '2-digit', month: 'long', year: 'numeric' }) : '';
  doc.fillColor(CINZA).fontSize(10).font('Helvetica').text(`Local: ${ev.local || '—'}${ev.cidade ? ' — ' + ev.cidade : ''}`, MARGIN, y);
  y = doc.y + 3;
  doc.text(`Data do evento: ${dataStr}${ev.horaEvento ? ' às ' + ev.horaEvento : ''}`, MARGIN, y);
  y = doc.y + 3;
  doc.fillColor(CINZA_CLARO).fontSize(9).text(`Emitido em: ${new Date().toLocaleString('pt-BR')}`, MARGIN, y);
  y = doc.y + 18;

  doc.moveTo(MARGIN, y).lineTo(PAGE_W - MARGIN, y).lineWidth(1).strokeColor(BORDA).stroke();
  y += 20;

  doc.fillColor(ESCURO).fontSize(12).font('Helvetica-Bold').text('Resumo por Lote', MARGIN, y);
  y = doc.y + 12;

  const porLote = {};
  pedidos.forEach(p => (p.itens || []).forEach(it => {
    if (!porLote[it.loteNome]) porLote[it.loteNome] = { qtd: 0, precoUnit: it.precoUnit, valorTotal: 0 };
    porLote[it.loteNome].qtd += it.qtd;
    porLote[it.loteNome].valorTotal += it.precoUnit * it.qtd;
  }));

  const colX = [MARGIN, MARGIN + 220, MARGIN + 320, MARGIN + 420];
  doc.fontSize(9).font('Helvetica-Bold').fillColor(CINZA_CLARO);
  doc.text('LOTE', colX[0], y);
  doc.text('QTD. VENDIDA', colX[1], y);
  doc.text('PREÇO UNIT.', colX[2], y);
  doc.text('VALOR TOTAL', colX[3], y);
  y += 16;
  doc.moveTo(MARGIN, y).lineTo(PAGE_W - MARGIN, y).lineWidth(0.75).strokeColor(BORDA).stroke();
  y += 8;

  let totalBrutoIngressos = 0, totalQtd = 0;
  Object.entries(porLote).forEach(([nome, d]) => {
    doc.fontSize(10).font('Helvetica').fillColor(ESCURO);
    doc.text(nome, colX[0], y, { width: 210 });
    doc.text(String(d.qtd), colX[1], y);
    doc.text('R$ ' + d.precoUnit.toFixed(2).replace('.', ','), colX[2], y);
    doc.text('R$ ' + d.valorTotal.toFixed(2).replace('.', ','), colX[3], y);
    totalBrutoIngressos += d.valorTotal; totalQtd += d.qtd;
    y += 20;
  });
  y += 4;
  doc.moveTo(MARGIN, y).lineTo(PAGE_W - MARGIN, y).lineWidth(1).strokeColor(BORDA).stroke();
  y += 10;
  doc.fontSize(10).font('Helvetica-Bold').fillColor(ESCURO);
  doc.text('Total Bruto', colX[0], y);
  doc.text(String(totalQtd), colX[1], y);
  doc.text('', colX[2], y);
  doc.text('R$ ' + totalBrutoIngressos.toFixed(2).replace('.', ','), colX[3], y);
  y += 34;

  doc.moveTo(MARGIN, y).lineTo(PAGE_W - MARGIN, y).lineWidth(1).strokeColor(BORDA).stroke();
  y += 20;
  doc.fillColor(ESCURO).fontSize(12).font('Helvetica-Bold').text('Resumo Financeiro', MARGIN, y);
  y = doc.y + 14;

  const totalDesconto = pedidos.reduce((s, p) => s + (p.desconto || 0), 0);
  const totalLiquido = pedidos.reduce((s, p) => s + (p.valorIngressos !== undefined ? p.valorIngressos : p.total), 0);

  const linhaFinanceira = (label, valor, opts = {}) => {
    doc.fontSize(10.5).font(opts.bold ? 'Helvetica-Bold' : 'Helvetica').fillColor(opts.cor || ESCURO);
    doc.text(label, MARGIN, y, { continued: false, width: 320 });
    doc.text((opts.negativo ? '- ' : '') + 'R$ ' + Math.abs(valor).toFixed(2).replace('.', ','), MARGIN + 320, y, { width: CONTENT_W - 320, align: 'right' });
    y += 20;
  };

  linhaFinanceira('Valor total vendido em ingressos', totalBrutoIngressos);
  if (totalDesconto > 0) linhaFinanceira('Descontos aplicados (cupons)', totalDesconto, { negativo: true, cor: CINZA });
  y += 8;
  doc.moveTo(MARGIN, y).lineTo(PAGE_W - MARGIN, y).lineWidth(1).strokeColor(LARANJA).stroke();
  y += 14;
  linhaFinanceira('Valor recebido', totalLiquido, { bold: true, cor: VERDE });

  doc.end();
  return done;
}

// ── CHECK-IN ──
// ════════════════════════════════════════════════════════
// SISTEMA DE BAR (comanda cashless usando o QR Code do próprio ingresso)
// ════════════════════════════════════════════════════════
function calcularContaBar(eventoId, codigo) {
  const registros = CONSUMOS_BAR.filter(c => c.eventoId === eventoId && c.ticketCodigo === codigo);
  const saldoCashless = registros.reduce((s, c) => {
    // Recargas feitas online (PIX) começam como "pendente" até o pagamento confirmar — só contam
    // pro saldo depois de confirmadas. Recargas feitas na hora pelo staff (dinheiro/cartão físico)
    // não têm esse campo, então já contam de cara.
    if (c.tipo === 'recarga' && c.status !== 'pendente') return s + c.valor;
    if (c.tipo === 'consumo' && c.modo === 'pre-pago') return s - c.valor;
    if (c.tipo === 'estorno') return s + c.valor;
    return s;
  }, 0);
  const contaAbertaPosPago = registros.filter(c => c.tipo === 'consumo' && c.modo === 'pos-pago' && c.status === 'em_aberto').reduce((s, c) => s + c.valor, 0);
  return { saldoCashless: Math.round(saldoCashless * 100) / 100, contaAbertaPosPago: Math.round(contaAbertaPosPago * 100) / 100, historico: registros.slice().reverse() };
}
function encontrarTicketPorCodigo(eventoId, codigo) {
  const pedidos = PEDIDOS.filter(p => p.eventoId === eventoId);
  for (const p of pedidos) { const t = (p.tickets || []).find(tk => tk.codigo === sanitize(codigo, 40)); if (t) return { ticket: t, pedido: p }; }
  return null;
}

app.get('/api/eventos/:id/bar-config', auth, (req, res) => {
  const ev = eventoVisivelPara(req.params.id, req.user);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  res.json({ barConfig: ev.barConfig || { ativo: false, modo: 'ambos', produtos: [] } });
});
app.patch('/api/eventos/:id/bar-config', auth, (req, res) => {
  const ev = eventoDoUsuario(req.params.id, req.user.id);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  const { ativo, modo, produtos } = req.body;
  if (!ev.barConfig) ev.barConfig = { ativo: false, modo: 'ambos', produtos: [] };
  if (ativo !== undefined) ev.barConfig.ativo = !!ativo;
  if (modo !== undefined && ['pre-pago', 'pos-pago', 'ambos'].includes(modo)) ev.barConfig.modo = modo;
  if (Array.isArray(produtos)) {
    ev.barConfig.produtos = produtos.map(p => ({
      id: p.id || uuidv4(), nome: sanitize(p.nome || 'Item', 60),
      preco: Math.max(0, parseFloat(p.preco) || 0), categoria: sanitize(p.categoria || 'Bebidas', 40),
      ativo: p.ativo !== false
    }));
  }
  persistEventos();
  res.json({ ok: true, barConfig: ev.barConfig });
});

// Consulta uma comanda pelo código do ingresso (QR Code) — quem opera precisa ser dono do evento
// ou colaborador dele.
app.get('/api/bar/:eventoId/ticket/:codigo', auth, (req, res) => {
  const ev = eventoVisivelPara(req.params.eventoId, req.user);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  const encontrado = encontrarTicketPorCodigo(req.params.eventoId, req.params.codigo);
  if (!encontrado) return res.status(404).json({ error: 'Ingresso não encontrado neste evento.' });
  const { ticket, pedido } = encontrado;
  if (ticket.cancelado) return res.status(400).json({ error: 'Este ingresso foi cancelado.' });
  const conta = calcularContaBar(req.params.eventoId, ticket.codigo);
  res.json({
    titular: ticket.titularNome || pedido.comprador?.nome, codigo: ticket.codigo,
    loteNome: ticket.loteNome, ...conta
  });
});

app.post('/api/bar/:eventoId/ticket/:codigo/recarga', auth, (req, res) => {
  const ev = eventoVisivelPara(req.params.eventoId, req.user);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  const encontrado = encontrarTicketPorCodigo(req.params.eventoId, req.params.codigo);
  if (!encontrado) return res.status(404).json({ error: 'Ingresso não encontrado.' });
  const valor = Math.round((parseFloat(req.body.valor) || 0) * 100) / 100;
  if (valor <= 0) return res.status(400).json({ error: 'Informe um valor válido.' });
  const formaPagamento = sanitize(req.body.formaPagamento || 'dinheiro', 20);
  CONSUMOS_BAR.push({
    id: uuidv4(), eventoId: req.params.eventoId, ticketCodigo: encontrado.ticket.codigo,
    tipo: 'recarga', valor, formaPagamento, operadorNome: req.user.nome,
    createdAt: new Date().toISOString()
  });
  persistConsumosBar();
  res.json({ ok: true, ...calcularContaBar(req.params.eventoId, encontrado.ticket.codigo) });
});

app.post('/api/bar/:eventoId/ticket/:codigo/consumo', auth, (req, res) => {
  const ev = eventoVisivelPara(req.params.eventoId, req.user);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  const encontrado = encontrarTicketPorCodigo(req.params.eventoId, req.params.codigo);
  if (!encontrado) return res.status(404).json({ error: 'Ingresso não encontrado.' });
  const { itens, modo } = req.body;
  if (!Array.isArray(itens) || !itens.length) return res.status(400).json({ error: 'Selecione ao menos um item.' });
  if (!['pre-pago', 'pos-pago'].includes(modo)) return res.status(400).json({ error: 'Modo inválido.' });
  const barConfig = ev.barConfig || { produtos: [] };
  const itensDetalhados = [];
  let total = 0;
  for (const it of itens) {
    const produto = barConfig.produtos.find(p => p.id === it.produtoId);
    if (!produto) return res.status(400).json({ error: 'Produto não encontrado no cardápio.' });
    const qtd = Math.max(1, parseInt(it.qtd) || 1);
    itensDetalhados.push({ produtoId: produto.id, nome: produto.nome, qtd, precoUnit: produto.preco });
    total += produto.preco * qtd;
  }
  total = Math.round(total * 100) / 100;
  if (modo === 'pre-pago') {
    const { saldoCashless } = calcularContaBar(req.params.eventoId, encontrado.ticket.codigo);
    if (total > saldoCashless) return res.status(400).json({ error: `Saldo insuficiente. Saldo atual: R$ ${saldoCashless.toFixed(2)}.` });
  }
  CONSUMOS_BAR.push({
    id: uuidv4(), eventoId: req.params.eventoId, ticketCodigo: encontrado.ticket.codigo,
    tipo: 'consumo', itens: itensDetalhados, valor: total, modo,
    status: modo === 'pre-pago' ? 'pago' : 'em_aberto',
    operadorNome: req.user.nome, createdAt: new Date().toISOString()
  });
  persistConsumosBar();
  res.json({ ok: true, ...calcularContaBar(req.params.eventoId, encontrado.ticket.codigo) });
});

// Fecha a conta em aberto (pós-pago) — o pagamento em si (dinheiro/cartão/PIX na maquininha) é
// feito fora do sistema, aqui só registramos que foi quitado, pra sair da lista de contas abertas.
app.post('/api/bar/:eventoId/ticket/:codigo/fechar-conta', auth, (req, res) => {
  const ev = eventoVisivelPara(req.params.eventoId, req.user);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  const registrosAbertos = CONSUMOS_BAR.filter(c => c.eventoId === req.params.eventoId && c.ticketCodigo === req.params.codigo && c.tipo === 'consumo' && c.modo === 'pos-pago' && c.status === 'em_aberto');
  if (!registrosAbertos.length) return res.status(400).json({ error: 'Não há conta em aberto pra esse ingresso.' });
  const formaPagamento = sanitize(req.body.formaPagamento || 'dinheiro', 20);
  registrosAbertos.forEach(c => { c.status = 'pago'; c.formaPagamentoFechamento = formaPagamento; c.fechadoEm = new Date().toISOString(); });
  persistConsumosBar();
  res.json({ ok: true, ...calcularContaBar(req.params.eventoId, req.params.codigo) });
});

app.get('/api/eventos/:id/bar-relatorio', auth, (req, res) => {
  const ev = eventoVisivelPara(req.params.id, req.user);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  const registros = CONSUMOS_BAR.filter(c => c.eventoId === req.params.id);
  const consumos = registros.filter(c => c.tipo === 'consumo');
  const recargas = registros.filter(c => c.tipo === 'recarga');
  const totalVendidoBar = consumos.reduce((s, c) => s + c.valor, 0);
  const totalRecarregado = recargas.reduce((s, c) => s + c.valor, 0);
  const totalEmAberto = consumos.filter(c => c.status === 'em_aberto').reduce((s, c) => s + c.valor, 0);
  const porProdutoMap = {};
  consumos.forEach(c => (c.itens || []).forEach(it => {
    if (!porProdutoMap[it.nome]) porProdutoMap[it.nome] = { qtd: 0, valor: 0 };
    porProdutoMap[it.nome].qtd += it.qtd;
    porProdutoMap[it.nome].valor += it.precoUnit * it.qtd;
  }));
  const porProduto = Object.entries(porProdutoMap).map(([nome, d]) => ({ nome, ...d })).sort((a, b) => b.valor - a.valor);
  // Por operador — quem processou quanto, útil pra conferência de caixa ao final do turno
  const porOperadorMap = {};
  registros.forEach(c => {
    const nome = c.operadorNome || 'Desconhecido';
    if (!porOperadorMap[nome]) porOperadorMap[nome] = { consumos: 0, valorConsumos: 0, recargas: 0, valorRecargas: 0 };
    if (c.tipo === 'consumo') { porOperadorMap[nome].consumos++; porOperadorMap[nome].valorConsumos += c.valor; }
    if (c.tipo === 'recarga' && c.status !== 'pendente') { porOperadorMap[nome].recargas++; porOperadorMap[nome].valorRecargas += c.valor; }
  });
  const porOperador = Object.entries(porOperadorMap).map(([nome, d]) => ({
    nome, consumos: d.consumos, valorConsumos: Math.round(d.valorConsumos * 100) / 100,
    recargas: d.recargas, valorRecargas: Math.round(d.valorRecargas * 100) / 100,
    totalMovimentado: Math.round((d.valorConsumos + d.valorRecargas) * 100) / 100
  })).sort((a, b) => b.totalMovimentado - a.totalMovimentado);
  res.json({ totalVendidoBar: Math.round(totalVendidoBar * 100) / 100, totalRecarregado: Math.round(totalRecarregado * 100) / 100, totalEmAberto: Math.round(totalEmAberto * 100) / 100, totalConsumos: consumos.length, porProduto, porOperador });
});

// ── Recarga online (PIX) — o próprio comprador carrega saldo antes do evento, direto de "Meus
// Ingressos". Usa o mesmo provedor de pagamento configurado na plataforma (Mercado Pago ou Asaas).
app.post('/api/public/bar/:eventoId/ticket/:codigo/recarga-pix', auth, async (req, res) => {
  const ev = EVENTOS.find(e => e.id === req.params.eventoId);
  if (!ev || !ev.barConfig?.ativo) return res.status(400).json({ error: 'Sistema de bar não está ativo pra esse evento.' });
  const encontrado = encontrarTicketPorCodigo(req.params.eventoId, req.params.codigo);
  if (!encontrado) return res.status(404).json({ error: 'Ingresso não encontrado.' });
  const { ticket, pedido } = encontrado;
  // Confirma que quem está pedindo a recarga é o próprio titular do ingresso
  const emailTitular = (ticket.titularEmail || pedido.comprador?.email || '').toLowerCase();
  if (emailTitular !== req.user.email.toLowerCase()) return res.status(403).json({ error: 'Esse ingresso não pertence à sua conta.' });

  const valor = Math.round((parseFloat(req.body.valor) || 0) * 100) / 100;
  if (valor < 5) return res.status(400).json({ error: 'Valor mínimo de recarga: R$ 5,00.' });

  const recargaId = uuidv4();
  const proto = req.get('x-forwarded-proto') || 'https';
  const baseUrl = `${proto}://${req.get('host')}`;
  const descricao = `Recarga de saldo — ${ev.nome}`.slice(0, 100);

  try {
    if (db.provedorPagamento === 'asaas') {
      if (!ASAAS_API_KEY) return res.status(500).json({ error: 'Asaas não configurado no servidor.' });
      const cpfLimpo = (req.user.cpfCnpj || '').replace(/[^\d]/g, '');
      if (!cpfLimpo) return res.status(400).json({ error: 'Cadastre seu CPF no perfil antes de recarregar.' });
      const checkoutBody = {
        billingTypes: ['PIX'], chargeTypes: ['DETACHED'], minutesToExpire: 30,
        externalReference: `recarga:${recargaId}`,
        callback: { successUrl: `${baseUrl}/meus-ingressos.html?recarga=sucesso`, cancelUrl: `${baseUrl}/meus-ingressos.html`, expiredUrl: `${baseUrl}/meus-ingressos.html` },
        items: [{ name: 'Recarga de saldo'.slice(0, 30), description: descricao, quantity: 1, value: valor }],
        customerData: { name: req.user.nome, cpfCnpj: cpfLimpo, email: req.user.email }
      };
      const criacao = await asaasFetch('/checkouts', { method: 'POST', body: JSON.stringify(checkoutBody) });
      if (!criacao.ok) return res.status(400).json({ error: criacao.data.errors?.[0]?.description || 'Erro ao criar recarga no Asaas.' });
      CONSUMOS_BAR.push({ id: recargaId, eventoId: req.params.eventoId, ticketCodigo: ticket.codigo, tipo: 'recarga', valor, formaPagamento: 'pix', status: 'pendente', paymentId: String(criacao.data.id), provedorPagamento: 'asaas', createdAt: new Date().toISOString() });
      persistConsumosBar();
      return res.json({ ok: true, recargaId, invoiceUrl: criacao.data.link });
    } else {
      if (!MP_PLATFORM_TOKEN) return res.status(500).json({ error: 'Mercado Pago não configurado no servidor.' });
      const pixBody = {
        transaction_amount: valor, description: descricao, payment_method_id: 'pix',
        payer: { email: req.user.email, first_name: sanitize(req.user.nome, 50) },
        external_reference: `recarga:${recargaId}`, notification_url: `${baseUrl}/api/mp/webhook?recarga=${recargaId}`
      };
      const pixResp = await fetch(`${MP_API}/v1/payments`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${MP_PLATFORM_TOKEN}`, 'X-Idempotency-Key': uuidv4() }, body: JSON.stringify(pixBody) });
      const pixData = await pixResp.json();
      if (!pixResp.ok) return res.status(400).json({ error: pixData.message || 'Erro ao gerar PIX.' });
      CONSUMOS_BAR.push({ id: recargaId, eventoId: req.params.eventoId, ticketCodigo: ticket.codigo, tipo: 'recarga', valor, formaPagamento: 'pix', status: 'pendente', paymentId: String(pixData.id), provedorPagamento: 'mercadopago', createdAt: new Date().toISOString() });
      persistConsumosBar();
      const td = pixData.point_of_interaction?.transaction_data || {};
      return res.json({ ok: true, recargaId, qrCode: td.qr_code || '', qrCodeBase64: td.qr_code_base64 || '' });
    }
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/public/bar/recarga/:recargaId/status', auth, (req, res) => {
  const recarga = CONSUMOS_BAR.find(c => c.id === req.params.recargaId && c.tipo === 'recarga');
  if (!recarga) return res.status(404).json({ error: 'Recarga não encontrada.' });
  res.json({ status: recarga.status === 'pendente' ? 'pendente' : 'confirmada', valor: recarga.valor });
});

app.post('/api/checkin/validar', auth, rateLimit(60000, 60), (req, res) => {
  const { eventoId, codigo } = req.body;
  const ev = eventoDoUsuario(eventoId, req.user.id);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  const pedidos = PEDIDOS.filter(p => p.eventoId === eventoId);
  let ticket = null, pedido = null;
  for (const p of pedidos) { const t = (p.tickets||[]).find(tk => tk.codigo === sanitize(codigo, 40)); if (t) { ticket = t; pedido = p; break; } }
  if (!ticket) return res.status(404).json({ error: 'Ingresso não encontrado.', valido: false });
  const titular = { nome: ticket.titularNome || pedido.comprador?.nome, email: ticket.titularEmail || pedido.comprador?.email };
  if (ticket.cancelado) return res.json({ valido: false, cancelado: true, ticket, comprador: titular });
  if (ticket.usado) return res.json({ valido: false, jaUsado: true, usadoEm: ticket.usadoEm, ticket, comprador: titular });
  ticket.usado = true; ticket.usadoEm = new Date().toISOString();
  persistPedidos();
  res.json({ valido: true, ticket, comprador: titular });
});

// ════════════════════════════════════════════════════════
// COMUNIDADE — perfil público, seguir, feed
// ════════════════════════════════════════════════════════
app.get('/api/organizadores/:slug', (req, res) => {
  const user = db.users.find(u => u.organizadorSlug === req.params.slug);
  if (!user) return res.status(404).json({ error: 'Página não encontrada.' });
  const eventosPublicados = EVENTOS.filter(e => e.organizadorId === user.id && e.status === 'publicado');
  const seguidores = FOLLOWS.filter(f => f.organizadorId === user.id).length;
  // Verifica se o usuário autenticado (se houver) já segue este organizador
  let jaSegue = false;
  const token = (req.headers['authorization'] || '').replace('Bearer ', '').trim();
  if (token) {
    try { const dec = jwt.verify(token, JWT_SECRET); jaSegue = FOLLOWS.some(f => f.userId === dec.id && f.organizadorId === user.id); } catch(e) {}
  }
  res.json({
    organizador: { id: user.id, nome: user.nomePublico || user.nome, slug: user.organizadorSlug, bio: user.bio, avatarUrl: user.avatarUrl, bannerUrl: user.bannerUrl, redesSociais: user.redesSociais || {}, seguidores, jaSegue, verificado: !!user.verificado },
    eventos: eventosPublicados.map(e => ({ id: e.id, slug: e.slug, nome: e.nome, dataEvento: e.dataEvento, cidade: e.cidade, imagemCapa: e.imagemCapa, categoria: e.categoria }))
  });
});

// "Seguir" continua existindo — não é mais usado pra feed/comunidade (removido), só serve pra
// decidir quem recebe e-mail quando esse produtor publica um evento novo (notificarSeguidoresNovoEvento).
app.post('/api/organizadores/:organizadorId/seguir', auth, (req, res) => {
  const organizadorId = req.params.organizadorId;
  if (organizadorId === req.user.id) return res.status(400).json({ error: 'Você não pode seguir a si mesmo.' });
  const existente = FOLLOWS.find(f => f.userId === req.user.id && f.organizadorId === organizadorId);
  if (existente) { FOLLOWS = FOLLOWS.filter(f => f !== existente); persistFollows(); return res.json({ seguindo: false }); }
  FOLLOWS.push({ userId: req.user.id, organizadorId, createdAt: new Date().toISOString() });
  persistFollows();
  res.json({ seguindo: true });
});

// ════════════════════════════════════════════════════════
// MARKETPLACE PÚBLICO
// ════════════════════════════════════════════════════════
// ── FORMULÁRIO DE CONTATO / SUPORTE ──
app.post('/api/public/contato', rateLimit(60000, 5), async (req, res) => {
  const nome = sanitize(req.body.nome || '', 100);
  const email = sanitize(req.body.email || '', 150).toLowerCase();
  const mensagem = sanitize(req.body.mensagem || '', 2000);
  const eventoSlug = sanitize(req.body.eventoSlug || '', 100);
  if (!nome || !email || !mensagem) return res.status(400).json({ error: 'Preencha nome, e-mail e mensagem.' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'E-mail inválido.' });
  const msg = { id: uuidv4(), nome, email, mensagem, eventoSlug, respondida: false, createdAt: new Date().toISOString() };
  MENSAGENS.push(msg); persistMensagens();
  if (SUPORTE_EMAIL) {
    enviarEmailGenerico(SUPORTE_EMAIL, `Nova mensagem de contato — ${nome}`,
      `<div style="font-family:Arial,sans-serif;padding:20px"><h3>Nova mensagem pelo formulário de contato</h3><p><strong>Nome:</strong> ${esc(nome)}</p><p><strong>E-mail:</strong> ${esc(email)}</p>${eventoSlug ? `<p><strong>Evento:</strong> ${esc(eventoSlug)}</p>` : ''}<p><strong>Mensagem:</strong><br>${esc(mensagem).replace(/\n/g, '<br>')}</p></div>`
    ).catch(e => console.error('Erro ao notificar suporte sobre nova mensagem:', e.message));
  } else {
    // Se isso aparecer no log, a variável SUPORTE_EMAIL não está configurada no servidor — a
    // mensagem fica salva normalmente (aparece no admin), mas nenhum e-mail é sequer tentado.
    console.error('[Contato] SUPORTE_EMAIL não configurado — e-mail de notificação não foi enviado pra mensagem de', email);
  }
  res.json({ ok: true });
});

app.get('/api/admin/auditoria', auth, adminOnly, (req, res) => {
  res.json({ registros: AUDITORIA.slice(-500).reverse() });
});

// ── DICAS PRA PRODUTORES (vídeo/PDF) — o admin publica, todo produtor vê no próprio painel ──
app.get('/api/produtor/dicas', auth, organizadorOnly, (req, res) => {
  const dicas = db.dicasProdutores || {};
  res.json({
    titulo: dicas.titulo || '', descricao: dicas.descricao || '',
    videoYoutubeId: extrairYoutubeId(dicas.videoUrl || ''),
    temPdf: !!dicas.pdfBase64, pdfNome: dicas.pdfNome || '',
    atualizadoEm: dicas.atualizadoEm || null
  });
});
app.get('/api/produtor/dicas/pdf', auth, organizadorOnly, (req, res) => {
  const dicas = db.dicasProdutores || {};
  if (!dicas.pdfBase64) return res.status(404).send('Nenhum PDF disponível.');
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `inline; filename="${dicas.pdfNome || 'dicas.pdf'}"`);
  res.send(Buffer.from(dicas.pdfBase64, 'base64'));
});
// ── Gestão do webhook do Asaas direto pela nossa API — evita depender de encontrar o botão certo
// no painel deles, que pode variar ou ser difícil de localizar quando a fila é pausada.
app.get('/api/admin/asaas-webhooks', auth, adminOnly, async (req, res) => {
  if (!ASAAS_API_KEY) return res.status(400).json({ error: 'Asaas não está configurado.' });
  try {
    const resposta = await asaasFetch('/webhooks');
    if (!resposta.ok) return res.status(400).json({ error: 'Erro ao consultar webhooks no Asaas.', detalhes: resposta.data });
    res.json({ webhooks: resposta.data.data || [] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/admin/asaas-webhooks/:id/reativar', auth, adminOnly, async (req, res) => {
  if (!ASAAS_API_KEY) return res.status(400).json({ error: 'Asaas não está configurado.' });
  try {
    const resposta = await asaasFetch(`/webhooks/${req.params.id}`, { method: 'PUT', body: JSON.stringify({ interrupted: false }) });
    if (!resposta.ok) return res.status(400).json({ error: resposta.data?.errors?.[0]?.description || 'Erro ao reativar o webhook.', detalhes: resposta.data });
    registrarAuditoria(req.user, 'reativou_webhook_asaas', { webhookId: req.params.id });
    res.json({ ok: true, webhook: resposta.data });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/dicas', auth, adminOnly, (req, res) => {
  const dicas = db.dicasProdutores || {};
  res.json({ titulo: dicas.titulo || '', descricao: dicas.descricao || '', videoUrl: dicas.videoUrl || '', pdfNome: dicas.pdfNome || '', temPdf: !!dicas.pdfBase64, atualizadoEm: dicas.atualizadoEm || null });
});
app.patch('/api/admin/dicas', auth, adminOnly, (req, res) => {
  const { titulo, descricao, videoUrl, pdfBase64, pdfNome, removerPdf } = req.body;
  if (!db.dicasProdutores) db.dicasProdutores = {};
  if (titulo !== undefined) db.dicasProdutores.titulo = sanitize(titulo, 150);
  if (descricao !== undefined) db.dicasProdutores.descricao = sanitize(descricao, 2000);
  if (videoUrl !== undefined) db.dicasProdutores.videoUrl = videoUrl && extrairYoutubeId(videoUrl) ? sanitize(videoUrl, 200) : '';
  if (removerPdf) { db.dicasProdutores.pdfBase64 = ''; db.dicasProdutores.pdfNome = ''; }
  else if (pdfBase64) {
    // Limite generoso (~9MB em base64) — arquivo grande demais é rejeitado com mensagem clara
    if (pdfBase64.length > 9_000_000) return res.status(400).json({ error: 'PDF grande demais (limite aproximado de 6-7MB). Tente compactar o arquivo.' });
    db.dicasProdutores.pdfBase64 = pdfBase64;
    db.dicasProdutores.pdfNome = sanitize(pdfNome || 'dicas.pdf', 100);
  }
  db.dicasProdutores.atualizadoEm = new Date().toISOString();
  saveDB(db);
  registrarAuditoria(req.user, 'atualizou_dicas_produtores', { titulo: db.dicasProdutores.titulo });
  res.json({ ok: true });
});

app.get('/api/admin/mensagens', auth, adminOnly, (req, res) => {
  res.json({ mensagens: MENSAGENS.slice().reverse() });
});
app.patch('/api/admin/mensagens/:id', auth, adminOnly, (req, res) => {
  const msg = MENSAGENS.find(m => m.id === req.params.id);
  if (!msg) return res.status(404).json({ error: 'Mensagem não encontrada.' });
  if (req.body.respondida !== undefined) msg.respondida = !!req.body.respondida;
  persistMensagens();
  res.json({ ok: true });
});

app.get('/api/public/cidades', rateLimit(60000, 60), (req, res) => {
  const cidades = [...new Set(EVENTOS.filter(e => e.status === 'publicado' && e.cidade).map(e => e.cidade))].sort();
  res.json({ cidades });
});

// Dados organizados pra home: carrossel de mais vistos, destaques escolhidos pelo admin, e a lista
// de categorias que têm pelo menos um evento publicado (pras abas por formato).
app.get('/api/public/home', rateLimit(60000, 60), (req, res) => {
  const publicados = EVENTOS.filter(e => e.status === 'publicado' && parseDataLocal(e.dataEvento) >= new Date(Date.now() - 86400000));
  const mapear = (e) => {
    const precos = e.lotes.filter(l => l.ativo && !l.cortesia).map(l => l.preco);
    return { slug: e.slug, nome: e.nome, dataEvento: e.dataEvento, horaEvento: e.horaEvento, cidade: e.cidade, local: e.local, categoria: e.categoria, imagemCapa: e.imagemCapa, bannerLargo: e.bannerLargo || '', precoMin: precos.length ? Math.min(...precos) : 0 };
  };
  const maisVistos = publicados.slice().sort((a, b) => (b.visualizacoes || 0) - (a.visualizacoes || 0)).slice(0, 8).map(mapear);
  const destaques = publicados.filter(e => e.destaque).sort((a,b) => parseDataLocal(a.dataEvento) - parseDataLocal(b.dataEvento)).map(mapear);
  const categorias = [...new Set(publicados.map(e => e.categoria).filter(Boolean))];
  res.json({ maisVistos, destaques, categorias });
});

app.get('/api/public/eventos', rateLimit(60000, 60), (req, res) => {
  const { cidade, categoria, busca } = req.query;
  let lista = EVENTOS.filter(e => e.status === 'publicado' && parseDataLocal(e.dataEvento) >= new Date(Date.now() - 86400000));
  if (cidade) lista = lista.filter(e => e.cidade.toLowerCase() === String(cidade).toLowerCase());
  if (categoria) lista = lista.filter(e => e.categoria.toLowerCase() === String(categoria).toLowerCase());
  if (busca) { const b = String(busca).toLowerCase(); lista = lista.filter(e => e.nome.toLowerCase().includes(b) || e.descricao.toLowerCase().includes(b)); }
  lista.sort((a,b) => parseDataLocal(a.dataEvento) - parseDataLocal(b.dataEvento));
  res.json({ eventos: lista.map(e => {
    const precos = e.lotes.filter(l=>l.ativo && !l.cortesia).map(l=>l.preco);
    return { slug: e.slug, nome: e.nome, dataEvento: e.dataEvento, horaEvento: e.horaEvento, cidade: e.cidade, local: e.local, categoria: e.categoria, imagemCapa: e.imagemCapa, precoMin: precos.length?Math.min(...precos):0 };
  })});
});

// Serve a imagem de capa como arquivo de verdade (ela é guardada em base64 no banco) —
// necessário pra redes sociais (WhatsApp, Instagram, etc.) conseguirem gerar preview do link.
app.get('/api/public/eventos/:slug/imagem', (req, res) => {
  const ref = db.ticketSlugs[req.params.slug];
  if (!ref) return res.status(404).send('Não encontrado.');
  const ev = EVENTOS.find(e => e.id === ref.eventoId);
  if (!ev || !ev.imagemCapa || !ev.imagemCapa.startsWith('data:image/')) return res.status(404).send('Sem imagem.');
  const match = ev.imagemCapa.match(/^data:(image\/\w+);base64,(.+)$/);
  if (!match) return res.status(404).send('Formato inválido.');
  const [, mime, base64Data] = match;
  res.setHeader('Content-Type', mime);
  res.setHeader('Cache-Control', 'public, max-age=86400');
  res.send(Buffer.from(base64Data, 'base64'));
});

app.get('/api/public/eventos/:slug', rateLimit(60000, 60), (req, res) => {
  const ref = db.ticketSlugs[req.params.slug];
  if (!ref) return res.status(404).json({ error: 'Evento não encontrado.' });
  const ev = EVENTOS.find(e => e.id === ref.eventoId);
  if (!ev || ev.status !== 'publicado') return res.status(404).json({ error: 'Evento não encontrado ou não publicado.' });
  ev.visualizacoes = (ev.visualizacoes || 0) + 1;
  persistEventos();
  const organizador = db.users.find(u => u.id === ev.organizadorId);
  const lotesPublicos = ev.lotes.filter(l => l.ativo && !l.exclusivoPromoter && l.vendidos < l.qtdTotal)
    .map(l => ({ id: l.id, nome: l.nome, preco: l.preco, cortesia: l.cortesia, disponivel: Math.floor((l.qtdTotal - l.vendidos) / pessoasPorUnidadeLote(l.nome)), imagemUrl: l.imagemUrl || '' }));
  res.json({
    nome: ev.nome, descricao: ev.descricao, dataEvento: ev.dataEvento, horaEvento: ev.horaEvento,
    local: ev.local, cidade: ev.cidade, categoria: ev.categoria, imagemCapa: ev.imagemCapa, cores: ev.cores,
    videoYoutubeId: extrairYoutubeId(ev.videoUrl || ''),
    lotes: lotesPublicos, pixels: ev.pixels, testMode: isTestToken(MP_PLATFORM_TOKEN),
    feePercent: db.marketplaceFeePercent || 10,
    mpPublicKey: MP_PUBLIC_KEY,
    googleClientId: GOOGLE_CLIENT_ID || undefined,
    suporteWhatsapp: SUPORTE_WHATSAPP || undefined,
    provedorPagamento: db.provedorPagamento,
    mapaAssentos: ev.mapaAssentos?.ativo ? ev.mapaAssentos : null,
    assentosOcupados: ev.mapaAssentos?.ativo ? (ev.assentosOcupados || []) : [],
    organizador: { nome: organizador?.nomePublico || organizador?.nome, slug: organizador?.organizadorSlug, verificado: !!organizador?.verificado }
  });
});

// Validação de cupom em tempo real — permite mostrar o desconto real antes do pagamento
app.get('/api/public/eventos/:slug/cupom/:codigo', rateLimit(60000, 60), (req, res) => {
  const ref = db.ticketSlugs[req.params.slug];
  if (!ref) return res.status(404).json({ error: 'Evento não encontrado.' });
  const ev = EVENTOS.find(e => e.id === ref.eventoId);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  const cupomObj = ev.cupons.find(c => c.codigo === String(req.params.codigo).toUpperCase().trim() && c.ativo);
  if (!cupomObj) return res.status(404).json({ error: 'Cupom inválido ou expirado.' });
  if (cupomObj.usosMax > 0 && cupomObj.usosAtuais >= cupomObj.usosMax) return res.status(400).json({ error: 'Cupom esgotado.' });
  res.json({ codigo: cupomObj.codigo, tipo: cupomObj.tipo, valor: cupomObj.valor });
});

app.get('/api/public/eventos/:slug/promoter/:codigoRef', rateLimit(60000, 60), (req, res) => {
  const ref = db.ticketSlugs[req.params.slug];
  if (!ref) return res.status(404).json({ error: 'Evento não encontrado.' });
  const ev = EVENTOS.find(e => e.id === ref.eventoId);
  const promoter = ev?.promoters.find(p => p.codigoRef === req.params.codigoRef && p.ativo);
  if (!promoter) return res.status(404).json({ error: 'Promoter não encontrado.' });
  const lotesExclusivos = ev.lotes.filter(l => l.ativo && l.vendidos < l.qtdTotal).map(l => ({ id: l.id, nome: l.nome, preco: l.preco, cortesia: l.cortesia, disponivel: Math.floor((l.qtdTotal - l.vendidos) / pessoasPorUnidadeLote(l.nome)) }));
  res.json({ promoterNome: promoter.nome, lotes: lotesExclusivos });
});
// ── CHECKOUT (com cupom, promoter e cortesia) ──
app.post('/api/public/checkout', rateLimit(60000, 20), async (req, res) => {
  try {
    const { slug, itens, comprador, cupom, ref } = req.body;
    const hostReq = req.get('host'); const protoReq = req.get('x-forwarded-proto') || 'https';
    const baseUrl = `${protoReq}://${hostReq}`;
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

    // ── Validação (sem alterar nada ainda) ──
    let subtotal = 0, itensDetalhados = [];
    for (const it of itens) {
      const lote = ev.lotes.find(l => l.id === it.loteId);
      if (!lote || !lote.ativo) return res.status(400).json({ error: 'Lote indisponível.' });
      if (it.assento) {
        // Compra com assento marcado — cada assento é único, sem quantidade agregada
        if (assentosOcupadosAtuais.includes(it.assento) || assentosSelecionadosNestePedido.includes(it.assento)) {
          return res.status(400).json({ error: `O assento ${it.assento} já foi vendido ou está reservado por outra pessoa. Escolha outro.` });
        }
        assentosSelecionadosNestePedido.push(it.assento);
        subtotal += lote.preco;
        itensDetalhados.push({ loteId: lote.id, qtd: 1, precoUnit: lote.preco, loteNome: lote.nome, assento: it.assento });
        continue;
      }
      const qtd = Math.max(1, parseInt(it.qtd) || 1);
      const pessoasUnidade = pessoasPorUnidadeLote(lote.nome);
      if (lote.vendidos + qtd * pessoasUnidade > lote.qtdTotal) return res.status(400).json({ error: `Apenas ${Math.floor((lote.qtdTotal - lote.vendidos) / pessoasUnidade)} disponíveis em "${lote.nome}".` });
      subtotal += lote.preco * qtd;
      // Nomes das pessoas adicionais (pra lotes Duplo/Quádruplo) — o comprador leva o próprio nome
      // automaticamente, então só recebemos os nomes de quem MAIS vai usar os ingressos desse item.
      const nomesEsperados = qtd * pessoasUnidade - 1;
      const nomesAdicionais = nomesEsperados > 0 && Array.isArray(it.nomesAdicionais)
        ? it.nomesAdicionais.slice(0, nomesEsperados).map(n => sanitize(n || '', 100))
        : [];
      itensDetalhados.push({ loteId: lote.id, qtd, precoUnit: lote.preco, loteNome: lote.nome, nomesAdicionais });
    }

    // ── Reserva IMEDIATA (crítico pra alta concorrência) ──
    // Tudo isso roda de forma síncrona, sem nenhum "await" desde a leitura de `lote.vendidos` até aqui —
    // o Node.js garante que nenhuma outra requisição "fura a fila" no meio disso. Reservar aqui (e não
    // só na confirmação do pagamento, minutos depois) é o que impede duas pessoas ganharem o mesmo
    // último ingresso/assento num pico de acesso simultâneo. A reserva é revertida automaticamente se
    // o pagamento for recusado, cancelado ou expirar sem confirmação (ver liberarReservaPedido).
    for (const it of itensDetalhados) {
      const lote = ev.lotes.find(l => l.id === it.loteId);
      if (lote && !it.assento) lote.vendidos = (lote.vendidos || 0) + it.qtd * pessoasPorUnidadeLote(lote.nome);
    }
    if (assentosSelecionadosNestePedido.length) {
      ev.assentosOcupados = [...assentosOcupadosAtuais, ...assentosSelecionadosNestePedido];
    }
    persistEventos();

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
    // Crédito de indicação: só pode abater da taxa administrativa (nunca do valor do produtor),
    // então o repasse ao produtor nunca é afetado por esse benefício.
    let creditoAplicado = 0;
    const compradorLogado = compradorUserId ? db.users.find(u => u.id === compradorUserId) : null;
    if (req.body.usarCredito && compradorLogado?.saldoCredito > 0) {
      creditoAplicado = Math.min(compradorLogado.saldoCredito, taxaAdministrativa);
      creditoAplicado = Math.round(creditoAplicado * 100) / 100;
    }
    const total = Math.round((valorIngressos + taxaAdministrativa - creditoAplicado) * 100) / 100;

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
      pedido.emailEnviado = await enviarEmailIngressos(pedido, ev, baseUrl);
      persistPedidos();
      return res.json({ ok: true, pedidoId, cortesia: true });
    }

    if (db.provedorPagamento === 'asaas' && !ASAAS_API_KEY) return res.status(500).json({ error: 'Pagamento indisponível no momento. Peça ao administrador para configurar o Asaas.' });
    if (db.provedorPagamento === 'mercadopago' && !MP_PLATFORM_TOKEN) return res.status(500).json({ error: 'Pagamento indisponível no momento. Peça ao administrador para configurar o Mercado Pago.' });

    const { metodo, cpf, token, installments, paymentMethodId, issuerId, deviceId, cep, numero } = req.body;
    const cpfLimpo = sanitize(cpf || '', 20).replace(/[^\d]/g, '');
    if (!cpfLimpo || cpfLimpo.length !== 11) return res.status(400).json({ error: 'CPF do comprador é obrigatório e deve ter 11 dígitos.' });

    // Garante um número "limpo" com exatamente 2 casas decimais — evita rejeição da API por formatação
    const valorCobranca = Number(total.toFixed(2));
    if (!(valorCobranca > 0)) return res.status(400).json({ error: 'Valor de cobrança inválido.' });

    const descricao = `${ev.nome} — ${itensDetalhados.map(it => it.loteNome).join(', ')}`.slice(0, 250);

    const pedidoBase = {
      id: pedidoId, eventoId: ev.id, status: 'pendente',
      comprador: { nome: sanitize(comprador.nome,100), email: comprador.email, telefone: sanitize(comprador.telefone||'',30), cpf: cpfLimpo },
      compradorUserId, provedorPagamento: db.provedorPagamento,
      itens: itensDetalhados, subtotal, desconto, valorIngressos, taxaAdministrativa, creditoAplicado, total, cupomUsado: cupomObj?.codigo || null, promoterRef: promoterObj?.id || null,
      mpPaymentId: null, tickets: [], createdAt: new Date().toISOString(),
      // Se o pagamento não for confirmado até esse horário, a reserva do ingresso/assento é liberada
      // automaticamente (ver job de limpeza mais abaixo) — evita que tentativas abandonadas travem
      // vagas pra sempre num evento concorrido.
      // Prazo generoso (90 min) — dá margem confortável além do prazo de 60 min que o próprio
      // Asaas usa pra sessão de checkout, e cobre bem o tempo que alguém pode levar pra pagar um PIX.
      expiraEm: new Date(Date.now() + 90 * 60000).toISOString()
    };

    // ── ASAAS — checkout hospedado (redireciona o comprador pra fatura do Asaas) ──
    if (db.provedorPagamento === 'asaas') {
      try {
        // Produto "Asaas Checkout" — diferente da cobrança básica que usávamos antes, esse permite
        // configurar quantas parcelas oferecer no cartão (o antigo não tinha essa opção, por isso
        // o parcelamento não aparecia). Também aceita os dados do cliente direto, sem precisar
        // cadastrar um "customer" separado antes.
        const chargeTypes = metodo === 'cartao' ? ['DETACHED', 'INSTALLMENT'] : ['DETACHED'];
        const billingTypesMap = { pix: ['PIX'], cartao: ['CREDIT_CARD'], boleto: ['BOLETO'] };
        const cepLimpo = (cep || '').replace(/[^\d]/g, '');

        // O Asaas exige endereço completo (rua, bairro, cidade) sempre que enviamos os dados do
        // cliente antecipadamente — não importa a forma de pagamento escolhida (PIX, cartão ou
        // boleto). Resolvemos isso consultando o CEP no ViaCEP (serviço público e gratuito) por
        // trás dos panos, assim o comprador só precisa digitar o CEP mesmo, em qualquer método.
        let enderecoResolvido = null;
        if (cepLimpo.length === 8) {
          try {
            const viaCepResp = await fetch(`https://viacep.com.br/ws/${cepLimpo}/json/`);
            const viaCepData = await viaCepResp.json();
            if (!viaCepData.erro) {
              enderecoResolvido = { address: viaCepData.logradouro || 'Endereço não informado', province: viaCepData.bairro || 'Centro', city: parseInt(viaCepData.ibge, 10) || undefined };
            }
          } catch (e) { console.error('Erro ao consultar CEP no ViaCEP:', e.message); }
        }
        if (!cepLimpo || cepLimpo.length !== 8) {
          return res.status(400).json({ error: 'CEP é obrigatório e deve ter 8 dígitos.' });
        }
        if (!enderecoResolvido) {
          return res.status(400).json({ error: 'Não conseguimos localizar esse CEP. Confira e tente novamente.' });
        }

        const checkoutBody = {
          billingTypes: billingTypesMap[metodo] || ['PIX', 'CREDIT_CARD'],
          chargeTypes,
          minutesToExpire: 60,
          externalReference: pedidoId,
          callback: {
            successUrl: `${baseUrl}/e/${slug}?pedido=${pedidoId}&status=success`,
            cancelUrl: `${baseUrl}/e/${slug}?pedido=${pedidoId}&status=pending`,
            expiredUrl: `${baseUrl}/e/${slug}?pedido=${pedidoId}&status=pending`,
          },
          // Um único item combinado (em vez de um por lote) evita qualquer risco de o total dos
          // itens não bater exatamente com o valor já calculado (com desconto de cupom/crédito
          // aplicado) — o valor cobrado sempre reflete exatamente o que já validamos.
          items: [{ name: ev.nome.slice(0, 30), description: descricao.slice(0, 150), quantity: 1, value: valorCobranca }],
          customerData: {
            name: comprador.nome, cpfCnpj: cpfLimpo, email: comprador.email,
            phone: (comprador.telefone || '').replace(/[^\d]/g, '') || undefined,
            postalCode: cepLimpo || undefined,
            addressNumber: numero || 'S/N',
            ...(enderecoResolvido || {})
          }
        };
        if (chargeTypes.includes('INSTALLMENT')) checkoutBody.installment = { maxInstallmentCount: 3 };

        const criacao = await asaasFetch('/checkouts', { method: 'POST', body: JSON.stringify(checkoutBody) });
        if (!criacao.ok) return res.status(400).json({ error: criacao.data.errors?.[0]?.description || 'Erro ao criar checkout no Asaas.' });
        pedidoBase.mpPaymentId = criacao.data.id; // guardamos o ID do checkout do Asaas nesse mesmo campo
        PEDIDOS.push(pedidoBase);
        // Gravação SÍNCRONA aqui — garante que o pedido já está de verdade em disco antes do
        // comprador ser redirecionado pro Asaas, fechando a janela de corrida que podia perder o
        // pedido em caso de reinício do servidor bem nesse instante.
        persistPedidosSync();
        console.log(`[Checkout Asaas] Pedido ${pedidoId} criado com sucesso — checkout id: ${criacao.data.id}, comprador: ${comprador.email}, valor: R$${valorCobranca}`);
        return res.json({ ok: true, pedidoId, metodo: 'asaas', invoiceUrl: criacao.data.link });
      } catch (e) { return res.status(500).json({ error: e.message }); }
    }

    if (metodo === 'pix') {
      const pixBody = {
        transaction_amount: valorCobranca, description: descricao, payment_method_id: 'pix',
        payer: { email: comprador.email, first_name: sanitize(comprador.nome,50), identification: { type: 'CPF', number: cpfLimpo } },
        external_reference: pedidoId, notification_url: `${baseUrl}/api/mp/webhook?ped=${pedidoId}`
      };
      console.log('Enviando pagamento PIX ao Mercado Pago:', JSON.stringify(pixBody));
      const pixResp = await fetch(`${MP_API}/v1/payments`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${MP_PLATFORM_TOKEN}`, 'X-Idempotency-Key': uuidv4(), ...(deviceId ? { 'X-meli-session-id': deviceId } : {}) }, body: JSON.stringify(pixBody) });
      const pixData = await pixResp.json();
      if (!pixResp.ok) {
        console.error('Mercado Pago recusou o PIX:', pixResp.status, JSON.stringify(pixData));
        const detalhe = Array.isArray(pixData.cause) && pixData.cause[0]?.description ? pixData.cause[0].description : pixData.message;
        return res.status(400).json({ error: detalhe || 'Erro ao gerar PIX.' });
      }
      pedidoBase.mpPaymentId = String(pixData.id);
      PEDIDOS.push(pedidoBase); persistPedidosSync();
      console.log(`[Checkout MP/PIX] Pedido ${pedidoId} criado com sucesso — payment id: ${pixData.id}, comprador: ${comprador.email}, valor: R$${valorCobranca}`);
      const td = pixData.point_of_interaction?.transaction_data || {};
      return res.json({ ok: true, pedidoId, metodo: 'pix', qrCode: td.qr_code || '', qrCodeBase64: td.qr_code_base64 || '', testMode: isTestToken(MP_PLATFORM_TOKEN) });
    }

    // Cartão
    if (!token || !paymentMethodId) return res.status(400).json({ error: 'Dados do cartão incompletos.' });
    // O Mercado Pago exige um mínimo de R$5,00 por parcela — limitamos aqui pra nunca enviar um
    // número de parcelas que resulte num valor de parcela abaixo disso (causa "Invalid transaction_amount").
    const maxParcelasPermitidas = Math.max(1, Math.floor(valorCobranca / 5));
    const parcelasSolicitadas = Math.max(1, parseInt(installments) || 1);
    const parcelasFinal = Math.min(parcelasSolicitadas, maxParcelasPermitidas);
    const [primeiroNome, ...restoNome] = (comprador.nome || '').trim().split(' ');
    const cardBody = {
      transaction_amount: valorCobranca, token, description: descricao,
      installments: parcelasFinal,
      payment_method_id: paymentMethodId, issuer_id: issuerId || undefined,
      capture: true,
      // 3D Secure: pede confirmação de identidade do titular do cartão direto com o banco emissor
      // quando a transação é considerada de risco — isso aumenta bastante a taxa de aprovação em
      // casos como o nosso (conta de produção recente), sem prejudicar quem já é de baixo risco
      // (nesses casos, segue aprovando direto, sem pedir nada extra ao comprador).
      three_d_secure_mode: 'optional',
      payer: {
        email: comprador.email, identification: { type: 'CPF', number: cpfLimpo },
        first_name: primeiroNome || undefined, last_name: restoNome.join(' ') || undefined,
        phone: comprador.telefone ? { number: comprador.telefone.replace(/[^\d]/g,'') } : undefined
      },
      additional_info: {
        items: itensDetalhados.map(it => ({ id: it.loteId, title: it.loteNome, quantity: it.qtd, unit_price: it.precoUnit, category_id: 'tickets' })),
        payer: { first_name: primeiroNome || undefined, last_name: restoNome.join(' ') || undefined, phone: comprador.telefone ? { number: comprador.telefone.replace(/[^\d]/g,'') } : undefined }
      },
      external_reference: pedidoId, notification_url: `${baseUrl}/api/mp/webhook?ped=${pedidoId}`
    };
    console.log('Enviando pagamento com cartão ao Mercado Pago:', JSON.stringify({ ...cardBody, token: '(oculto)' }), '| Device ID presente:', !!deviceId);
    const cardResp = await fetch(`${MP_API}/v1/payments`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${MP_PLATFORM_TOKEN}`, 'X-Idempotency-Key': uuidv4(), ...(deviceId ? { 'X-meli-session-id': deviceId } : {}) }, body: JSON.stringify(cardBody) });
    const cardData = await cardResp.json();
    if (!cardResp.ok) {
      console.error('Mercado Pago recusou o pagamento:', cardResp.status, JSON.stringify(cardData));
      const detalhe = Array.isArray(cardData.cause) && cardData.cause[0]?.description ? cardData.cause[0].description : cardData.message;
      return res.status(400).json({ error: detalhe || 'Erro ao processar pagamento.' });
    }

    pedidoBase.mpPaymentId = String(cardData.id);
    PEDIDOS.push(pedidoBase); persistPedidosSync();
    console.log(`[Checkout MP/Cartão] Pedido ${pedidoId} criado — payment id: ${cardData.id}, status inicial: ${cardData.status}, comprador: ${comprador.email}, valor: R$${valorCobranca}`);
    const pedidoSalvo = PEDIDOS.find(p => p.id === pedidoId);

    if (cardData.status === 'pending' && cardData.status_detail === 'pending_challenge' && cardData.three_ds_info) {
      // O banco pediu uma confirmação extra de identidade (3D Secure) — o pedido continua "pendente"
      // no nosso banco (o pagamento só será aprovado depois que o comprador concluir essa etapa com
      // o banco). O front-end mostra a tela de verificação do Mercado Pago pra isso acontecer.
      pedidoSalvo.mpPaymentId = String(cardData.id);
      persistPedidos();
      return res.json({ ok: true, pedidoId, status: 'challenge_3ds', paymentId: cardData.id, threeDsInfo: cardData.three_ds_info });
    } else if (cardData.status === 'approved') {
      await processarPagamentoAprovado(pedidoSalvo, cardData.id, baseUrl);
      return res.json({ ok: true, pedidoId, status: 'approved', tickets: pedidoSalvo.tickets });
    } else if (cardData.status === 'in_process' || cardData.status === 'pending') {
      return res.json({ ok: true, pedidoId, status: 'pending' });
    } else {
      console.error('Mercado Pago processou mas RECUSOU o pagamento:', '| status:', cardData.status, '| status_detail:', cardData.status_detail, '| payment_id:', cardData.id, '| pedido:', pedidoId);
      pedidoSalvo.status = 'recusado';
      liberarReservaPedido(pedidoSalvo, ev);
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

// ════════════════════════════════════════════════════════
// ASAAS — checkout hospedado (comprador é redirecionado pra fatura do Asaas)
// ════════════════════════════════════════════════════════
async function asaasFetch(caminho, opcoes = {}) {
  const resp = await fetch(`${ASAAS_API}${caminho}`, {
    ...opcoes,
    headers: { 'Content-Type': 'application/json', 'access_token': ASAAS_API_KEY, ...(opcoes.headers || {}) }
  });
  const data = await resp.json().catch(() => ({}));
  return { ok: resp.ok, status: resp.status, data };
}

async function buscarOuCriarClienteAsaas(comprador, cpf) {
  const busca = await asaasFetch(`/customers?cpfCnpj=${cpf}`);
  if (busca.ok && busca.data.data && busca.data.data.length > 0) return busca.data.data[0].id;
  const criacao = await asaasFetch('/customers', {
    method: 'POST',
    body: JSON.stringify({ name: comprador.nome, email: comprador.email, cpfCnpj: cpf, phone: (comprador.telefone || '').replace(/[^\d]/g, '') || undefined })
  });
  if (!criacao.ok) throw new Error(criacao.data.errors?.[0]?.description || 'Erro ao cadastrar comprador no Asaas.');
  return criacao.data.id;
}


function gerarTicketsEAtualizar(ev, pedido, cupomObj, promoterObj) {
  pedido.tickets = [];
  if (!ev.assentosOcupados) ev.assentosOcupados = [];
  // NOTA: `lote.vendidos` e `ev.assentosOcupados` já foram reservados no momento do checkout
  // (ver rota de checkout), não incrementamos de novo aqui — só geramos os códigos dos ingressos.
  for (const it of pedido.itens) {
    if (it.assento) {
      pedido.tickets.push({ codigo: gerarCodigoTicket(), loteNome: it.loteNome, assento: it.assento, usado: false, usadoEm: null, titularNome: pedido.comprador?.nome || '', titularEmail: pedido.comprador?.email || '' });
    } else {
      // Lotes "Duplo"/"Quádruplo" geram um ingresso PRA CADA PESSOA (com QR Code próprio), não um
      // só pra unidade comprada. O comprador leva o dele automaticamente; os nomes das demais
      // pessoas (se informados no checkout) vão pra cada ingresso adicional correspondente.
      const pessoasPorUnidade = pessoasPorUnidadeLote(it.loteNome);
      const nomesAdicionais = Array.isArray(it.nomesAdicionais) ? it.nomesAdicionais : [];
      let ponteiroNomes = 0;
      for (let unidade = 0; unidade < it.qtd; unidade++) {
        for (let pessoa = 0; pessoa < pessoasPorUnidade; pessoa++) {
          const ehTitularPrincipal = unidade === 0 && pessoa === 0;
          const nomeAdicional = ehTitularPrincipal ? null : (nomesAdicionais[ponteiroNomes++] || '');
          pedido.tickets.push({
            codigo: gerarCodigoTicket(), loteNome: it.loteNome, usado: false, usadoEm: null,
            titularNome: ehTitularPrincipal ? (pedido.comprador?.nome || '') : (nomeAdicional || pedido.comprador?.nome || ''),
            titularEmail: pedido.comprador?.email || ''
          });
        }
      }
    }
  }
  if (cupomObj) cupomObj.usosAtuais = (cupomObj.usosAtuais || 0) + 1;
  if (promoterObj) { promoterObj.vendas = (promoterObj.vendas || 0) + pedido.tickets.length; promoterObj.receita = (promoterObj.receita || 0) + (pedido.valorIngressos !== undefined ? pedido.valorIngressos : pedido.total); }
  ev.updatedAt = new Date().toISOString();
}

async function gerarPdfIngressos(pedido, ev) {
  const doc = new PDFDocument({ size: 'A4', margin: 0 });
  const chunks = [];
  doc.on('data', c => chunks.push(c));
  const done = new Promise((resolve, reject) => { doc.on('end', () => resolve(Buffer.concat(chunks))); doc.on('error', reject); });

  const PAGE_W = doc.page.width;
  const MARGIN = 40;
  const CONTENT_W = PAGE_W - MARGIN * 2;
  const LARANJA = '#C47B14';
  const LARANJA_CLARO = '#E8961A';
  const ESCURO = '#18160F';
  const CINZA = '#555555';
  const CINZA_CLARO = '#8A8378';
  const BORDA = '#E4DDD1';

  const tickets = pedido.tickets || [];
  for (let i = 0; i < tickets.length; i++) {
    const t = tickets[i];
    if (i > 0) doc.addPage({ size: 'A4', margin: 0 });

    // ── Faixa superior com a logo ──
    doc.rect(0, 0, PAGE_W, 80).fill(ESCURO);
    try {
      const logoPath = path.join(PUBLIC_DIR, 'logo.png');
      if (fs.existsSync(logoPath)) doc.image(logoPath, MARGIN, 20, { height: 40 });
    } catch (e) { console.error('Erro ao carregar logo no PDF:', e.message); }
    doc.fillColor('#FFFFFF').fontSize(19).font('Helvetica-Bold').text('LOTA', MARGIN + 48, 32);

    // ── Nome do evento e dados ──
    let y = 105;
    doc.fillColor(ESCURO).fontSize(21).font('Helvetica-Bold').text(ev.nome || 'Evento', MARGIN, y, { width: CONTENT_W });
    y = doc.y + 10;

    const dataStr = ev.dataEvento ? parseDataLocal(ev.dataEvento).toLocaleDateString('pt-BR', { weekday: 'long', day: '2-digit', month: 'long', year: 'numeric' }) : '';
    doc.fillColor(CINZA).fontSize(11).font('Helvetica').text(`Data:  ${dataStr}${ev.horaEvento ? ' às ' + ev.horaEvento : ''}`, MARGIN, y);
    y = doc.y + 4;
    if (ev.local) { doc.text(`Local:  ${ev.local}${ev.cidade ? ', ' + ev.cidade : ''}`, MARGIN, y); y = doc.y + 4; }

    // ── Linha divisória ──
    y += 14;
    doc.moveTo(MARGIN, y).lineTo(PAGE_W - MARGIN, y).lineWidth(1).strokeColor(BORDA).stroke();
    y += 24;

    // ── Card do ingresso (formato talão, com linha pontilhada separando o QR) ──
    const cardH = 190;
    const cardY = y;
    const qrColW = 170;
    const infoColW = CONTENT_W - qrColW;

    doc.roundedRect(MARGIN, cardY, CONTENT_W, cardH, 10).lineWidth(1.2).strokeColor(BORDA).stroke();

    // Linha pontilhada vertical separando as duas seções
    const divisorX = MARGIN + infoColW;
    doc.save();
    doc.dash(4, { space: 4 }).moveTo(divisorX, cardY + 14).lineTo(divisorX, cardY + cardH - 14).strokeColor(BORDA).lineWidth(1.2).stroke();
    doc.undash();
    doc.restore();

    // Furinhos decorativos nas bordas do divisor (efeito "destacável")
    doc.circle(divisorX, cardY, 8).fill('#FFFFFF');
    doc.circle(divisorX, cardY + cardH, 8).fill('#FFFFFF');

    // ── Coluna esquerda: dados do ingresso ──
    const padX = MARGIN + 22;
    let iy = cardY + 22;
    doc.fillColor(CINZA_CLARO).fontSize(9).font('Helvetica-Bold').text('INGRESSO', padX, iy, { characterSpacing: 1.5 });
    iy += 22;
    doc.fillColor(CINZA_CLARO).fontSize(9).font('Helvetica-Bold').text('TITULAR', padX, iy, { characterSpacing: 1 });
    doc.fillColor(ESCURO).fontSize(13).font('Helvetica-Bold').text(t.titularNome || pedido.comprador?.nome || '', padX, iy + 13);
    iy += 42;
    doc.fillColor(CINZA_CLARO).fontSize(9).font('Helvetica-Bold').text('LOTE', padX, iy, { characterSpacing: 1 });
    doc.fillColor(ESCURO).fontSize(13).font('Helvetica-Bold').text(`${t.loteNome || ''}${t.assento ? '  •  Assento ' + t.assento : ''}`, padX, iy + 13, { width: infoColW - 40 });
    iy += 42;
    doc.fillColor(CINZA_CLARO).fontSize(9).font('Helvetica-Bold').text('CÓDIGO DO INGRESSO', padX, iy, { characterSpacing: 1 });
    doc.fillColor(LARANJA).fontSize(15).font('Helvetica-Bold').text(t.codigo, padX, iy + 13);

    // ── Coluna direita: QR Code ──
    try {
      const qrDataUrl = await QRCode.toDataURL(t.codigo, { width: 300, margin: 0 });
      const qrBuffer = Buffer.from(qrDataUrl.split(',')[1], 'base64');
      const qrSize = 118;
      doc.image(qrBuffer, divisorX + (qrColW - qrSize) / 2, cardY + (cardH - qrSize) / 2 - 6, { width: qrSize, height: qrSize });
      doc.fillColor(CINZA_CLARO).fontSize(8).font('Helvetica').text('Apresente na entrada', divisorX, cardY + (cardH - qrSize) / 2 + qrSize + 2, { width: qrColW, align: 'center' });
    } catch (e) {}

    // ── Rodapé ──
    const footY = cardY + cardH + 30;
    doc.fillColor(CINZA_CLARO).fontSize(9).font('Helvetica').text('Este ingresso é pessoal e intransferível. Apresente o QR Code (impresso ou no celular) na entrada do evento.', MARGIN, footY, { width: CONTENT_W });
    doc.fillColor(CINZA_CLARO).fontSize(9).text('Vendido com Lota — lotaticketeria.com.br', MARGIN, footY + 16);
  }
  doc.end();
  return done;
}

async function enviarEmailIngressos(pedido, ev, baseUrl) {
  console.log(`Preparando e-mail de ingressos para ${pedido.comprador?.email} (pedido ${pedido.id})`);
  if (!RESEND_API_KEY) { console.error('RESEND_API_KEY não configurada — e-mail de ingressos não enviado.'); return false; }
  if (!pedido.comprador?.email) { console.error('Pedido sem e-mail de comprador — não é possível enviar.'); return false; }
  const nomeEvento = ev.nome || 'Evento';
  const linkPdf = baseUrl ? `${baseUrl}/api/public/pedido/${pedido.id}/pdf` : '';
  const ticketsHtml = (pedido.tickets || []).map(t => `
    <div style="border:1px solid #2A2822;border-radius:10px;padding:16px;margin-bottom:10px;display:flex;align-items:center;gap:16px;background:#161410;">
      <img src="https://api.qrserver.com/v1/create-qr-code/?size=120x120&data=${encodeURIComponent(t.codigo)}" width="90" height="90" style="border-radius:8px;background:#fff;padding:4px" />
      <div><div style="font-family:monospace;font-weight:700;color:#C47B14;font-size:14px;">${t.codigo}</div><div style="font-size:12px;color:#A09880;margin-top:2px;">${esc(t.loteNome)}${t.assento?' · Assento '+esc(t.assento):''}</div></div>
    </div>`).join('');
  const html = `<div style="background:#0F0E0C;padding:32px 20px;font-family:Arial,sans-serif;color:#F0EDE8;"><div style="max-width:480px;margin:0 auto;">
    <div style="margin-bottom:4px;"><img src="${baseUrl}/logo-header.png" alt="Lota" height="28" style="vertical-align:middle;margin-right:8px"><span style="font-size:20px;font-weight:800;color:#C47B14;vertical-align:middle;">Lota</span></div>
    <p style="font-size:14px;color:#A09880;margin-bottom:24px;">Confirmação de compra</p>
    <h2 style="font-size:18px;margin-bottom:6px;">Seu ingresso para</h2>
    <p style="font-size:20px;font-weight:800;color:#fff;margin-bottom:20px;">${esc(nomeEvento)}</p>
    <p style="font-size:13px;color:#A09880;margin-bottom:16px;">Olá ${esc(pedido.comprador.nome)}, aqui estão seus ingressos:</p>
    ${ticketsHtml}
    ${linkPdf ? `<a href="${linkPdf}" style="display:block;text-align:center;background:#E8961A;color:#18160F;font-weight:800;padding:13px;border-radius:9px;text-decoration:none;font-size:14px;margin-top:18px;">📄 Abrir ingresso em PDF</a>` : ''}
    <p style="font-size:11px;color:#605848;margin-top:20px;">Apresente o QR Code na entrada. Se o PDF anexado não abrir, use o botão acima pra acessá-lo a qualquer momento.</p>
    </div></div>`;
  const payload = { from: RESEND_FROM, to: pedido.comprador.email, subject: `Seus ingressos — ${nomeEvento}`, html };
  try {
    const pdfBuffer = await gerarPdfIngressos(pedido, ev);
    payload.attachments = [{ filename: `ingresso-${(ev.slug || 'lota')}.pdf`, content: pdfBuffer.toString('base64') }];
    console.log(`PDF do ingresso gerado com sucesso (${pdfBuffer.length} bytes) para o pedido ${pedido.id}`);
  } catch (e) { console.error('Erro ao gerar PDF do ingresso — e-mail seguirá sem anexo, mas com o link de download:', e.message); }
  try {
    const r = await fetch('https://api.resend.com/emails', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${RESEND_API_KEY}` }, body: JSON.stringify(payload) });
    if (!r.ok) { const errBody = await r.text().catch(()=>''); console.error('Resend recusou o envio do e-mail de ingressos:', r.status, errBody); return false; }
    console.log(`E-mail de ingressos enviado com sucesso para ${pedido.comprador.email} (pedido ${pedido.id})`);
    return true;
  } catch(e) { console.error('Erro de rede ao enviar e-mail de ingressos:', e.message); return false; }
}

// ── WEBHOOK MERCADO PAGO ──
async function processarPagamentoAprovado(pedido, paymentId, baseUrl) {
  if (pedido.status === 'pago') return;
  pedido.status = 'pago'; pedido.pagoEm = new Date().toISOString();
  const checkoutIdOriginal = String(paymentId);
  pedido.mpPaymentId = checkoutIdOriginal;
  // No Asaas, o "paymentId" que chega aqui (do webhook de Checkout ou da consulta de status) é o
  // ID do CHECKOUT, não do pagamento em si — e reembolso precisa do ID do pagamento de verdade.
  // Resolvemos isso buscando o pagamento pelo filtro "checkoutSession" (o jeito correto e oficial
  // de encontrar o pagamento gerado por uma sessão de checkout específica).
  if (pedido.provedorPagamento === 'asaas' && ASAAS_API_KEY) {
    try {
      const busca = await asaasFetch(`/payments?checkoutSession=${checkoutIdOriginal}`);
      if (busca.ok && busca.data.data && busca.data.data.length > 0) {
        pedido.mpPaymentId = String(busca.data.data[0].id);
      } else {
        console.error(`Não foi possível localizar o pagamento real da sessão de checkout ${checkoutIdOriginal} — reembolso desse pedido pode precisar do ID manual.`);
      }
    } catch (e) { console.error('Erro ao resolver pagamento real do Checkout Asaas:', e.message); }
  }
  // Debita o crédito de indicação usado nesse pedido — só agora que o pagamento foi confirmado de verdade,
  // pra não descontar crédito de um pagamento que acabe sendo recusado.
  if (pedido.creditoAplicado > 0 && pedido.compradorUserId) {
    const comprador = db.users.find(u => u.id === pedido.compradorUserId);
    if (comprador) { comprador.saldoCredito = Math.max(0, (comprador.saldoCredito || 0) - pedido.creditoAplicado); saveDB(db); }
  }
  const ev = EVENTOS.find(e => e.id === pedido.eventoId);
  if (ev) {
    // Se a reserva já tinha sido liberada antes (ex: pedido foi marcado "expirado" cedo demais, mas
    // o pagamento acabou confirmando depois), precisamos contar a vaga de novo — senão o lote fica
    // com a contagem de vendidos desatualizada, mesmo com o ingresso gerado corretamente.
    if (pedido.reservaLiberada) {
      for (const it of (pedido.itens || [])) {
        if (it.assento) { if (!ev.assentosOcupados) ev.assentosOcupados = []; if (!ev.assentosOcupados.includes(it.assento)) ev.assentosOcupados.push(it.assento); }
        else { const lote = ev.lotes.find(l => l.id === it.loteId); if (lote) lote.vendidos = (lote.vendidos || 0) + it.qtd * pessoasPorUnidadeLote(lote.nome); }
      }
      pedido.reservaLiberada = false;
    }
    const cupomObj = pedido.cupomUsado ? ev.cupons.find(c => c.codigo === pedido.cupomUsado) : null;
    const promoterObj = pedido.promoterRef ? ev.promoters.find(p => p.id === pedido.promoterRef) : null;
    gerarTicketsEAtualizar(ev, pedido, cupomObj, promoterObj);
    persistEventos();
    pedido.emailEnviado = await enviarEmailIngressos(pedido, ev, baseUrl);
  }
  persistPedidos();
  // Programa de indicação: concede crédito na PRIMEIRA compra de verdade (paga) do indicado
  if (pedido.compradorUserId && pedido.valorIngressos > 0) {
    await concederCreditoIndicacao(pedido.compradorUserId, baseUrl).catch(e => console.error('Erro ao conceder crédito de indicação:', e.message));
  }
}

const CREDITO_INDICACAO_VALOR = 10; // R$10 pra cada lado — ajustável aqui
async function concederCreditoIndicacao(compradorUserId, baseUrl) {
  const comprador = db.users.find(u => u.id === compradorUserId);
  if (!comprador || !comprador.indicadoPor || comprador.boasVindasCreditoConcedido) return;
  const indicador = db.users.find(u => u.id === comprador.indicadoPor);
  if (!indicador) return;
  comprador.boasVindasCreditoConcedido = true;
  comprador.saldoCredito = (comprador.saldoCredito || 0) + CREDITO_INDICACAO_VALOR;
  indicador.saldoCredito = (indicador.saldoCredito || 0) + CREDITO_INDICACAO_VALOR;
  saveDB(db);
  console.log(`Crédito de indicação concedido: ${comprador.email} e ${indicador.email} ganharam R$${CREDITO_INDICACAO_VALOR} cada.`);
  const htmlComprador = `<div style="background:#0F0E0C;padding:32px 20px;font-family:Arial,sans-serif;color:#F0EDE8;"><div style="max-width:480px;margin:0 auto;">
    <div style="margin-bottom:20px;"><img src="${baseUrl}/logo-header.png" alt="Lota" height="28" style="vertical-align:middle;margin-right:8px"><span style="font-size:20px;font-weight:800;color:#C47B14;vertical-align:middle;">Lota</span></div>
    <p style="font-size:14px;">Você ganhou <strong style="color:#4ADE80">R$ ${CREDITO_INDICACAO_VALOR.toFixed(2)}</strong> de crédito por ter usado um código de indicação na sua primeira compra!</p>
    <p style="font-size:12px;color:#A09880;margin-top:10px;">Use esse crédito na sua próxima compra na Lota.</p>
    </div></div>`;
  const htmlIndicador = `<div style="background:#0F0E0C;padding:32px 20px;font-family:Arial,sans-serif;color:#F0EDE8;"><div style="max-width:480px;margin:0 auto;">
    <div style="margin-bottom:20px;"><img src="${baseUrl}/logo-header.png" alt="Lota" height="28" style="vertical-align:middle;margin-right:8px"><span style="font-size:20px;font-weight:800;color:#C47B14;vertical-align:middle;">Lota</span></div>
    <p style="font-size:14px;">${esc(comprador.nome)}, que você indicou, fez a primeira compra! Você ganhou <strong style="color:#4ADE80">R$ ${CREDITO_INDICACAO_VALOR.toFixed(2)}</strong> de crédito.</p>
    <p style="font-size:12px;color:#A09880;margin-top:10px;">Continue indicando amigos pra ganhar mais créditos.</p>
    </div></div>`;
  await enviarEmailGenerico(comprador.email, 'Você ganhou crédito na Lota! 🎉', htmlComprador);
  await enviarEmailGenerico(indicador.email, 'Sua indicação rendeu crédito! 🎉', htmlIndicador);
}

app.post('/api/mp/webhook', async (req, res) => {
  try {
    // O Mercado Pago pode notificar em dois formatos diferentes:
    // novo:  type=payment  & data.id=X   (no corpo JSON ou na query)
    // antigo (IPN): topic=payment & id=X (só na query)
    const paymentId = req.body?.data?.id || req.query['data.id'] || (req.query.topic === 'payment' ? req.query.id : null);
    const isPaymentNotif = req.body?.type === 'payment' || req.query.type === 'payment' || req.query.topic === 'payment';
    if (!isPaymentNotif || !paymentId) return res.sendStatus(200);
    const { ped: pedidoId, recarga: recargaId } = req.query;
    if (!MP_PLATFORM_TOKEN) return res.sendStatus(200);

    const payResp = await fetch(`${MP_API}/v1/payments/${paymentId}`, { headers: { 'Authorization': `Bearer ${MP_PLATFORM_TOKEN}` } });
    const payment = await payResp.json();
    if (!payResp.ok) return res.sendStatus(200);

    // Recarga de saldo do bar — fluxo separado dos pedidos de ingresso normais
    if (recargaId) {
      const recarga = CONSUMOS_BAR.find(c => c.id === recargaId && c.tipo === 'recarga');
      if (recarga && recarga.status === 'pendente' && payment.status === 'approved') {
        recarga.status = 'pago';
        persistConsumosBar();
      }
      return res.sendStatus(200);
    }

    // Se o pedidoId não veio na URL (por algum motivo), localizamos pelo external_reference do próprio pagamento
    const pedido = PEDIDOS.find(p => p.id === (pedidoId || payment.external_reference));
    if (!pedido) { console.error(`[Webhook MP] ⚠️ Pagamento ${paymentId} (status: ${payment.status}) não corresponde a nenhum pedido conhecido (ped=${pedidoId||'ausente'}, external_reference=${payment.external_reference||'ausente'}).`); return res.sendStatus(200); }

    if (payment.status === 'approved' && pedido.status !== 'pago') {
      const hostW = req.get('host'); const protoW = req.get('x-forwarded-proto') || 'https';
      // IMPORTANTE: não usamos "await" aqui de propósito. Descobrimos que gerar o PDF e enviar o
      // e-mail (dentro dessa função) pode demorar alguns segundos — tempo suficiente pro Mercado
      // Pago considerar a entrega do webhook como "falhou" por demora, mesmo o pagamento sendo
      // processado corretamente. Por isso respondemos com sucesso imediatamente, e deixamos a
      // geração do ingresso e o envio do e-mail continuarem rodando em segundo plano.
      processarPagamentoAprovado(pedido, paymentId, `${protoW}://${hostW}`)
        .then(() => console.log(`[Webhook MP] Pedido ${pedido.id} processado com sucesso em segundo plano.`))
        .catch(e => console.error(`[Webhook MP] Erro ao processar pedido ${pedido.id} em segundo plano:`, e.message));
    } else if (['rejected','cancelled'].includes(payment.status) && pedido.status === 'pendente') {
      pedido.mpPaymentId = String(paymentId);
      pedido.status = 'recusado';
      const evR = EVENTOS.find(e => e.id === pedido.eventoId);
      if (evR) liberarReservaPedido(pedido, evR);
      persistPedidos();
    } else if (['refunded','charged_back'].includes(payment.status) && pedido.status === 'pago') {
      // Estorno feito direto no site/app do Mercado Pago (não pelo botão da nossa plataforma) —
      // sem isso, o relatório de vendas ficava desatualizado, mostrando a venda como se ainda valesse.
      const ev = EVENTOS.find(e => e.id === pedido.eventoId);
      if (ev) { marcarPedidoComoReembolsado(pedido, ev); persistPedidos(); persistEventos(); console.log(`Estorno externo detectado e sincronizado — pedido ${pedido.id}, pagamento ${paymentId}`); }
    }
    res.sendStatus(200);
  } catch(e) { console.error('Erro no webhook do Mercado Pago:', e.message); res.sendStatus(200); }
});

// Webhook do Asaas — configurado uma vez direto no painel deles (Integrações > Webhooks),
// apontando pra: SEU-DOMINIO/api/asaas/webhook
app.post('/api/asaas/webhook', async (req, res) => {
  try {
    // Verifica o token de autenticação do webhook, se configurado — o Asaas envia isso no header
    // "asaas-access-token". Se ainda não configuramos ASAAS_WEBHOOK_TOKEN no servidor, seguimos sem
    // bloquear (pra não quebrar quem ainda não migrou), mas o recomendado é sempre configurar.
    if (ASAAS_WEBHOOK_TOKEN && req.headers['asaas-access-token'] !== ASAAS_WEBHOOK_TOKEN) {
      console.error('Webhook do Asaas recebido com token de autenticação inválido ou ausente.');
      return res.sendStatus(401);
    }
    const evento = req.body?.event;
    const payment = req.body?.payment;
    const checkout = req.body?.checkout;

    // Eventos de CHECKOUT (CHECKOUT_PAID, etc) — formato separado dos eventos de pagamento comuns,
    // usado quando a cobrança nasce do Asaas Checkout (nosso caso, desde a migração pro checkout
    // hospedado com opção de parcelamento).
    if (checkout && checkout.externalReference) {
      // Recarga de saldo do bar — identificada pelo prefixo "recarga:" no externalReference
      if (checkout.externalReference.startsWith('recarga:')) {
        const recargaId = checkout.externalReference.slice('recarga:'.length);
        const recarga = CONSUMOS_BAR.find(c => c.id === recargaId && c.tipo === 'recarga');
        if (recarga && recarga.status === 'pendente' && evento === 'CHECKOUT_PAID') {
          recarga.status = 'pago';
          persistConsumosBar();
        } else if (!recarga) {
          console.error(`[Webhook Asaas] Recarga "${recargaId}" não encontrada (evento: ${evento}).`);
        }
        return res.sendStatus(200);
      }
      const pedido = PEDIDOS.find(p => p.id === checkout.externalReference);
      if (pedido) {
        if (evento === 'CHECKOUT_PAID' && pedido.status !== 'pago') {
          const proto = req.get('x-forwarded-proto') || 'https';
          // Sem "await" de propósito — ver explicação detalhada no webhook do Mercado Pago, mesma
          // causa: gerar PDF + enviar e-mail demorava o suficiente pro Asaas considerar a entrega
          // como falha, mesmo o pagamento sendo reconhecido corretamente do nosso lado.
          processarPagamentoAprovado(pedido, checkout.id, `${proto}://${req.get('host')}`)
            .then(() => console.log(`[Webhook Asaas] Pedido ${pedido.id} processado com sucesso em segundo plano (via CHECKOUT_PAID).`))
            .catch(e => console.error(`[Webhook Asaas] Erro ao processar pedido ${pedido.id} em segundo plano:`, e.message));
          console.log(`[Webhook Asaas] Pedido ${pedido.id} confirmado como pago via CHECKOUT_PAID.`);
        } else if (['CHECKOUT_CANCELED', 'CHECKOUT_EXPIRED'].includes(evento) && pedido.status === 'pendente') {
          pedido.status = 'recusado';
          const evR = EVENTOS.find(e => e.id === pedido.eventoId);
          if (evR) liberarReservaPedido(pedido, evR);
          persistPedidos();
        }
      } else {
        // Isso NUNCA deveria acontecer se o pedido foi gravado corretamente antes do comprador ser
        // redirecionado — se aparecer no log, é sinal de que o pedido se perdeu antes do webhook
        // chegar (por isso a gravação da criação do pedido virou síncrona).
        console.error(`[Webhook Asaas] ⚠️ Checkout "${checkout.externalReference}" (evento: ${evento}) não corresponde a nenhum pedido conhecido — pedido pode ter se perdido antes da confirmação.`);
      }
      return res.sendStatus(200);
    }

    if (!payment) { console.log('[Webhook Asaas] Evento recebido sem payment (evento:', evento, ') — ignorado.'); return res.sendStatus(200); }
    // Em alguns casos o Asaas manda o pagamento com "externalReference" nulo (mesmo vindo de um
    // Checkout que tinha isso preenchido) — quando isso acontece, usamos o "checkoutSession" como
    // identificador alternativo, já que é o ID do checkout que guardamos em pedido.mpPaymentId
    // enquanto o pedido ainda está pendente.
    if (payment.externalReference && payment.externalReference.startsWith('recarga:')) {
      const recargaId = payment.externalReference.slice('recarga:'.length);
      const recarga = CONSUMOS_BAR.find(c => c.id === recargaId && c.tipo === 'recarga');
      if (recarga && recarga.status === 'pendente' && ['PAYMENT_CONFIRMED', 'PAYMENT_RECEIVED'].includes(evento)) {
        recarga.status = 'pago';
        persistConsumosBar();
      }
      return res.sendStatus(200);
    }
    let pedido = payment.externalReference ? PEDIDOS.find(p => p.id === payment.externalReference) : null;
    if (!pedido && payment.checkoutSession) pedido = PEDIDOS.find(p => p.mpPaymentId === payment.checkoutSession);
    if (!pedido) { console.error(`[Webhook Asaas] ⚠️ Payment "${payment.id}" (externalReference: ${payment.externalReference}, checkoutSession: ${payment.checkoutSession}, evento: ${evento}) não corresponde a nenhum pedido conhecido.`); return res.sendStatus(200); }

    if (['PAYMENT_CONFIRMED', 'PAYMENT_RECEIVED'].includes(evento) && pedido.status !== 'pago') {
      const proto = req.get('x-forwarded-proto') || 'https';
      processarPagamentoAprovado(pedido, payment.id, `${proto}://${req.get('host')}`)
        .then(() => console.log(`[Webhook Asaas] Pedido ${pedido.id} processado com sucesso em segundo plano (via ${evento}).`))
        .catch(e => console.error(`[Webhook Asaas] Erro ao processar pedido ${pedido.id} em segundo plano:`, e.message));
    } else if (['PAYMENT_REPROVED_BY_RISK_ANALYSIS', 'PAYMENT_CREDIT_CARD_CAPTURE_REFUSED', 'PAYMENT_DELETED'].includes(evento) && pedido.status === 'pendente') {
      pedido.mpPaymentId = String(payment.id);
      pedido.status = 'recusado';
      const evR = EVENTOS.find(e => e.id === pedido.eventoId);
      if (evR) liberarReservaPedido(pedido, evR);
      persistPedidos();
    } else if (['PAYMENT_REFUNDED', 'PAYMENT_CHARGEBACK_REQUESTED', 'PAYMENT_CHARGEBACK_DISPUTE'].includes(evento) && pedido.status === 'pago') {
      const ev = EVENTOS.find(e => e.id === pedido.eventoId);
      if (ev) { marcarPedidoComoReembolsado(pedido, ev); persistPedidos(); persistEventos(); console.log(`Estorno externo (Asaas) detectado e sincronizado — pedido ${pedido.id}, cobrança ${payment.id}`); }
    }
    res.sendStatus(200);
  } catch (e) { console.error('Erro no webhook do Asaas:', e.message); res.sendStatus(200); }
});

app.get('/api/public/pedido/:pedidoId', rateLimit(60000, 60), async (req, res) => {
  const pedido = PEDIDOS.find(p => p.id === req.params.pedidoId);
  if (!pedido) return res.status(404).json({ error: 'Pedido não encontrado.' });
  // Rede de segurança: se o webhook não chegou por algum motivo (comum em PIX, que pode demorar
  // pra confirmar), consultamos ativamente o pagamento pelo ID que já guardamos.
  if (['pendente','expirado'].includes(pedido.status) && pedido.mpPaymentId && pedido.provedorPagamento === 'asaas' && ASAAS_API_KEY) {
    try {
      // Prioridade 1: o status do próprio Checkout — sinal mais confiável (descobrimos que o filtro
      // "checkoutSession" às vezes não retorna resultado mesmo com o pagamento já confirmado do lado
      // do Asaas, mesmo aparecendo como "Pago" no painel deles).
      const consulta = await asaasFetch(`/checkouts/${pedido.mpPaymentId}`);
      if (consulta.ok && consulta.data.status === 'PAID') {
        const protoF = req.get('x-forwarded-proto') || 'https';
        await processarPagamentoAprovado(pedido, pedido.mpPaymentId, `${protoF}://${req.get('host')}`);
      } else if (consulta.ok && ['CANCELED','EXPIRED'].includes(consulta.data.status)) {
        pedido.status = 'recusado';
        const evR = EVENTOS.find(e => e.id === pedido.eventoId);
        if (evR) liberarReservaPedido(pedido, evR);
        persistPedidos();
      } else {
        // Reforço: tenta também pelo filtro antigo, caso o Checkout já não exista mais como registro ativo
        const buscaPagamento = await asaasFetch(`/payments?checkoutSession=${pedido.mpPaymentId}`);
        const pagamentoReal = (buscaPagamento.ok && buscaPagamento.data.data && buscaPagamento.data.data[0]) || null;
        if (pagamentoReal && ['CONFIRMED', 'RECEIVED'].includes(pagamentoReal.status)) {
          const protoF = req.get('x-forwarded-proto') || 'https';
          await processarPagamentoAprovado(pedido, pedido.mpPaymentId, `${protoF}://${req.get('host')}`);
        }
      }
    } catch(e) { console.error('Erro ao verificar pagamento (Asaas):', e.message); }
  } else if (['pendente','expirado'].includes(pedido.status) && pedido.mpPaymentId && pedido.provedorPagamento !== 'asaas' && MP_PLATFORM_TOKEN) {
    try {
      const payResp = await fetch(`${MP_API}/v1/payments/${pedido.mpPaymentId}`, { headers: { 'Authorization': `Bearer ${MP_PLATFORM_TOKEN}` } });
      const payData = await payResp.json();
      if (payResp.ok) {
        if (payData.status === 'approved') {
          const hostF = req.get('host'); const protoF = req.get('x-forwarded-proto') || 'https';
          await processarPagamentoAprovado(pedido, payData.id, `${protoF}://${hostF}`);
        }
        else if (['rejected','cancelled'].includes(payData.status)) {
          pedido.status = 'recusado';
          const evR = EVENTOS.find(e => e.id === pedido.eventoId);
          if (evR) liberarReservaPedido(pedido, evR);
          persistPedidos();
        }
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

// ── TRANSFERIR INGRESSO ──
app.post('/api/public/pedido/:pedidoId/ticket/:codigo/transferir', rateLimit(60000, 10), async (req, res) => {
  try {
    const pedido = PEDIDOS.find(p => p.id === req.params.pedidoId);
    if (!pedido) return res.status(404).json({ error: 'Pedido não encontrado.' });
    if (pedido.status !== 'pago') return res.status(400).json({ error: 'Este pedido ainda não foi confirmado.' });
    const ticket = (pedido.tickets || []).find(t => t.codigo === req.params.codigo);
    if (!ticket) return res.status(404).json({ error: 'Ingresso não encontrado.' });
    if (ticket.cancelado) return res.status(400).json({ error: 'Este ingresso foi cancelado e não pode ser transferido.' });
    if (ticket.usado) return res.status(400).json({ error: 'Este ingresso já foi utilizado na entrada e não pode mais ser transferido.' });
    const { novoNome, novoEmail } = req.body;
    const nomeLimpo = sanitize(novoNome || '', 100);
    const emailLimpo = sanitize(novoEmail || '', 150).toLowerCase();
    if (!nomeLimpo || !emailLimpo) return res.status(400).json({ error: 'Preencha nome e e-mail de quem vai receber o ingresso.' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailLimpo)) return res.status(400).json({ error: 'E-mail inválido.' });

    const nomeAntigo = ticket.titularNome || pedido.comprador?.nome || '';
    const emailAntigo = ticket.titularEmail || pedido.comprador?.email || '';
    ticket.titularNome = nomeLimpo;
    ticket.titularEmail = emailLimpo;
    persistPedidos();

    const ev = EVENTOS.find(e => e.id === pedido.eventoId);
    if (ev) {
      const proto = req.get('x-forwarded-proto') || 'https';
      const baseUrl = `${proto}://${req.get('host')}`;
      const linkPdf = `${baseUrl}/api/public/pedido/${pedido.id}/pdf`;
      // Avisa quem recebeu o ingresso
      const htmlNovo = `<div style="background:#0F0E0C;padding:32px 20px;font-family:Arial,sans-serif;color:#F0EDE8;"><div style="max-width:480px;margin:0 auto;">
        <div style="margin-bottom:20px;"><img src="${baseUrl}/logo-header.png" alt="Lota" height="28" style="vertical-align:middle;margin-right:8px"><span style="font-size:20px;font-weight:800;color:#C47B14;vertical-align:middle;">Lota</span></div>
        <p style="font-size:13px;color:#A09880;margin-bottom:6px;">${esc(nomeAntigo)} transferiu um ingresso pra você</p>
        <h2 style="font-size:20px;font-weight:800;color:#fff;margin-bottom:16px;">${esc(ev.nome)}</h2>
        <div style="border:1px solid #2A2822;border-radius:10px;padding:16px;margin-bottom:16px;background:#161410;">
          <img src="https://api.qrserver.com/v1/create-qr-code/?size=120x120&data=${encodeURIComponent(ticket.codigo)}" width="90" height="90" style="border-radius:8px;background:#fff;padding:4px" />
          <div style="font-family:monospace;font-weight:700;color:#C47B14;font-size:13px;margin-top:8px;">${ticket.codigo}</div>
        </div>
        <a href="${linkPdf}" style="display:inline-block;background:#E8961A;color:#18160F;font-weight:800;padding:12px 24px;border-radius:9px;text-decoration:none;font-size:14px;">Abrir ingresso em PDF →</a>
        <p style="font-size:11px;color:#605848;margin-top:20px;">Apresente o QR Code na entrada do evento.</p>
        </div></div>`;
      await enviarEmailGenerico(emailLimpo, `Você recebeu um ingresso — ${ev.nome}`, htmlNovo);
      // Avisa quem transferiu, confirmando
      if (emailAntigo) {
        const htmlAntigo = `<div style="background:#0F0E0C;padding:32px 20px;font-family:Arial,sans-serif;color:#F0EDE8;"><div style="max-width:480px;margin:0 auto;">
          <div style="margin-bottom:20px;"><img src="${baseUrl}/logo-header.png" alt="Lota" height="28" style="vertical-align:middle;margin-right:8px"><span style="font-size:20px;font-weight:800;color:#C47B14;vertical-align:middle;">Lota</span></div>
          <p style="font-size:14px;color:#F0EDE8;">O ingresso <strong style="color:#E8961A">${ticket.codigo}</strong> pra <strong>${esc(ev.nome)}</strong> foi transferido pra ${esc(nomeLimpo)} (${esc(emailLimpo)}) com sucesso.</p>
          <p style="font-size:11px;color:#605848;margin-top:16px;">Se você não fez essa transferência, entre em contato com o suporte imediatamente.</p>
          </div></div>`;
        await enviarEmailGenerico(emailAntigo, `Ingresso transferido — ${ev.nome}`, htmlAntigo);
      }
    }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Rota pública amigável /e/:slug e /o/:slug
app.get('/e/:slug', (req, res) => {
  const p = path.join(PUBLIC_DIR, 'evento.html');
  if (!fs.existsSync(p)) return res.status(404).send('Não encontrado.');
  try {
    const ref = db.ticketSlugs[req.params.slug];
    const ev = ref ? EVENTOS.find(e => e.id === ref.eventoId) : null;
    let html = fs.readFileSync(p, 'utf8');
    if (ev && ev.status === 'publicado') {
      const proto = req.get('x-forwarded-proto') || 'https';
      const baseUrl = `${proto}://${req.get('host')}`;
      const pageUrl = `${baseUrl}/e/${ev.slug}`;
      const imageUrl = ev.imagemCapa ? `${baseUrl}/api/public/eventos/${ev.slug}/imagem` : `${baseUrl}/favicon.png`;
      const descricaoLimpa = sanitize(ev.descricao || `Ingressos para ${ev.nome}`, 200).replace(/\n/g, ' ');
      const dataFormatada = ev.dataEvento ? parseDataLocal(ev.dataEvento).toLocaleDateString('pt-BR') : '';
      const tituloOg = `${ev.nome}${dataFormatada ? ' — ' + dataFormatada : ''}`;
      // Dados estruturados (Schema.org Event) — ajuda o Google a entender que essa página é um
      // evento de verdade (com data, local e preço), podendo exibir isso de forma destacada na
      // busca, inclusive na aba "Eventos" do Google, não só como um link comum.
      const menorPreco = ev.lotes && ev.lotes.length ? Math.min(...ev.lotes.filter(l => l.ativo).map(l => l.preco)) : 0;
      const dataISO = ev.dataEvento ? `${ev.dataEvento}${ev.horaEvento ? 'T' + ev.horaEvento : 'T00:00'}:00-03:00` : undefined;
      const organizadorEv = db.users.find(u => u.id === ev.organizadorId);
      const schemaEvento = {
        '@context': 'https://schema.org', '@type': 'Event',
        name: ev.nome, description: descricaoLimpa, image: [imageUrl],
        startDate: dataISO, eventStatus: 'https://schema.org/EventScheduled',
        eventAttendanceMode: 'https://schema.org/OfflineEventAttendanceMode',
        location: { '@type': 'Place', name: ev.local || ev.nome, address: { '@type': 'PostalAddress', addressLocality: ev.cidade || '', addressCountry: 'BR' } },
        offers: { '@type': 'Offer', url: pageUrl, price: menorPreco, priceCurrency: 'BRL', availability: 'https://schema.org/InStock', validFrom: ev.createdAt },
        organizer: organizadorEv ? { '@type': 'Organization', name: organizadorEv.nomePublico || organizadorEv.nome } : undefined
      };
      const metaTags = `
    <meta property="og:type" content="website">
    <meta property="og:title" content="${esc(tituloOg)}">
    <meta property="og:description" content="${esc(descricaoLimpa)}">
    <meta property="og:image" content="${imageUrl}">
    <meta property="og:url" content="${pageUrl}">
    <meta property="og:site_name" content="Lota">
    <meta name="twitter:card" content="summary_large_image">
    <meta name="twitter:title" content="${esc(tituloOg)}">
    <meta name="twitter:description" content="${esc(descricaoLimpa)}">
    <meta name="twitter:image" content="${imageUrl}">
    <title>${esc(ev.nome)} — Lota</title>
    <script type="application/ld+json">${JSON.stringify(schemaEvento)}</script>`;
      // Substitui o <title> estático da página pelas tags dinâmicas (incluindo um novo <title>)
      html = html.replace(/<title>.*?<\/title>/i, metaTags);
    }
    res.send(html);
  } catch (e) {
    res.sendFile(p);
  }
});
app.get('/api/public/organizadores/:slug/imagem', (req, res) => {
  const user = db.users.find(u => u.organizadorSlug === req.params.slug);
  const img = user?.bannerUrl || user?.avatarUrl;
  if (!user || !img || !img.startsWith('data:image/')) return res.status(404).send('Sem imagem.');
  const match = img.match(/^data:(image\/\w+);base64,(.+)$/);
  if (!match) return res.status(404).send('Formato inválido.');
  const [, mime, base64Data] = match;
  res.setHeader('Content-Type', mime);
  res.setHeader('Cache-Control', 'public, max-age=86400');
  res.send(Buffer.from(base64Data, 'base64'));
});

app.get('/o/:slug', (req, res) => {
  const p = path.join(PUBLIC_DIR, 'organizador.html');
  if (!fs.existsSync(p)) return res.status(404).send('Não encontrado.');
  try {
    const user = db.users.find(u => u.organizadorSlug === req.params.slug);
    let html = fs.readFileSync(p, 'utf8');
    if (user) {
      const proto = req.get('x-forwarded-proto') || 'https';
      const baseUrl = `${proto}://${req.get('host')}`;
      const nomeExibicao = user.nomePublico || user.nome;
      const imageUrl = (user.bannerUrl || user.avatarUrl) ? `${baseUrl}/api/public/organizadores/${user.organizadorSlug}/imagem` : `${baseUrl}/favicon.png`;
      const bioLimpa = sanitize(user.bio || `Confira os eventos de ${nomeExibicao} na Lota`, 200).replace(/\n/g, ' ');
      const metaTags = `
    <meta property="og:type" content="profile">
    <meta property="og:title" content="${esc(nomeExibicao)}">
    <meta property="og:description" content="${esc(bioLimpa)}">
    <meta property="og:image" content="${imageUrl}">
    <meta property="og:url" content="${baseUrl}/o/${user.organizadorSlug}">
    <meta property="og:site_name" content="Lota">
    <meta name="twitter:card" content="summary_large_image">
    <meta name="twitter:title" content="${esc(nomeExibicao)}">
    <meta name="twitter:description" content="${esc(bioLimpa)}">
    <meta name="twitter:image" content="${imageUrl}">
    <title>${esc(nomeExibicao)} — Lota</title>`;
      html = html.replace(/<title>.*?<\/title>/i, metaTags);
    }
    res.send(html);
  } catch (e) {
    res.sendFile(p);
  }
});

// ── Páginas de cidade e categoria (SEO) — servem a home com meta tags específicas e já filtrada ──
function renderPaginaFiltrada(req, res, tipo, nomeReal, valorParaUrl) {
  const p = path.join(PUBLIC_DIR, 'index.html');
  if (!fs.existsSync(p)) return res.status(404).send('Não encontrado.');
  const proto = req.get('x-forwarded-proto') || 'https';
  const baseUrl = `${proto}://${req.get('host')}`;
  const tituloOg = tipo === 'cidade' ? `Eventos em ${nomeReal}` : `Eventos de ${nomeReal}`;
  const descricaoOg = tipo === 'cidade'
    ? `Confira os próximos eventos, shows e ingressos em ${nomeReal}. Compre com segurança pela Lota.`
    : `Encontre eventos de ${nomeReal.toLowerCase()} com ingressos disponíveis. Compre com segurança pela Lota.`;
  let html = fs.readFileSync(p, 'utf8');
  const metaTags = `
    <meta property="og:type" content="website">
    <meta property="og:title" content="${esc(tituloOg)}">
    <meta property="og:description" content="${esc(descricaoOg)}">
    <meta property="og:url" content="${baseUrl}${req.originalUrl}">
    <meta property="og:site_name" content="Lota">
    <title>${esc(tituloOg)} — Lota</title>`;
  html = html.replace(/<title>.*?<\/title>/i, metaTags);
  // Em vez de redirecionar via JS (o que causaria um recarregamento visível), injetamos o valor
  // direto numa variável global — o script da home já lê isso na inicialização, sem piscar a tela.
  html = html.replace('<script>', `<script>window.SEO_FILTRO_PRESET={tipo:${JSON.stringify(tipo)},valor:${JSON.stringify(nomeReal)}};</script>\n<script>`);
  res.send(html);
}
app.get('/eventos/cidade/:slug', (req, res) => {
  const eventosPublicados = EVENTOS.filter(e => e.status === 'publicado');
  const cidadeReal = eventosPublicados.map(e => e.cidade).find(c => c && slugify(c) === req.params.slug);
  if (!cidadeReal) return res.redirect('/');
  renderPaginaFiltrada(req, res, 'cidade', cidadeReal);
});
app.get('/eventos/categoria/:slug', (req, res) => {
  const eventosPublicados = EVENTOS.filter(e => e.status === 'publicado');
  const categoriaReal = eventosPublicados.map(e => e.categoria).find(c => c && slugify(c) === req.params.slug);
  if (!categoriaReal) return res.redirect('/');
  renderPaginaFiltrada(req, res, 'categoria', categoriaReal);
});

// ════════════════════════════════════════════════════════
// ADMIN (plataforma)
// ════════════════════════════════════════════════════════
app.get('/api/admin/marketplace-fee', auth, adminOnly, (req, res) => res.json({ feePercent: db.marketplaceFeePercent }));
app.patch('/api/admin/marketplace-fee', auth, adminOnly, (req, res) => {
  const v = parseFloat(req.body.feePercent);
  if (isNaN(v) || v < 0 || v > 50) return res.status(400).json({ error: 'Valor inválido (0-50%).' });
  const valorAnterior = db.marketplaceFeePercent;
  db.marketplaceFeePercent = v; saveDB(db);
  registrarAuditoria(req.user, 'alterou_comissao', { de: valorAnterior, para: v });
  res.json({ ok: true, feePercent: v });
});
app.get('/api/admin/provedor-pagamento', auth, adminOnly, (req, res) => res.json({
  provedor: db.provedorPagamento,
  mercadopagoConfigurado: !!MP_PLATFORM_TOKEN, asaasConfigurado: !!ASAAS_API_KEY
}));
app.patch('/api/admin/provedor-pagamento', auth, adminOnly, (req, res) => {
  const { provedor } = req.body;
  if (!['mercadopago', 'asaas'].includes(provedor)) return res.status(400).json({ error: 'Provedor inválido.' });
  if (provedor === 'mercadopago' && !MP_PLATFORM_TOKEN) return res.status(400).json({ error: 'MP_ACCESS_TOKEN não está configurado no servidor.' });
  if (provedor === 'asaas' && !ASAAS_API_KEY) return res.status(400).json({ error: 'ASAAS_API_KEY não está configurado no servidor.' });
  const anterior = db.provedorPagamento;
  db.provedorPagamento = provedor; saveDB(db);
  registrarAuditoria(req.user, 'trocou_provedor_pagamento', { de: anterior, para: provedor });
  res.json({ ok: true, provedor });
});

app.get('/api/admin/usuarios', auth, adminOnly, (req, res) => res.json({ usuarios: db.users.map(safe) }));

app.patch('/api/admin/usuarios/:id/ativo', auth, adminOnly, (req, res) => {
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'Usuário não encontrado.' });
  if (user.isAdmin) return res.status(400).json({ error: 'Não é possível desativar uma conta de administrador.' });
  user.ativo = !!req.body.ativo;
  saveDB(db);
  registrarAuditoria(req.user, user.ativo ? 'reativou_usuario' : 'desativou_usuario', { userId: user.id, userNome: user.nome, userEmail: user.email });
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

// Libera/revoga a possibilidade de solicitar antecipação de recebíveis — só produtores com
// contrato ativo com a Lota devem ter isso habilitado. Decisão manual do admin, produtor nenhum
// consegue ativar isso sozinho.
app.patch('/api/admin/usuarios/:id/pode-antecipar', auth, adminOnly, (req, res) => {
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'Usuário não encontrado.' });
  if (!user.isOrganizador) return res.status(400).json({ error: 'Somente produtores podem ter essa permissão.' });
  user.podeAntecipar = !!req.body.podeAntecipar;
  saveDB(db);
  registrarAuditoria(req.user, 'alterou_permissao_antecipacao', { produtorId: user.id, podeAntecipar: user.podeAntecipar });
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

// ── Visão detalhada por produtor — cada produtor com seus eventos, vendas por período, ticket
// médio e comissão. Usado na Visão Geral reorganizada, agrupando tudo por produtor em vez de uma
// lista solta de eventos ou usuários.
app.get('/api/admin/produtores-detalhado', auth, adminOnly, (req, res) => {
  const agora = Date.now();
  const limiteDiario = agora - 24 * 60 * 60 * 1000;
  const limiteSemanal = agora - 7 * 24 * 60 * 60 * 1000;
  const limiteSemestral = agora - 182 * 24 * 60 * 60 * 1000; // ~6 meses

  const calcularJanela = (pedidosPagos, limiteMs) => {
    const doPeriodo = pedidosPagos.filter(p => new Date(p.pagoEm || p.createdAt).getTime() >= limiteMs);
    const ingressos = doPeriodo.reduce((s, p) => s + (p.tickets?.length || 0), 0);
    const valorVendido = doPeriodo.reduce((s, p) => s + (p.valorIngressos !== undefined ? p.valorIngressos : p.total), 0);
    const comissao = doPeriodo.reduce((s, p) => s + (p.taxaAdministrativa !== undefined ? p.taxaAdministrativa : (p.marketplaceFee || 0)), 0);
    return { ingressos, valorVendido: Math.round(valorVendido * 100) / 100, comissao: Math.round(comissao * 100) / 100 };
  };

  const produtores = db.users.filter(u => u.isOrganizador && !u.isAdmin);
  const resultado = produtores.map(produtor => {
    const eventosDoProdutor = EVENTOS.filter(e => e.organizadorId === produtor.id);
    const eventosDetalhados = eventosDoProdutor.map(ev => {
      const pedidosPagos = PEDIDOS.filter(p => p.eventoId === ev.id && p.status === 'pago');
      const totalIngressos = pedidosPagos.reduce((s, p) => s + (p.tickets?.length || 0), 0);
      const totalVendido = pedidosPagos.reduce((s, p) => s + (p.valorIngressos !== undefined ? p.valorIngressos : p.total), 0);
      const totalComissao = pedidosPagos.reduce((s, p) => s + (p.taxaAdministrativa !== undefined ? p.taxaAdministrativa : (p.marketplaceFee || 0)), 0);
      return {
        eventoId: ev.id, eventoNome: ev.nome, status: ev.status,
        diario: calcularJanela(pedidosPagos, limiteDiario),
        semanal: calcularJanela(pedidosPagos, limiteSemanal),
        semestral: calcularJanela(pedidosPagos, limiteSemestral),
        totalIngressos, totalVendido: Math.round(totalVendido * 100) / 100,
        totalComissao: Math.round(totalComissao * 100) / 100,
        valorMedioIngresso: totalIngressos > 0 ? Math.round((totalVendido / totalIngressos) * 100) / 100 : 0
      };
    }).sort((a, b) => b.totalVendido - a.totalVendido);

    const totalVendidoProdutor = eventosDetalhados.reduce((s, e) => s + e.totalVendido, 0);
    const totalComissaoProdutor = eventosDetalhados.reduce((s, e) => s + e.totalComissao, 0);
    const totalIngressosProdutor = eventosDetalhados.reduce((s, e) => s + e.totalIngressos, 0);
    return {
      produtorId: produtor.id, produtorNome: produtor.nomePublico || produtor.nome, produtorEmail: produtor.email,
      eventos: eventosDetalhados,
      totalVendidoProdutor: Math.round(totalVendidoProdutor * 100) / 100,
      totalComissaoProdutor: Math.round(totalComissaoProdutor * 100) / 100,
      totalIngressosProdutor,
      valorMedioIngressoProdutor: totalIngressosProdutor > 0 ? Math.round((totalVendidoProdutor / totalIngressosProdutor) * 100) / 100 : 0
    };
  }).sort((a, b) => b.totalVendidoProdutor - a.totalVendidoProdutor); // do que mais vende pro que menos vende

  const totalGeralVendido = Math.round(resultado.reduce((s, p) => s + p.totalVendidoProdutor, 0) * 100) / 100;
  const totalGeralComissao = Math.round(resultado.reduce((s, p) => s + p.totalComissaoProdutor, 0) * 100) / 100;

  res.json({ produtores: resultado, totalGeralVendido, totalGeralComissao });
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
      receita, comissao, ingressos, totalPedidos: pedidosPagos.length, createdAt: ev.createdAt, destaque: !!ev.destaque
    };
  }).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json({ eventos: lista });
});

// Marca/desmarca um evento como "destaque" — aparece na seção de destaques da home, escolhida
// manualmente pelo admin (diferente da seção "mais vistos", que é automática).
app.patch('/api/admin/eventos/:id/destaque', auth, adminOnly, (req, res) => {
  const ev = EVENTOS.find(e => e.id === req.params.id);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  ev.destaque = !!req.body.destaque;
  persistEventos();
  res.json({ ok: true, destaque: ev.destaque });
});

app.get('/api/admin/eventos/:id', auth, adminOnly, (req, res) => {
  const ev = EVENTOS.find(e => e.id === req.params.id);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  const organizador = db.users.find(u => u.id === ev.organizadorId);
  const pedidos = PEDIDOS.filter(p => p.eventoId === ev.id);
  res.json({ evento: ev, organizador: organizador ? { nome: organizador.nomePublico || organizador.nome, email: organizador.email } : null, pedidos });
});

// ── RECUPERAÇÃO MANUAL DE PEDIDO (para casos de perda de dados) ──
// Recria um pedido "do zero" a partir de informações que o admin já confirmou existirem de verdade
// (ex: o pagamento aparece no extrato do Mercado Pago/Asaas, mas sumiu do nosso banco). Gera os
// ingressos e reenvia o e-mail de confirmação normalmente, como se a compra tivesse acabado de ser paga.
// Reenvio manual do e-mail com o ingresso (PDF) — útil quando o comprador avisa que não recebeu.
app.post('/api/admin/eventos/:id/pedidos/:pedidoId/reenviar-email', auth, adminOnly, async (req, res) => {
  const ev = EVENTOS.find(e => e.id === req.params.id);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  const pedido = PEDIDOS.find(p => p.id === req.params.pedidoId && p.eventoId === ev.id);
  if (!pedido) return res.status(404).json({ error: 'Pedido não encontrado.' });
  if (pedido.status !== 'pago') return res.status(400).json({ error: 'Só é possível reenviar o e-mail de pedidos pagos.' });
  const proto = req.get('x-forwarded-proto') || 'https';
  const baseUrl = `${proto}://${req.get('host')}`;
  const enviado = await enviarEmailIngressos(pedido, ev, baseUrl);
  pedido.emailEnviado = enviado;
  persistPedidos();
  if (!enviado) return res.status(500).json({ error: 'Não conseguimos enviar o e-mail agora. Confira os logs do servidor pra mais detalhes, ou baixe o PDF direto pela lista de pedidos.' });
  res.json({ ok: true });
});

// Corrige os dados do comprador de um pedido já existente — útil quando algo foi digitado errado
// (na compra normal, ou numa recuperação manual). Não mexe em itens/valores, só nos dados de contato.
app.patch('/api/admin/eventos/:id/pedidos/:pedidoId', auth, adminOnly, async (req, res) => {
  const ev = EVENTOS.find(e => e.id === req.params.id);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  const pedido = PEDIDOS.find(p => p.id === req.params.pedidoId && p.eventoId === ev.id);
  if (!pedido) return res.status(404).json({ error: 'Pedido não encontrado.' });
  const { nome, email, telefone, cpf, mpPaymentId } = req.body;
  const nomeLimpo = sanitize(nome || '', 100);
  const emailLimpo = sanitize(email || '', 150).toLowerCase();
  if (!nomeLimpo || !emailLimpo) return res.status(400).json({ error: 'Nome e e-mail são obrigatórios.' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailLimpo)) return res.status(400).json({ error: 'E-mail inválido.' });
  const emailAntigo = (pedido.comprador?.email || '').toLowerCase();
  pedido.comprador = {
    nome: nomeLimpo, email: emailLimpo,
    telefone: sanitize(telefone || '', 30), cpf: sanitize(cpf || '', 20).replace(/[^\d]/g, '')
  };
  // Os tickets guardam o nome/e-mail de quem recebe individualmente (pode ter sido transferido pra
  // outra pessoa depois da compra) — só atualizamos o titular dos ingressos que ainda pertencem ao
  // comprador original, sem sobrescrever quem já recebeu por transferência.
  (pedido.tickets || []).forEach(t => {
    if ((t.titularEmail || '').toLowerCase() === emailAntigo) { t.titularNome = nomeLimpo; t.titularEmail = emailLimpo; }
  });
  if (mpPaymentId !== undefined) pedido.mpPaymentId = mpPaymentId || pedido.mpPaymentId;
  persistPedidos();
  registrarAuditoria(req.user, 'editou_dados_pedido', { pedidoId: pedido.id, eventoId: ev.id, emailAnterior: emailAntigo, emailNovo: emailLimpo });
  res.json({ ok: true });
});

// Exclui um pedido definitivamente — útil pra corrigir um pedido criado a mais por engano (ex: na
// recuperação manual) ou pra limpar a lista de pedidos recusados/expirados que não interessam mais.
// Libera qualquer vaga/assento que ainda estivesse reservado em nome desse pedido antes de apagar.
app.delete('/api/admin/eventos/:id/pedidos/:pedidoId', auth, adminOnly, async (req, res) => {
  const ev = EVENTOS.find(e => e.id === req.params.id);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  const pedido = PEDIDOS.find(p => p.id === req.params.pedidoId && p.eventoId === ev.id);
  if (!pedido) return res.status(404).json({ error: 'Pedido não encontrado.' });
  if (pedido.status === 'pago' && !req.body.confirmarExclusaoPago) {
    return res.status(400).json({ error: 'Esse pedido está pago — confirme novamente se realmente quer excluir (isso não estorna o pagamento, só remove o registro daqui).', precisaConfirmar: true });
  }
  if (pedido.status !== 'reembolsado') liberarReservaPedido(pedido, ev);
  const idx = PEDIDOS.indexOf(pedido);
  PEDIDOS.splice(idx, 1);
  persistPedidos();
  registrarAuditoria(req.user, 'excluiu_pedido', { pedidoId: pedido.id, eventoId: ev.id, statusAnterior: pedido.status, compradorEmail: pedido.comprador?.email });
  res.json({ ok: true });
});

// Tenta vincular um pedido (que ainda não tem compradorUserId) a uma conta existente, procurando
// por e-mail — útil no admin pra diagnosticar/corrigir na hora por que um pedido não aparece em
// "Meus Ingressos" do cliente (só aparece se estiver vinculado, ou se o e-mail bater exatamente).
app.post('/api/admin/pedidos/:pedidoId/vincular-conta', auth, adminOnly, (req, res) => {
  const pedido = PEDIDOS.find(p => p.id === req.params.pedidoId);
  if (!pedido) return res.status(404).json({ error: 'Pedido não encontrado.' });
  const emailPedido = (pedido.comprador?.email || '').toLowerCase();
  if (!emailPedido) return res.status(400).json({ error: 'Esse pedido não tem e-mail cadastrado.' });
  const conta = db.users.find(u => u.email.toLowerCase() === emailPedido);
  if (!conta) return res.json({ vinculado: false });
  pedido.compradorUserId = conta.id;
  persistPedidos();
  registrarAuditoria(req.user, 'vinculou_pedido_manualmente', { pedidoId: pedido.id, contaId: conta.id, contaEmail: conta.email });
  res.json({ vinculado: true, contaEmail: conta.email });
});

app.post('/api/admin/eventos/:id/recuperar-pedido', auth, adminOnly, async (req, res) => {
  const ev = EVENTOS.find(e => e.id === req.params.id);
  if (!ev) return res.status(404).json({ error: 'Evento não encontrado.' });
  const { nome, email, telefone, cpf, itens, mpPaymentId, valorPago, provedorPagamento } = req.body;
  const nomeLimpo = sanitize(nome || '', 100);
  const emailLimpo = sanitize(email || '', 150).toLowerCase();
  const cpfLimpo = sanitize(cpf || '', 20).replace(/[^\d]/g, '');
  if (!nomeLimpo || !emailLimpo) return res.status(400).json({ error: 'Nome e e-mail são obrigatórios.' });
  if (!Array.isArray(itens) || !itens.length) return res.status(400).json({ error: 'Selecione ao menos um item (lote e quantidade).' });

  const itensDetalhados = [];
  let subtotal = 0;
  for (const it of itens) {
    const lote = ev.lotes.find(l => l.id === it.loteId);
    if (!lote) return res.status(400).json({ error: 'Lote não encontrado: ' + it.loteId });
    const qtd = it.assento ? 1 : Math.max(1, parseInt(it.qtd) || 1);
    itensDetalhados.push({ loteId: lote.id, qtd, precoUnit: lote.preco, loteNome: lote.nome, assento: it.assento || undefined });
    subtotal += lote.preco * qtd;
  }
  const valorIngressos = subtotal;
  const feePercent = db.marketplaceFeePercent || 10;
  const taxaAdministrativa = Math.round(valorIngressos * (feePercent / 100) * 100) / 100;
  const total = valorPago !== undefined && valorPago !== '' ? Number(valorPago) : Math.round((valorIngressos + taxaAdministrativa) * 100) / 100;

  const pedido = {
    id: uuidv4(), eventoId: ev.id, status: 'pago', pagoEm: new Date().toISOString(),
    comprador: { nome: nomeLimpo, email: emailLimpo, telefone: sanitize(telefone || '', 30), cpf: cpfLimpo },
    // Como o login já é obrigatório pra comprar, o cliente quase sempre já tem uma conta com esse
    // e-mail — vinculamos automaticamente, senão o ingresso recuperado nunca aparece em "Meus
    // Ingressos" (só chegaria por e-mail, que era exatamente o problema que estávamos corrigindo).
    compradorUserId: (db.users.find(u => u.email.toLowerCase() === emailLimpo)?.id) || null,
    provedorPagamento: provedorPagamento || 'mercadopago',
    itens: itensDetalhados, subtotal, desconto: 0, valorIngressos, taxaAdministrativa, creditoAplicado: 0, total,
    cupomUsado: null, promoterRef: null,
    mpPaymentId: mpPaymentId || 'RECUPERADO_MANUALMENTE', tickets: [], createdAt: new Date().toISOString(),
    recuperadoManualmente: true
  };

  // Reserva as vagas/assentos normalmente, como qualquer venda real
  for (const it of itensDetalhados) {
    const lote = ev.lotes.find(l => l.id === it.loteId);
    if (lote && !it.assento) lote.vendidos = (lote.vendidos || 0) + it.qtd * pessoasPorUnidadeLote(lote.nome);
    if (it.assento) { if (!ev.assentosOcupados) ev.assentosOcupados = []; ev.assentosOcupados.push(it.assento); }
  }
  gerarTicketsEAtualizar(ev, pedido, null, null);
  PEDIDOS.push(pedido);
  persistPedidos(); persistEventos();

  const proto = req.get('x-forwarded-proto') || 'https';
  const baseUrl = `${proto}://${req.get('host')}`;
  try { await enviarEmailIngressos(pedido, ev, baseUrl); } catch (e) { console.error('Erro ao reenviar e-mail do pedido recuperado:', e.message); }

  registrarAuditoria(req.user, 'recuperou_pedido_manualmente', { pedidoId: pedido.id, eventoId: ev.id, compradorEmail: pedido.comprador?.email, valor: pedido.total });
  res.json({ ok: true, pedidoId: pedido.id, ticketsGerados: pedido.tickets.length });
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

  // Por mês (últimos 12 meses, incluindo meses sem venda nenhuma — pro gráfico não ter buracos)
  const porMesMap = {};
  pedidosPagos.forEach(p => {
    const mes = (p.pagoEm || p.createdAt).slice(0, 7); // YYYY-MM
    if (!porMesMap[mes]) porMesMap[mes] = { receita: 0, comissao: 0, pedidos: 0 };
    porMesMap[mes].receita += p.total;
    porMesMap[mes].comissao += ((p.taxaAdministrativa !== undefined ? p.taxaAdministrativa : (p.marketplaceFee || 0)));
    porMesMap[mes].pedidos += 1;
  });
  const porMesTodos = Object.entries(porMesMap).map(([mes, d]) => ({ mes, ...d })).sort((a, b) => a.mes.localeCompare(b.mes));
  const ultimos12Meses = [];
  const dataRef = new Date();
  for (let i = 11; i >= 0; i--) {
    const d = new Date(dataRef.getFullYear(), dataRef.getMonth() - i, 1);
    const chave = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
    const encontrado = porMesMap[chave];
    ultimos12Meses.push({ mes: chave, receita: encontrado?.receita || 0, comissao: encontrado?.comissao || 0, pedidos: encontrado?.pedidos || 0 });
  }

  // Por dia (últimos 30 dias, incluindo dias sem venda)
  const porDiaMap = {};
  pedidosPagos.forEach(p => {
    const dia = (p.pagoEm || p.createdAt).slice(0, 10); // YYYY-MM-DD
    if (!porDiaMap[dia]) porDiaMap[dia] = { receita: 0, comissao: 0, pedidos: 0 };
    porDiaMap[dia].receita += p.total;
    porDiaMap[dia].comissao += ((p.taxaAdministrativa !== undefined ? p.taxaAdministrativa : (p.marketplaceFee || 0)));
    porDiaMap[dia].pedidos += 1;
  });
  const ultimos30Dias = [];
  for (let i = 29; i >= 0; i--) {
    const d = new Date(dataRef.getTime() - i * 24 * 60 * 60 * 1000);
    const chave = d.toISOString().slice(0, 10);
    const encontrado = porDiaMap[chave];
    ultimos30Dias.push({ dia: chave, receita: encontrado?.receita || 0, comissao: encontrado?.comissao || 0, pedidos: encontrado?.pedidos || 0 });
  }

  res.json({ totalReceita, totalComissao, totalPedidos: pedidosPagos.length, porEvento, porMes: porMesTodos, ultimos12Meses, ultimos30Dias });
});

app.get('/api/admin/financeiro.csv', auth, adminOnly, (req, res) => {
  const pedidosPagos = PEDIDOS.filter(p => p.status === 'pago');
  const feePercent = db.marketplaceFeePercent || 10;
  const linhas = [
    ['RELATÓRIO FINANCEIRO — LOTA'],
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
    status: 'ok', app: 'Lota', users: db.users.length, eventos: EVENTOS.length,
    provedor_pagamento_ativo: db.provedorPagamento,
    mercadopago: MP_PLATFORM_TOKEN ? '✅' : '❌ (configure MP_ACCESS_TOKEN)',
    mercadopago_chave_publica: MP_PUBLIC_KEY ? '✅' : '❌ (configure MP_PUBLIC_KEY — sem isso, o formulário de cartão não aparece no checkout)',
    suporte_email: SUPORTE_EMAIL ? `✅ (${SUPORTE_EMAIL})` : '❌ (configure SUPORTE_EMAIL — sem isso, mensagens do formulário de contato não geram e-mail de notificação)',
    asaas: ASAAS_API_KEY ? `✅ (${ASAAS_SANDBOX ? 'sandbox' : 'produção'})` : '❌ (configure ASAAS_API_KEY)',
    asaas_webhook_token: ASAAS_WEBHOOK_TOKEN ? '✅ configurado' : '⚠️ não configurado (recomendado configurar ASAAS_WEBHOOK_TOKEN)',
    criptografia_cpf: ENCRYPTION_KEY ? '✅ ativa' : '⚠️ não configurada (recomendado configurar ENCRYPTION_KEY)',
    backup_automatico: fs.existsSync(BACKUP_DIR) ? `✅ ativo (${fs.readdirSync(BACKUP_DIR).length} backup(s) guardado(s))` : '⏳ ainda não rodou (primeiro backup ocorre 1 min após o servidor iniciar)',
    backup_por_email: (SUPORTE_EMAIL || db.users.find(u => u.isAdmin)?.email) ? `✅ enviado pra ${SUPORTE_EMAIL || db.users.find(u => u.isAdmin)?.email}` : '⚠️ sem destinatário configurado (configure SUPORTE_EMAIL)',
    resend_email: !!RESEND_API_KEY ? '✅' : '❌ (configure RESEND_API_KEY)',
    armazenamento_persistente: DATA_DIR === '/data' ? '✅ (Volume configurado — dados seguros em deploys)' : '❌ PERIGO: sem Volume — dados serão perdidos no próximo deploy!',
    data_dir: DATA_DIR,
    uptime: Math.round(process.uptime()) + 's'
  });
});

// ── SEO: sitemap.xml e robots.txt ──
app.get('/robots.txt', (req, res) => {
  const proto = req.get('x-forwarded-proto') || 'https';
  const baseUrl = `${proto}://${req.get('host')}`;
  res.type('text/plain').send(
`User-agent: *
Allow: /
Disallow: /api/
Disallow: /painel.html
Disallow: /admin.html
Disallow: /meus-ingressos.html

Sitemap: ${baseUrl}/sitemap.xml`
  );
});

app.get('/sitemap.xml', (req, res) => {
  const proto = req.get('x-forwarded-proto') || 'https';
  const baseUrl = `${proto}://${req.get('host')}`;
  const paginasFixas = ['', 'sobre-nos.html', 'termos.html', 'privacidade.html'];
  const eventosPublicados = EVENTOS.filter(e => e.status === 'publicado');
  const cidadesUnicas = [...new Set(eventosPublicados.map(e => e.cidade).filter(Boolean))];
  const categoriasUnicas = [...new Set(eventosPublicados.map(e => e.categoria).filter(Boolean))];

  let xml = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n';
  paginasFixas.forEach(p => { xml += `  <url><loc>${baseUrl}/${p}</loc><changefreq>daily</changefreq><priority>${p === '' ? '1.0' : '0.5'}</priority></url>\n`; });
  eventosPublicados.forEach(ev => {
    xml += `  <url><loc>${baseUrl}/e/${ev.slug}</loc><lastmod>${(ev.updatedAt || ev.createdAt).slice(0, 10)}</lastmod><changefreq>daily</changefreq><priority>0.9</priority></url>\n`;
  });
  cidadesUnicas.forEach(cidade => {
    xml += `  <url><loc>${baseUrl}/eventos/cidade/${encodeURIComponent(slugify(cidade))}</loc><changefreq>daily</changefreq><priority>0.7</priority></url>\n`;
  });
  categoriasUnicas.forEach(categoria => {
    xml += `  <url><loc>${baseUrl}/eventos/categoria/${encodeURIComponent(slugify(categoria))}</loc><changefreq>daily</changefreq><priority>0.7</priority></url>\n`;
  });
  xml += '</urlset>';
  res.type('application/xml').send(xml);
});

app.get('*', (req, res) => {
  const idx = path.join(PUBLIC_DIR, 'index.html');
  if (fs.existsSync(idx)) return res.sendFile(idx);
  res.status(500).send('index.html não encontrado.');
});

// ── BACKUP AUTOMÁTICO ──
// Guarda uma cópia de segurança dos dados (usuários, eventos, pedidos, mensagens) todos os dias,
// numa subpasta separada dentro do mesmo Volume persistente. Mantém os últimos 7 dias, apagando
// backups mais antigos automaticamente. Isso é uma proteção adicional contra erro humano (por
// exemplo, apagar um evento sem querer) — não substitui um backup fora do Volume pra casos de
// perda total da infraestrutura, mas já cobre a maioria dos cenários do dia a dia.
const BACKUP_DIR = path.join(DATA_DIR, 'backups');
const BACKUP_RETENCAO_DIAS = 7;
function fazerBackup() {
  try {
    if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const pastaBackup = path.join(BACKUP_DIR, timestamp);
    fs.mkdirSync(pastaBackup, { recursive: true });
    const arquivosBackup = ['db.json', 'eventos.json', 'pedidos.json', 'mensagens.json'];
    arquivosBackup.forEach(arquivo => {
      const origem = path.join(DATA_DIR, arquivo);
      if (fs.existsSync(origem)) fs.copyFileSync(origem, path.join(pastaBackup, arquivo));
    });
    console.log(`[Backup] Cópia de segurança criada em ${timestamp}`);
    // Remove backups mais antigos que o período de retenção
    const pastas = fs.readdirSync(BACKUP_DIR).filter(n => fs.statSync(path.join(BACKUP_DIR, n)).isDirectory());
    const limiteMs = Date.now() - BACKUP_RETENCAO_DIAS * 24 * 60 * 60 * 1000;
    pastas.forEach(nome => {
      const caminho = path.join(BACKUP_DIR, nome);
      const stat = fs.statSync(caminho);
      if (stat.birthtimeMs < limiteMs) { fs.rmSync(caminho, { recursive: true, force: true }); console.log(`[Backup] Removido backup antigo: ${nome}`); }
    });
    // Envia uma cópia por e-mail também — diferente do backup acima (que fica no mesmo Volume),
    // isso garante uma cópia genuinamente FORA da infraestrutura do Railway. Se o Volume inteiro
    // falhar ou for perdido, essa cópia continua existindo na caixa de entrada do e-mail configurado.
    enviarBackupPorEmail(pastaBackup, arquivosBackup, timestamp).catch(e => console.error('[Backup] Erro ao enviar cópia por e-mail:', e.message));
  } catch (e) { console.error('[Backup] Erro ao criar cópia de segurança:', e.message); }
}

async function enviarBackupPorEmail(pastaBackup, arquivosBackup, timestamp) {
  const destinatario = SUPORTE_EMAIL || db.users.find(u => u.isAdmin)?.email;
  if (!destinatario || !RESEND_API_KEY) { console.log('[Backup] Envio por e-mail pulado — configure SUPORTE_EMAIL pra ativar essa camada extra de segurança.'); return; }
  const LIMITE_ANEXO_BYTES = 15 * 1024 * 1024; // ~15MB por arquivo — margem segura dentro do limite do Resend
  const attachments = [];
  let algumArquivoGrandeDemais = false;
  for (const arquivo of arquivosBackup) {
    const caminho = path.join(pastaBackup, arquivo);
    if (!fs.existsSync(caminho)) continue;
    const stat = fs.statSync(caminho);
    if (stat.size > LIMITE_ANEXO_BYTES) { algumArquivoGrandeDemais = true; console.error(`[Backup] Arquivo ${arquivo} grande demais pra anexar por e-mail (${stat.size} bytes) — considere configurar um backup em nuvem dedicado.`); continue; }
    attachments.push({ filename: arquivo, content: fs.readFileSync(caminho).toString('base64') });
  }
  if (!attachments.length) return;
  const html = `<div style="font-family:Arial,sans-serif;padding:20px"><h3>Backup automático — Lota</h3><p>Cópia de segurança gerada em ${timestamp}.</p>${algumArquivoGrandeDemais ? '<p style="color:#c00"><strong>Atenção:</strong> um ou mais arquivos ficaram grandes demais pra anexar por e-mail e não estão incluídos aqui. Considere configurar um backup em nuvem dedicado (ex: S3) além deste.</p>' : ''}<p style="font-size:12px;color:#666">Guarde este e-mail em um local seguro — ele contém dados sensíveis da plataforma.</p></div>`;
  try {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${RESEND_API_KEY}` },
      body: JSON.stringify({ from: RESEND_FROM, to: destinatario, subject: `Backup automático — ${timestamp}`, html, attachments })
    });
    if (!r.ok) { const errBody = await r.text().catch(()=>''); console.error('[Backup] Resend recusou o e-mail de backup:', r.status, errBody); }
    else console.log(`[Backup] Cópia enviada por e-mail com sucesso para ${destinatario}`);
  } catch (e) { console.error('[Backup] Erro de rede ao enviar backup por e-mail:', e.message); }
}
setInterval(fazerBackup, 24 * 60 * 60 * 1000); // a cada 24 horas
setTimeout(fazerBackup, 60000); // primeiro backup 1 minuto após o servidor subir

// Verifica se um pedido pendente já foi realmente pago, consultando o provedor de pagamento direto
// — usado tanto pela limpeza de reservas expiradas quanto pela verificação proativa abaixo.
async function pedidoFoiPagoDeVerdade(pedido) {
  try {
    if (pedido.provedorPagamento === 'asaas' && ASAAS_API_KEY && pedido.mpPaymentId) {
      // Consulta o Checkout diretamente pelo status dele — sinal mais direto e confiável. Descobrimos
      // em produção que o filtro por "checkoutSession" (usado antes) às vezes não retorna resultado
      // mesmo com o pagamento já confirmado do lado do Asaas — por isso agora usamos o status do
      // próprio Checkout como fonte principal da verdade.
      const consultaCheckout = await asaasFetch(`/checkouts/${pedido.mpPaymentId}`);
      if (consultaCheckout.ok && consultaCheckout.data.status === 'PAID') return true;
      // Reforço: também tenta pelo filtro antigo, caso o Checkout já não exista mais como registro
      // ativo mas o pagamento gerado por ele ainda esteja rastreável dessa forma.
      const busca = await asaasFetch(`/payments?checkoutSession=${pedido.mpPaymentId}`);
      const pagamentoReal = (busca.ok && busca.data.data && busca.data.data[0]) || null;
      return !!(pagamentoReal && ['CONFIRMED', 'RECEIVED'].includes(pagamentoReal.status));
    } else if (pedido.provedorPagamento !== 'asaas' && MP_PLATFORM_TOKEN && pedido.mpPaymentId) {
      const payResp = await fetch(`${MP_API}/v1/payments/${pedido.mpPaymentId}`, { headers: { 'Authorization': `Bearer ${MP_PLATFORM_TOKEN}` } });
      const payData = await payResp.json().catch(() => ({}));
      return payResp.ok && payData.status === 'approved';
    }
  } catch (e) { console.error('Erro ao verificar pagamento:', e.message); }
  return false;
}

// ── VERIFICAÇÃO PROATIVA DE PAGAMENTOS PENDENTES ──
// Roda a cada 3 minutos: confere TODO pedido pendente (não só os que já expiraram) direto com o
// provedor de pagamento. Isso existe como uma segunda camada de segurança independente do webhook —
// se o webhook falhar ou atrasar por qualquer motivo, e o comprador fechar a página de confirmação
// sem esperar, esse job garante que o pedido seja reconhecido como pago em poucos minutos mesmo assim,
// sem depender de ninguém estar olhando a tela na hora.
setInterval(async () => {
  try {
    const agora = Date.now();
    let recuperados = 0;
    // Só confere pedidos com pelo menos 2 minutos de vida — dá tempo do webhook normal chegar primeiro,
    // evitando checagens desnecessárias em pedidos criados há poucos segundos.
    const candidatos = PEDIDOS.filter(p => p.status === 'pendente' && p.mpPaymentId && (agora - new Date(p.createdAt).getTime()) > 2 * 60000);
    if (candidatos.length > 0) console.log(`[Verificação proativa] Conferindo ${candidatos.length} pedido(s) pendente(s): ${candidatos.map(p => p.id).join(', ')}`);
    for (const pedido of candidatos) {
      // Try/catch em CADA pedido individualmente — um erro num pedido específico não pode derrubar
      // a verificação dos outros, nem (mais importante ainda) travar o processo inteiro do servidor.
      try {
        const pago = await pedidoFoiPagoDeVerdade(pedido);
        if (pago) {
          await processarPagamentoAprovado(pedido, pedido.mpPaymentId, PUBLIC_BASE_URL);
          recuperados++;
          console.log(`[Verificação proativa] Pedido ${pedido.id} confirmado como pago.`);
        } else {
          console.log(`[Verificação proativa] Pedido ${pedido.id} (provedor: ${pedido.provedorPagamento}, id externo: ${pedido.mpPaymentId}) ainda não confirmado.`);
        }
      } catch (e) { console.error(`[Verificação proativa] Erro ao verificar pedido ${pedido.id}:`, e.message); }
    }
    if (recuperados > 0) { persistPedidos(); console.log(`[Verificação proativa] ${recuperados} pedido(s) confirmado(s) que ainda não tinham sido reconhecidos automaticamente.`); }
  } catch (e) { console.error('[Verificação proativa] Erro geral na rotina:', e.message); }
}, 3 * 60000);

// Mesma ideia acima, mas pras recargas de saldo do bar — evita que uma recarga fique "pendente"
// pra sempre se o webhook falhar.
setInterval(async () => {
  const agora = Date.now();
  let confirmadas = 0;
  const candidatas = CONSUMOS_BAR.filter(c => c.tipo === 'recarga' && c.status === 'pendente' && c.paymentId && (agora - new Date(c.createdAt).getTime()) > 2 * 60000);
  for (const recarga of candidatas) {
    try {
      let pago = false;
      if (recarga.provedorPagamento === 'asaas' && ASAAS_API_KEY) {
        const busca = await asaasFetch(`/payments?checkoutSession=${recarga.paymentId}`);
        const pagamentoReal = (busca.ok && busca.data.data && busca.data.data[0]) || null;
        if (pagamentoReal && ['CONFIRMED', 'RECEIVED'].includes(pagamentoReal.status)) pago = true;
      } else if (MP_PLATFORM_TOKEN) {
        const payResp = await fetch(`${MP_API}/v1/payments/${recarga.paymentId}`, { headers: { 'Authorization': `Bearer ${MP_PLATFORM_TOKEN}` } });
        const payData = await payResp.json().catch(() => ({}));
        if (payResp.ok && payData.status === 'approved') pago = true;
      }
      if (pago) { recarga.status = 'pago'; confirmadas++; }
    } catch (e) { console.error('Erro ao verificar recarga pendente:', e.message); }
  }
  if (confirmadas > 0) { persistConsumosBar(); console.log(`[Verificação proativa] ${confirmadas} recarga(s) de bar confirmada(s).`); }
}, 3 * 60000);

// ── LIMPEZA DE RESERVAS EXPIRADAS ──
// Roda a cada 5 minutos: qualquer pedido "pendente" cujo prazo já passou tem uma ÚLTIMA checagem
// ao vivo com o provedor de pagamento antes de ser marcado como expirado — isso existe justamente
// pra evitar o problema de marcar como "expirado" um pedido que na verdade FOI pago (por exemplo,
// um PIX confirmado poucos minutos depois do prazo, ou um webhook que atrasou). Só libera a reserva
// de vaga de verdade se a checagem confirmar que não foi pago.
setInterval(async () => {
  try {
    const agora = Date.now();
    let liberados = 0, recuperados = 0;
    const candidatos = PEDIDOS.filter(p => p.status === 'pendente' && p.expiraEm && new Date(p.expiraEm).getTime() < agora);
    for (const pedido of candidatos) {
      try {
        const ev = EVENTOS.find(e => e.id === pedido.eventoId);
        const foiPago = await pedidoFoiPagoDeVerdade(pedido);

        if (foiPago) {
          await processarPagamentoAprovado(pedido, pedido.mpPaymentId, PUBLIC_BASE_URL);
          recuperados++;
        } else {
          pedido.status = 'expirado';
          if (ev) liberarReservaPedido(pedido, ev);
          liberados++;
        }
      } catch (e) { console.error(`[Limpeza] Erro ao processar pedido ${pedido.id}:`, e.message); }
    }
    if (liberados > 0 || recuperados > 0) {
      persistPedidos();
      console.log(`[Limpeza] ${liberados} reserva(s) expirada(s) liberada(s), ${recuperados} pedido(s) recuperado(s) numa última checagem antes de expirar.`);
    }
  } catch (e) { console.error('[Limpeza] Erro geral na rotina:', e.message); }
}, 5 * 60000);

// ── PROTEÇÃO GLOBAL CONTRA QUEDAS INESPERADAS ──
// Por padrão, o Node.js derruba o processo inteiro se algum erro não for capturado em algum lugar
// (por exemplo, dentro de uma rotina automática). Isso registra o erro no log em vez de deixar o
// servidor inteiro cair e reiniciar — o que explicava tanto pagamentos perdidos no meio do processo
// quanto instabilidade geral (incluindo envio de e-mail) sempre que algo desse errado.
process.on('unhandledRejection', (motivo) => {
  console.error('⚠️ Erro não tratado (unhandledRejection) — servidor continua rodando normalmente:', motivo);
});
process.on('uncaughtException', (erro) => {
  console.error('⚠️ Exceção não capturada (uncaughtException) — servidor continua rodando normalmente:', erro);
});

app.listen(PORT, () => {
  console.log(`\n🎟️  LOTA rodando na porta ${PORT}`);
  console.log(`   Mercado Pago: ${MP_PLATFORM_TOKEN ? '✅' : '❌'}`);
  console.log(`   Resend: ${RESEND_API_KEY ? '✅' : '❌'}\n`);
});

// ── REEMBOLSO AUTOMÁTICO DE SALDO CASHLESS NÃO USADO ──
// Roda a cada 6 horas: qualquer evento com sistema de bar ativo, que já terminou há pelo menos 24h
// (margem de segurança pra garantir que todo mundo já fechou a conta), tem o saldo não usado de
// cada ingresso devolvido automaticamente — como crédito na conta da plataforma, usável na próxima
// compra. Isso evita ter que estornar pagamento por pagamento direto no Mercado Pago/Asaas (que seria
// bem mais complexo, já que uma pessoa pode ter feito várias recargas diferentes ao longo do evento).
setInterval(async () => {
  try {
    const agora = Date.now();
    const margemHoras = 24 * 60 * 60 * 1000;
    let eventosProcessados = 0, pessoasReembolsadas = 0, valorTotalReembolsado = 0;

    for (const ev of EVENTOS) {
      try {
        if (!ev.barConfig?.ativo || ev.barSaldosReembolsados) continue;
        if (!ev.dataEvento) continue;
        const dataHoraEvento = new Date(`${ev.dataEvento}T${ev.horaEvento || '23:59'}:00`).getTime();
        if (isNaN(dataHoraEvento) || (agora - dataHoraEvento) < margemHoras) continue;

        const pedidosDoEvento = PEDIDOS.filter(p => p.eventoId === ev.id && p.status === 'pago');
        const codigosProcessados = new Set();
        for (const pedido of pedidosDoEvento) {
          for (const ticket of (pedido.tickets || [])) {
            try {
              if (ticket.cancelado || codigosProcessados.has(ticket.codigo)) continue;
              codigosProcessados.add(ticket.codigo);
              const { saldoCashless } = calcularContaBar(ev.id, ticket.codigo);
              if (saldoCashless <= 0) continue;

              const emailTitular = (ticket.titularEmail || pedido.comprador?.email || '').toLowerCase();
              // Bug corrigido: se algum usuário tivesse o e-mail ausente/nulo no banco, "u.email"
              // seria undefined e ".toLowerCase()" quebrava a rotina inteira sem proteção nenhuma.
              const conta = emailTitular ? db.users.find(u => (u.email || '').toLowerCase() === emailTitular) : null;
              if (conta) {
                conta.saldoCredito = Math.round(((conta.saldoCredito || 0) + saldoCashless) * 100) / 100;
                enviarEmailGenerico(conta.email,
                  `Saldo do bar devolvido — ${ev.nome}`,
                  `<div stye="font-family:Arial,sans-serif;padding:20px"><h3>Você tinha saldo sobrando no bar de "${esc(ev.nome)}"</h3><p>Devolvemos <strong>R$ ${saldoCashless.toFixed(2)}</strong> como crédito na sua conta Lota — é só usar na sua próxima compra de ingresso.</p></div>`
                ).catch(e => console.error('[Reembolso Bar] Erro ao notificar:', e.message));
              }
              CONSUMOS_BAR.push({
                id: uuidv4(), eventoId: ev.id, ticketCodigo: ticket.codigo, tipo: 'consumo', modo: 'pre-pago',
                status: 'pago', valor: saldoCashless, itens: [{ produtoId: 'reembolso-automatico', nome: 'Reembolso automático (saldo não usado)', qtd: 1, precoUnit: saldoCashless }],
                operadorNome: 'Sistema (automático)', createdAt: new Date().toISOString()
              });
              pessoasReembolsadas++; valorTotalReembolsado += saldoCashless;
            } catch (e) { console.error(`[Reembolso Bar] Erro ao processar ingresso ${ticket.codigo}:`, e.message); }
          }
        }
        ev.barSaldosReembolsados = true;
        eventosProcessados++;
      } catch (e) { console.error(`[Reembolso Bar] Erro ao processar evento ${ev.id}:`, e.message); }
    }
    if (eventosProcessados > 0) {
      persistConsumosBar(); persistEventos(); saveDB(db);
      console.log(`[Reembolso Bar] ${eventosProcessados} evento(s) processado(s), ${pessoasReembolsadas} pessoa(s) reembolsada(s), total R$ ${valorTotalReembolsado.toFixed(2)}.`);
    }
  } catch (e) { console.error('[Reembolso Bar] Erro geral na rotina:', e.message); }
}, 6 * 60 * 60 * 1000);
