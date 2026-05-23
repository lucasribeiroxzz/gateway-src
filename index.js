require('dotenv').config();

const express = require('express');

const session = require('express-session');

const bodyParser = require('body-parser');

const axios = require('axios');

const fs = require('fs');

const multer = require('multer');

const bcrypt = require('bcrypt');

const helmet = require('helmet');

const path = require('path');

const crypto = require('crypto');

const xss = require('xss'); 
const geoip = require('geoip-lite');
const useragent = require('express-useragent');
const rateLimit = require('express-rate-limit');

process.on('uncaughtException', (err) => console.error('❌ Erro Fatal (Ignorado):', err.message));

process.on('unhandledRejection', (err) => console.error('❌ Erro Promise (Ignorado):', err.message));

const app = express();

app.use(helmet({ 
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" }
})); 

app.set('view engine', 'ejs');

app.set('views', path.join(__dirname, 'views'));

app.use(express.static('public'));

app.use(bodyParser.urlencoded({ extended: true }));

app.use(bodyParser.json());

app.set('trust proxy', 1);

app.use(useragent.express());

app.use((req, res, next) => {
    let ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
    if (ip.includes('::ffff:')) {
        ip = ip.split(':').pop();
    }

    const geo = geoip.lookup(ip);
    let localizacao = "Desconhecida/Localhost";
    if (geo) {
        localizacao = `${geo.city || 'Cidade N/A'} - ${geo.country}`;
    }

    const ua = req.useragent;
    const dispositivo = ua.isMobile ? '📱 Celular' : '💻 PC/Desktop';
    const navegador = `${ua.browser} ${ua.version} (${ua.os})`;

    const dataHora = new Date().toLocaleString("pt-BR", { timeZone: "America/Sao_Paulo" });

    console.log('--------------------------------------------------');
    console.log(`🕒 [${dataHora}] - Novo Acesso`);
    console.log(`🌍 IP: ${ip}`);
    console.log(`📍 Local: ${localizacao}`);
    console.log(`${dispositivo} | 🌐 ${navegador}`);
    console.log(`🔗 Rota: ${req.url}`);
    console.log('--------------------------------------------------');

    next();
});

app.use(session({

    secret: process.env.SESSION_SECRET || 'segredo_olympus_pay',

    resave: false,

    saveUninitialized: false,

    cookie: { 
        maxAge: 24 * 60 * 60 * 1000,
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax'
    }

}));

const generateCsrfToken = () => {
    return crypto.randomBytes(32).toString('hex');
};

app.use((req, res, next) => {
    if (!req.session.csrfToken) {
        req.session.csrfToken = generateCsrfToken();
    }
    res.locals.csrfToken = req.session.csrfToken;
    next();
});

const verifyCsrf = (req, res, next) => {
    const token = req.body._csrf || req.headers['x-csrf-token'];
    if (!token || token !== req.session.csrfToken) {
        console.log(`🚫 CSRF Token inválido - IP: ${req.ip}`);
        return res.status(403).json({ error: 'Token de segurança inválido. Recarregue a página.' });
    }
    next();
};

const depositLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 20,
    message: { error: 'Muitas requisições. Aguarde 1 minuto.' },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => req.session.userId || req.ip
});

const withdrawLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 20,
    message: { error: 'Muitas requisições. Aguarde 1 minuto.' },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => req.session.userId || req.ip
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: 'Muitas tentativas de login. Tente novamente em 15 minutos.',
    standardHeaders: true,
    legacyHeaders: false
});

const apiLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    message: { error: 'Limite de requisições excedido.' },
    standardHeaders: true,
    legacyHeaders: false
});

const ANTI_BOT_SECRET = process.env.SESSION_SECRET || 'olympus_anti_bot_key_2024';
const depositCooldowns = new Map();

const generateDepositToken = (userId, timestamp) => {
    const data = `${userId}:${timestamp}:${ANTI_BOT_SECRET}`;
    return crypto.createHash('sha256').update(data).digest('hex');
};

const verifyDepositToken = (token, userId, timestamp) => {
    const expectedToken = generateDepositToken(userId, timestamp);
    return crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expectedToken));
};

const antiAutomationDeposit = (req, res, next) => {
    const userId = req.session.userId;
    const { _depositToken, _depositTime } = req.body;
    
    if (!_depositToken || !_depositTime) {
        console.log(`🤖 BLOQUEADO: Token anti-bot ausente - User: ${userId}`);
        return res.render('deposit', { 
            error: 'Requisição inválida. Recarregue a página.', 
            qr_code: null, code: null, settings: getDb().settings, tx_id: null 
        });
    }
    
    const timestamp = parseInt(_depositTime);
    const now = Date.now();
    const timeDiff = now - timestamp;
    
    if (timeDiff < 2000) {
        console.log(`🤖 BLOQUEADO: Preenchimento muito rápido (${timeDiff}ms) - User: ${userId}`);
        return res.render('deposit', { 
            error: 'Aguarde alguns segundos antes de enviar.', 
            qr_code: null, code: null, settings: getDb().settings, tx_id: null 
        });
    }
    
    if (timeDiff > 600000) {
        console.log(`🤖 BLOQUEADO: Token expirado - User: ${userId}`);
        return res.render('deposit', { 
            error: 'Sessão expirada. Recarregue a página.', 
            qr_code: null, code: null, settings: getDb().settings, tx_id: null 
        });
    }
    
    try {
        if (!verifyDepositToken(_depositToken, userId, timestamp)) {
            console.log(`🤖 BLOQUEADO: Token inválido - User: ${userId}`);
            return res.render('deposit', { 
                error: 'Token de segurança inválido.', 
                qr_code: null, code: null, settings: getDb().settings, tx_id: null 
            });
        }
    } catch (e) {
        console.log(`🤖 BLOQUEADO: Erro na verificação - User: ${userId}`);
        return res.render('deposit', { 
            error: 'Erro de validação. Recarregue a página.', 
            qr_code: null, code: null, settings: getDb().settings, tx_id: null 
        });
    }
    
    const lastDeposit = depositCooldowns.get(userId);
    if (lastDeposit && (now - lastDeposit) < 10000) {
        const waitTime = Math.ceil((10000 - (now - lastDeposit)) / 1000);
        console.log(`🤖 BLOQUEADO: Cooldown ativo - User: ${userId}`);
        return res.render('deposit', { 
            error: `Aguarde ${waitTime} segundos entre depósitos.`, 
            qr_code: null, code: null, settings: getDb().settings, tx_id: null 
        });
    }
    
    depositCooldowns.set(userId, now);
    
    next();
};

setInterval(() => {
    const now = Date.now();
    for (const [key, value] of depositCooldowns.entries()) {
        if (now - value > 60000) depositCooldowns.delete(key);
    }
}, 60000);

const WEBHOOK_URL = process.env.WEBHOOK_URL || '';
const WEBHOOK_PUBLIC_URL = process.env.WEBHOOK_PUBLIC_URL || '';

const getLocationFromIP = (ip) => {
    if (!ip || ip === '127.0.0.1' || ip === '::1' || ip.includes('192.168.') || ip.includes('10.0.')) {
        return { city: 'Local', region: 'Localhost', country: 'BR' };
    }
    const geo = geoip.lookup(ip);
    if (geo) {
        return {
            city: geo.city || 'Desconhecida',
            region: geo.region || 'N/A',
            country: geo.country || 'BR'
        };
    }
    return { city: 'Desconhecida', region: 'N/A', country: 'BR' };
};

const sendWebhookPrivate = async (type, data) => {
    if (!WEBHOOK_URL) return;
    
    const colors = {
        'deposit_created': 0x3498db,
        'withdraw_created': 0xf39c12
    };
    
    const titles = {
        'deposit_created': '💰 Novo Depósito Gerado',
        'withdraw_created': '💸 Novo Saque Solicitado'
    };
    
    const location = getLocationFromIP(data.ip);
    const timestamp = new Date().toISOString();
    
    const embed = {
        embeds: [{
            title: titles[type] || 'Notificação',
            color: colors[type] || 0x7289da,
            fields: [
                { name: '👤 Usuário', value: data.userName || 'N/A', inline: true },
                { name: '📧 Email', value: data.userEmail || 'N/A', inline: true },
                { name: '🆔 User ID', value: String(data.userId) || 'N/A', inline: true },
                { name: '💵 Valor', value: `R$ ${parseFloat(data.amount).toFixed(2)}`, inline: true },
                { name: '🌐 IP', value: data.ip || 'N/A', inline: true },
                { name: '📍 Localização', value: `${location.city}, ${location.region} - ${location.country}`, inline: true }
            ],
            footer: { text: 'OlympusPay - Admin' },
            timestamp: timestamp
        }]
    };
    
    if (data.txId) {
        embed.embeds[0].fields.push({ name: '🔖 TX ID', value: data.txId, inline: false });
    }
    
    if (data.pixKey) {
        embed.embeds[0].fields.push({ name: '🔑 Chave PIX', value: data.pixKey, inline: true });
        embed.embeds[0].fields.push({ name: '📋 Tipo Chave', value: data.keyType || 'N/A', inline: true });
    }
    
    try {
        await axios.post(WEBHOOK_URL, embed, {
            headers: { 'Content-Type': 'application/json' }
        });
        console.log(`📤 Webhook privado enviado: ${type}`);
    } catch (err) {
        console.error(`❌ Erro webhook privado: ${err.message}`);
    }
};

const sendWebhookPublic = async (type, data) => {
    if (!WEBHOOK_PUBLIC_URL) return;
    
    const timestamp = new Date().toISOString();
    const valor = parseFloat(data.amount).toFixed(2);
    const userName = data.userName || 'Usuário';
    
    let embed;
    
    if (type === 'deposit_approved') {
        embed = {
            embeds: [{
                title: '🎉 NOVO DEPÓSITO CONFIRMADO!',
                description: `**${userName}** acabou de depositar na plataforma!`,
                color: 0x00ff88,
                fields: [
                    { 
                        name: '💰 Valor Depositado', 
                        value: `\`\`\`fix\nR$ ${valor}\n\`\`\``, 
                        inline: false 
                    }
                ],
                thumbnail: {
                    url: 'https://cdn-icons-png.flaticon.com/512/6941/6941697.png'
                },
                footer: { 
                    text: '⚡ OlympusPay • Depósitos Instantâneos',
                    icon_url: 'https://cdn-icons-png.flaticon.com/512/7016/7016425.png'
                },
                timestamp: timestamp
            }]
        };
    } else if (type === 'withdraw_approved') {
        embed = {
            embeds: [{
                title: '💸 SAQUE REALIZADO COM SUCESSO!',
                description: `**${userName}** acabou de sacar da plataforma!`,
                color: 0xa855f7,
                fields: [
                    { 
                        name: '💵 Valor Sacado', 
                        value: `\`\`\`fix\nR$ ${valor}\n\`\`\``, 
                        inline: false 
                    }
                ],
                thumbnail: {
                    url: 'https://cdn-icons-png.flaticon.com/512/2489/2489756.png'
                },
                footer: { 
                    text: '⚡ OlympusPay • Saques Rápidos',
                    icon_url: 'https://cdn-icons-png.flaticon.com/512/7016/7016425.png'
                },
                timestamp: timestamp
            }]
        };
    }
    
    if (!embed) {
        console.log(`⚠️ Webhook público: tipo desconhecido - ${type}`);
        return;
    }
    
    console.log(`📡 Tentando enviar webhook público: ${type} para ${WEBHOOK_PUBLIC_URL}`);
    
    try {
        const response = await axios.post(WEBHOOK_PUBLIC_URL, embed, {
            headers: { 'Content-Type': 'application/json' }
        });
        console.log(`📤 Webhook público enviado: ${type} - Status: ${response.status}`);
    } catch (err) {
        console.error(`❌ Erro webhook público: ${err.message}`);
        if (err.response) {
            console.error(`❌ Detalhes: ${JSON.stringify(err.response.data)}`);
        }
    }
};

app.use((req, res, next) => {

    if (req.body) {

        for (let key in req.body) {

            if (typeof req.body[key] === 'string') {

                req.body[key] = xss(req.body[key]); 

            }

        }

    }

    if (req.query) {

        for (let key in req.query) {

            if (typeof req.query[key] === 'string') {

                req.query[key] = xss(req.query[key]);

            }

        }

    }

    next();

});

const DB_DIR = './DBs';
const DB_FILES = {
    users: `${DB_DIR}/users.json`,
    admins: `${DB_DIR}/admins.json`,
    transactions: `${DB_DIR}/transactions.json`,
    pending: `${DB_DIR}/pending.json`,
    stats: `${DB_DIR}/stats.json`,
    settings: `${DB_DIR}/settings.json`,
    backups: `${DB_DIR}/backups.json`
};

const SUPER_ADMIN_EMAILS = ['luk34093@gmail.com', 'gabrieldantaslopes17@gmail.com'];

const defaultData = {
    users: [],
    admins: { superAdmins: SUPER_ADMIN_EMAILS, admins: [] },
    transactions: [],
    pending: [],
    stats: [],
    settings: { fee_dep: 1.00, fee_sac: 1.00 },
    backups: { lastBackup: null, backupCount: 0 }
};

if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });

Object.entries(DB_FILES).forEach(([key, file]) => {
    if (!fs.existsSync(file)) {
        fs.writeFileSync(file, JSON.stringify(defaultData[key], null, 2));
    }
});

const readDbFile = (key) => {
    try {
        return JSON.parse(fs.readFileSync(DB_FILES[key]));
    } catch {
        return defaultData[key];
    }
};

const writeDbFile = (key, data) => {
    fs.writeFileSync(DB_FILES[key], JSON.stringify(data, null, 2));
};

const getDb = () => {
    const adminsData = readDbFile('admins');
    return {
        users: readDbFile('users'),
        transactions: [...readDbFile('transactions'), ...readDbFile('pending')],
        admins: adminsData.admins || [],
        userStats: readDbFile('stats'),
        settings: readDbFile('settings'),
        backupInfo: readDbFile('backups')
    };
};

const saveDb = (data) => {
    if (data.users) writeDbFile('users', data.users);
    if (data.settings) writeDbFile('settings', data.settings);
    if (data.userStats) writeDbFile('stats', data.userStats);
    if (data.backupInfo) writeDbFile('backups', data.backupInfo);
    
    if (data.transactions) {
        const completed = data.transactions.filter(t => t.status === 'completed' || t.status === 'failed');
        const pending = data.transactions.filter(t => t.status === 'pending');
        writeDbFile('transactions', completed);
        writeDbFile('pending', pending);
    }
    
    if (data.admins) {
        const adminsData = readDbFile('admins');
        adminsData.admins = data.admins;
        writeDbFile('admins', adminsData);
    }
};

const isSuperAdmin = (email) => SUPER_ADMIN_EMAILS.includes(email);

const canAddAdmin = (user) => {
    return user && user.isAdmin && (user.isSuperAdmin || isSuperAdmin(user.email));
};

const archiver = require('archiver');

const createBackup = async () => {
    const backupDir = path.join(__dirname, 'Backup');
    if (!fs.existsSync(backupDir)) {
        fs.mkdirSync(backupDir, { recursive: true });
    }
    
    const now = new Date();
    const timestamp = now.toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const backupName = `backup_${timestamp}.zip`;
    const backupPath = path.join(backupDir, backupName);
    
    return new Promise((resolve, reject) => {
        const output = fs.createWriteStream(backupPath);
        const archive = archiver('zip', { zlib: { level: 9 } });
        
        output.on('close', () => {
            const backupInfo = readDbFile('backups');
            backupInfo.lastBackup = now.toISOString();
            backupInfo.lastBackupFile = backupName;
            backupInfo.backupCount++;
            writeDbFile('backups', backupInfo);
            
            console.log(`💾 Backup criado: ${backupName} (${archive.pointer()} bytes)`);
            
            try {
                const files = fs.readdirSync(backupDir).filter(f => f.endsWith('.zip')).sort().reverse();
                if (files.length > 24) {
                    files.slice(24).forEach(f => {
                        try { fs.unlinkSync(path.join(backupDir, f)); } catch(e) {}
                    });
                    console.log(`🗑️ Backups antigos removidos (mantendo últimos 24)`);
                }
            } catch(e) {}
            
            resolve(backupName);
        });
        
        output.on('error', (err) => {
            console.error('❌ Erro ao criar backup:', err.message);
            reject(err);
        });
        
        archive.on('error', (err) => {
            console.error('❌ Erro no archiver:', err.message);
            reject(err);
        });
        
        archive.pipe(output);
        
        const dbsDir = path.join(__dirname, 'DBs');
        if (fs.existsSync(dbsDir)) archive.directory(dbsDir, 'DBs');
        
        const viewsDir = path.join(__dirname, 'views');
        if (fs.existsSync(viewsDir)) archive.directory(viewsDir, 'views');
        
        const publicDir = path.join(__dirname, 'public');
        if (fs.existsSync(publicDir)) archive.directory(publicDir, 'public');
        
        const indexFile = path.join(__dirname, 'index.js');
        if (fs.existsSync(indexFile)) archive.file(indexFile, { name: 'index.js' });
        
        const packageFile = path.join(__dirname, 'package.json');
        if (fs.existsSync(packageFile)) archive.file(packageFile, { name: 'package.json' });
        
        const envFile = path.join(__dirname, '.env');
        if (fs.existsSync(envFile)) archive.file(envFile, { name: '.env' });
        
        archive.finalize();
    });
};

setInterval(() => createBackup().catch(console.error), 60 * 60 * 1000);
setTimeout(() => createBackup().catch(console.error), 10000);

const vision = axios.create({

    baseURL: 'https://api.visionwallet.com.br/api/v1',

    headers: { 'Authorization': `Bearer ${process.env.VISION_KEY}` },

    timeout: 30000

});

const storage = multer.diskStorage({

    destination: function (req, file, cb) {

        const dir = './public/avatars';

        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

        cb(null, dir);

    },

    filename: function (req, file, cb) {

        const ext = path.extname(file.originalname);

        cb(null, `${req.session.userId}_${Date.now()}${ext}`);

    }

});

const fileFilter = (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    if (allowedTypes.includes(file.mimetype)) {
        cb(null, true);
    } else {
        cb(new Error('Tipo de arquivo não permitido'), false);
    }
};

const upload = multer({ 
    storage: storage,
    fileFilter: fileFilter,
    limits: { fileSize: 5 * 1024 * 1024 }
});

const apiRateLimits = new Map();

setInterval(() => {

    const now = Date.now();

    for (const [key, value] of apiRateLimits.entries()) {

        if (now > value.resetTime) apiRateLimits.delete(key);

    }

}, 10 * 60 * 1000);

const requireAuth = (req, res, next) => {

    if (!req.session.userId) return res.redirect('/login');

    const db = getDb();

    const user = db.users.find(u => u.id === req.session.userId);

    if (!user || user.banned) {

        req.session.destroy();

        return res.redirect('/login?error=Conta suspensa.');

    }

    next();

};

const requireAdmin = (req, res, next) => {

    const db = getDb();

    const user = db.users.find(u => u.id === req.session.userId);

    if (!user || !user.isAdmin) return res.redirect('/dashboard');

    next();

};

const apiAuth = (req, res, next) => {

    const apiKey = req.headers['authorization']; 

    if (!apiKey) return res.status(401).json({ error: "API Key não fornecida." });

    const now = Date.now();

    const windowMs = 60 * 1000;

    const maxRequests = 20;

    if (!apiRateLimits.has(apiKey)) {

        apiRateLimits.set(apiKey, { count: 1, resetTime: now + windowMs });

    } else {

        const usage = apiRateLimits.get(apiKey);

        if (now > usage.resetTime) {

            usage.count = 1;

            usage.resetTime = now + windowMs;

        } else {

            usage.count++;

            if (usage.count > maxRequests) {

                const waitSeconds = Math.ceil((usage.resetTime - now) / 1000);

                return res.status(429).json({ 

                    error: "Too Many Requests", 

                    message: `Limite de 20 requisições/min excedido. Aguarde ${waitSeconds}s.` 

                });

            }

        }

    }

    const db = getDb();

    const user = db.users.find(u => u.apiKey === apiKey);

    if (!user) return res.status(401).json({ error: "API Key inválida." });

    if (user.banned) return res.status(403).json({ error: "Conta banida." });

    req.apiUser = user;

    next();

};

app.get('/', (req, res) => {

    const db = getDb();

    const totalUsers = db.users.length;

    const totalVolume = db.transactions

        .filter(t => t.status === 'completed')

        .reduce((acc, t) => acc + parseFloat(t.val), 0);

    res.render('landing', { totalUsers, totalVolume });

});

app.get('/docs', (req, res) => res.render('docs'));

app.get('/terms', (req, res) => res.render('terms'));

app.get('/api/v1/balance', apiAuth, (req, res) => {
    res.json({ balance: req.apiUser.balance });
});

app.post('/api/v1/pay', apiAuth, apiLimiter, async (req, res) => {
    const amount = parseFloat(req.body.amount);
    if (!amount || amount < 5) return res.status(400).json({ error: "Valor mínimo R$ 5.00" });

    try {
        let hook = req.apiUser.webhookUrl; 
        if (!hook) {
            hook = process.env.DOMAIN || "https://olympuspay.squareweb.app";
            if (!hook.endsWith('/webhook')) hook += '/webhook';
        }

        const { data } = await vision.post('/payment/create', { 
            value: amount, method: 'pix', webhook_url: hook 
        });

        let code = data.pix_copy_paste || (data.qr_code && data.qr_code.includes('000201') ? data.qr_code : data.brcode);
        
        if (!code) {
             const match = JSON.stringify(data).match(/000201[^"]+/);
             if(match) code = match[0].replace(/\\/g, '');
        }

        let realId = data.id || data.txid || (data.data ? data.data.id : null);

        if (!realId && code) {
            const urlMatch = code.match(/id=([a-zA-Z0-9]+)/);
            if (urlMatch) realId = urlMatch[1];
            
            if (!realId) {
                const emvMatch = code.match(/62\d{2}05\d{2}([a-zA-Z0-9]{1,35})/);
                if (emvMatch) realId = emvMatch[1];
            }
        }

        if (!realId) realId = `err_${Date.now()}`;

        const db = getDb();
        db.transactions.push({ 
            id: realId,
            uid: req.apiUser.id, 
            type: 'deposit', 
            val: amount, 
            status: 'pending', 
            date: new Date(),
            via_api: true,
            pix_code: code 
        });
        saveDb(db);

        res.json({
            id: realId, 
            status: 'pending',
            qr_code: code,
            qr_code_base64: `https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=${encodeURIComponent(code)}`
        });

    } catch (e) {
        console.error("Erro API Pay:", e.message);
        res.status(500).json({ error: "Erro interno ao gerar PIX." });
    }
});

app.post('/api/v1/withdraw', apiAuth, apiLimiter, async (req, res) => {
    const amount = parseFloat(req.body.amount);
    const { pix_key, key_type } = req.body;
    const db = getDb();
    
    const user = db.users.find(u => u.id === req.apiUser.id);
    const settings = db.settings;

    if (!amount || amount < 5) return res.status(400).json({ error: "Valor mínimo R$ 5.00" });
    const totalDebit = amount + settings.fee_sac;

    if (user.balance < totalDebit) {
        return res.status(400).json({ error: "Saldo insuficiente.", balance: user.balance, required: totalDebit });
    }

    try {
        let hook = user.webhookUrl;
        if (!hook) {
            hook = process.env.DOMAIN;
            if (!hook.endsWith('/webhook')) hook += '/webhook';
        }

        const { data: visionData } = await vision.post('/withdraw/create', { 
            pixKey: pix_key, 
            pixKeyType: key_type || 'random', 
            amount: amount, 
            webhook_url: hook 
        });

        user.balance -= totalDebit;

        const txIdOlympus = `wd_api_${Date.now()}`;
        
        db.transactions.push({ 
            id: txIdOlympus,
            vision_id: visionData.id,
            uid: user.id, 
            type: 'withdraw', 
            val: amount, 
            status: 'pending', 
            date: new Date(),
            via_api: true
        });
        saveDb(db);

        res.json({ 
            id: txIdOlympus, 
            status: 'pending', 
            message: 'Saque solicitado.' 
        });

    } catch (e) {
        res.status(500).json({ error: "Erro ao processar saque.", details: e.response?.data || e.message });
    }
});

app.get('/api/v1/payment/:id', apiAuth, async (req, res) => {
    const db = getDb();
    const txId = req.params.id;
    
    const tx = db.transactions.find(t => String(t.id) === String(txId) && t.uid === req.apiUser.id);

    if (!tx) return res.status(404).json({ error: "Transação não encontrada." });
    if (tx.status === 'completed') return res.json({ id: tx.id, status: 'paid', amount: tx.val });

    try {
        const { data } = await vision.get(`/payment/get/${txId}`);
        let statusVision = (data.status || (data.data && data.data.status) || "").toLowerCase();
        
        const aprovados = ['paid', 'approved', 'concluded', 'completed', 'success'];

        if (aprovados.includes(statusVision)) {
            const user = db.users.find(u => u.id === req.apiUser.id);
            const valorBruto = parseFloat(tx.val);
            const taxa = parseFloat(db.settings.fee_dep);
            const valorLiquido = valorBruto - taxa;

            user.balance = parseFloat((user.balance + valorLiquido).toFixed(2));
            tx.status = 'completed';
            saveDb(db);

            return res.json({ 
                id: tx.id, 
                status: 'paid', 
                message: 'Pagamento confirmado.', 
                received: valorLiquido 
            });
        }

        res.json({ id: tx.id, status: 'pending', vision_status: statusVision });

    } catch (e) {
        res.status(500).json({ error: "Erro ao consultar Vision." });
    }
});

app.get('/api/v1/withdraw/:id', apiAuth, async (req, res) => {
    const db = getDb();
    const txIdOlympus = req.params.id;
    
    const tx = db.transactions.find(t => String(t.id) === String(txIdOlympus) && t.uid === req.apiUser.id);

    if (!tx) return res.status(404).json({ error: "Saque não encontrado." });

    if (tx.status === 'completed') return res.json({ id: tx.id, status: 'paid' });
    if (tx.status === 'failed') return res.json({ id: tx.id, status: 'failed', message: 'Saque estornado.' });

    const idParaConsultar = tx.vision_id || tx.id; 

    try {
        const { data } = await vision.get(`/withdraw/get/${idParaConsultar}`);
        let statusVision = (data.status || (data.data && data.data.status) || "").toLowerCase();

        const aprovados = ['paid', 'concluded', 'completed', 'approved', 'success'];
        const reprovados = ['failed', 'rejected', 'canceled', 'error'];

        if (aprovados.includes(statusVision)) {
            tx.status = 'completed';
            saveDb(db);
            return res.json({ id: tx.id, status: 'paid' });
        } 
        else if (reprovados.includes(statusVision)) {
            const user = db.users.find(u => u.id === req.apiUser.id);
            const reembolso = parseFloat(tx.val) + parseFloat(db.settings.fee_sac);
            
            user.balance = parseFloat((user.balance + reembolso).toFixed(2));
            tx.status = 'failed';
            saveDb(db);

            return res.json({ id: tx.id, status: 'failed', message: 'Falha no banco. Valor estornado.' });
        }

        res.json({ id: tx.id, status: 'pending' });

    } catch (e) {
        res.status(500).json({ error: "Erro ao consultar status no banco." });
    }
});

app.post('/api/check-payment/:id', requireAuth, apiLimiter, async (req, res) => {

    const db = getDb();

    const txId = req.params.id;

    const user = db.users.find(u => u.id === req.session.userId);

    const tx = db.transactions.find(t => String(t.id) === String(txId));

    if (!tx || tx.uid !== user.id || tx.type !== 'deposit') {

        return res.json({ status: 'error', message: 'Transação inválida.' });

    }

    if (tx.status === 'completed') {

        return res.json({ status: 'paid', message: 'Já está pago!' });

    }

    try {

        console.log(`🔎 Consultando na Rota Oficial: /payment/get/${txId}`);

        const { data } = await vision.get(`/payment/get/${txId}`);

let statusVision = (data.status || (data.data && data.data.status) || "").toLowerCase();

console.log("📦 Resposta Vision:", JSON.stringify(data));

const aprovados = ['paid', 'approved', 'concluded', 'completed'];

if (aprovados.includes(statusVision)) {

    const valorPago = parseFloat(tx.val);

    const taxaConfigurada = parseFloat(db.settings.fee_dep);

    const netValue = valorPago - taxaConfigurada;

    console.log(`💰 [DEPÓSITO] Bruto: ${valorPago} | Taxa: ${taxaConfigurada} | Líquido para Saldo: ${netValue}`);

    user.balance = parseFloat(user.balance) + netValue;

    tx.status = 'completed';

    saveDb(db);

    sendWebhookPublic('deposit_approved', {
        userName: user.name,
        amount: tx.val
    });

    return res.json({ status: 'paid', message: `Confirmado! R$ ${netValue.toFixed(2)} adicionados ao seu saldo.`, valor: netValue });

} else {

    return res.json({ status: 'pending', message: `Aguardando... Status: ${statusVision}` });

}

    } catch (error) {

        console.error("❌ Erro ao consultar:", error.message);

        if (error.response) console.error("Dados Erro:", error.response.data);

        return res.json({ status: 'pending', message: 'Pagamento ainda não processado.' });

    }

});

app.post('/api/check-withdraw/:id', requireAuth, apiLimiter, async (req, res) => {
    const db = getDb();
    const txId = req.params.id;
    const user = db.users.find(u => u.id === req.session.userId);

    const tx = db.transactions.find(t => String(t.id) === String(txId));

    if (!tx || tx.uid !== user.id || tx.type !== 'withdraw') {
        return res.json({ status: 'error', message: 'Transação não encontrada.' });
    }

    if (tx.status === 'completed') return res.json({ status: 'paid', message: 'Saque já realizado!' });
    if (tx.status === 'failed') return res.json({ status: 'failed', message: 'Este saque falhou e foi estornado.' });

    try {
        console.log(`👤 Usuário verificando saque: ${txId}`);
        
        const { data } = await vision.get(`/withdraw/get/${txId}`);
        
        let statusVision = (data.status || (data.data && data.data.status) || "").toLowerCase();
        
        const aprovados = ['paid', 'concluded', 'completed', 'approved', 'success'];
        const reprovados = ['failed', 'rejected', 'canceled', 'error'];

        if (aprovados.includes(statusVision)) {
            tx.status = 'completed';
            saveDb(db);
            
            sendWebhookPublic('withdraw_approved', {
                userName: user.name,
                amount: tx.val
            });
            
            return res.json({ status: 'paid', message: 'Saque confirmado! O valor já foi enviado.', valor: tx.val });
        } 
        
        else if (reprovados.includes(statusVision)) {
            const valorEstorno = parseFloat(tx.val) + parseFloat(db.settings.fee_sac);
            
            user.balance = parseFloat((user.balance + valorEstorno).toFixed(2));
            tx.status = 'failed';
            saveDb(db);
            
            return res.json({ status: 'failed', message: 'Falha no banco. Valor estornado para sua conta.' });
        }

        return res.json({ status: 'pending', message: `Processando... Status atual: ${statusVision}` });

    } catch (e) {
        console.error("Erro Check User:", e.message);
        return res.json({ status: 'error', message: 'Erro ao consultar status.' });
    }
});

app.get('/login', (req, res) => res.render('login', { error: req.query.error }));

app.post('/login', authLimiter, async (req, res) => {

    const { email, password } = req.body;

    const db = getDb();

    const user = db.users.find(u => u.email === email);

    if (user && await bcrypt.compare(password, user.password)) {

        if(user.banned) return res.render('login', { error: "Banido." });

        req.session.userId = user.id;
        
        req.session.csrfToken = generateCsrfToken();

        if(process.env.ADMIN_EMAIL && user.email === process.env.ADMIN_EMAIL && !user.isAdmin) {

            user.isAdmin = true; saveDb(db);

        }

        return res.redirect('/dashboard');

    }

    res.render('login', { error: "Dados incorretos." });

});

app.get('/register', (req, res) => res.render('register', { error: null }));

app.post('/register', authLimiter, async (req, res) => {

    const { name, email, cpf, password } = req.body;

    const recaptchaToken = req.body['g-recaptcha-response']; 

    if (!recaptchaToken) {

        return res.render('register', { error: "Por favor, marque a caixa 'Não sou um robô'." });

    }

    const secretKey = '6LfhIDIsAAAAAJTqC4OsL7Xwx9hmqBvyVRjemXcW';

    const verifyUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${recaptchaToken}`;

    try {

        const googleReq = await axios.post(verifyUrl); 

        const googleData = googleReq.data;

        if (!googleData.success) {

            return res.render('register', { error: "Falha na verificação do robô. Tente novamente." });

        }

        const db = getDb();

        if (db.users.find(u => u.email === email)) {

            return res.render('register', { error: "Este email já está em uso." });

        }

        if (db.users.find(u => u.cpf === cpf)) {

            return res.render('register', { error: "Este CPF já está em uso." });

        }

        const hashedPassword = await bcrypt.hash(password, 12);

        const isNewSuperAdmin = isSuperAdmin(email);
        
        const newUser = { 
            id: Date.now(), 
            name, email, cpf, 
            password: hashedPassword, 
            balance: 0.00, 
            banned: false, 
            isAdmin: isNewSuperAdmin,
            isSuperAdmin: isNewSuperAdmin,
            joined: new Date(),
            apiKey: null, webhookUrl: null, integrationName: null,
            avatar: null 
        };

        db.users.push(newUser);
        
        if (isNewSuperAdmin) {
            const adminsData = readDbFile('admins');
            if (!adminsData.admins.find(a => a.email === email)) {
                adminsData.admins.push({
                    id: newUser.id,
                    email: email,
                    isSuperAdmin: true,
                    addedAt: new Date(),
                    addedBy: 'system'
                });
                writeDbFile('admins', adminsData);
            }
            console.log(`👑 Super Admin auto-definido: ${email}`);
        }
        
        saveDb(db);

        req.session.userId = newUser.id;

        res.redirect('/dashboard');

    } catch (err) {

        console.error("Erro no Registro:", err);

        return res.render('register', { error: "Erro interno no servidor." });

    }

});

app.get('/logout', (req, res) => { req.session.destroy(); res.redirect('/'); });

app.get('/dashboard', requireAuth, (req, res) => {

    const db = getDb();

    const user = db.users.find(u => u.id === req.session.userId);

    const txs = db.transactions.filter(t => t.uid === user.id).sort((a,b) => new Date(b.date) - new Date(a.date)).slice(0, 10);

    res.render('dashboard', { user, txs });

});

app.get('/developer', requireAuth, (req, res) => {

    const db = getDb();

    const user = db.users.find(u => u.id === req.session.userId);

    res.render('developer', { user, error: null, success: req.query.msg });

});

app.post('/developer/save', requireAuth, verifyCsrf, (req, res) => {

    const db = getDb();

    const user = db.users.find(u => u.id === req.session.userId);

    user.integrationName = req.body.integrationName;

    user.webhookUrl = req.body.webhookUrl;

    saveDb(db);

    res.redirect('/developer?msg=Salvo!');

});

app.post('/developer/generate', requireAuth, verifyCsrf, (req, res) => {

    const db = getDb();

    const user = db.users.find(u => u.id === req.session.userId);

    user.apiKey = 'oly_live_' + crypto.randomBytes(12).toString('hex');

    saveDb(db);

    res.redirect('/developer?msg=Gerada!');

});

app.post('/developer/reveal', requireAuth, async (req, res) => {

    const { password } = req.body;

    const db = getDb();

    const user = db.users.find(u => u.id === req.session.userId);

    if (user && await bcrypt.compare(password, user.password)) return res.json({ success: true, apiKey: user.apiKey });

    res.json({ success: false });

});

app.post('/update-profile', requireAuth, upload.single('avatar'), verifyCsrf, (req, res) => {

    const { name } = req.body;

    const db = getDb();

    const user = db.users.find(u => u.id === req.session.userId);

    if (user) {

        if(name) user.name = name;

        if (req.file) {

            if (user.avatar) {

                const oldPath = path.join(__dirname, 'public', 'avatars', user.avatar);

                if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);

            }

            user.avatar = req.file.filename;

        }

        saveDb(db);

    }

    res.redirect('/dashboard');

});

app.get('/admin', requireAuth, requireAdmin, async (req, res) => {

    const db = getDb();

    const totalCustody = db.users.reduce((acc, user) => acc + parseFloat(user.balance || 0), 0);

    

    const allTxs = db.transactions.map(tx => {

        const u = db.users.find(user => user.id === tx.uid);

        return { ...tx, userName: u ? u.name : 'Desconhecido' };

    }).sort((a,b) => new Date(b.date) - new Date(a.date));

    res.render('admin', { 

        users: db.users, transactions: allTxs,

        apiBalance: totalCustody.toFixed(2), settings: db.settings, msg: req.query.msg 

    });

});

app.post('/admin/ban', requireAuth, requireAdmin, verifyCsrf, (req, res) => {

    const { userId } = req.body;

    const db = getDb();

    const user = db.users.find(u => u.id == userId);

    if(user && !user.isAdmin) {

        user.banned = !user.banned;

        saveDb(db);

    }

    res.redirect('/admin?msg=Status alterado');

});

app.post('/admin/settings', requireAuth, requireAdmin, verifyCsrf, (req, res) => {

    const db = getDb();

    const { fee_dep, fee_sac } = req.body;

    if(fee_dep) db.settings.fee_dep = parseFloat(fee_dep);

    if(fee_sac) db.settings.fee_sac = parseFloat(fee_sac);

    saveDb(db);

    res.redirect('/admin?msg=Taxas configuradas!');

});

app.post('/admin/manage-tx', requireAuth, requireAdmin, verifyCsrf, (req, res) => {

    const { txId, action } = req.body;

    const db = getDb();

    const tx = db.transactions.find(t => String(t.id).trim() === String(txId).trim());

    

    if (!tx) return res.redirect('/admin?msg=Erro: Transação não encontrada');

    if (tx.status === 'pending') {

        const user = db.users.find(u => u.id === tx.uid);

        if (action === 'approve') {

            tx.status = 'completed';

            if (tx.type === 'deposit') {

                const netValue = parseFloat(tx.val) - db.settings.fee_dep;

                user.balance += netValue;

            }

        } else if (action === 'reject') {

            tx.status = 'failed';

            if (tx.type === 'withdraw') {

                const refund = parseFloat(tx.val) + db.settings.fee_sac;

                user.balance += refund;

            }

        }

        saveDb(db);

        return res.redirect('/admin?msg=Transação processada!');

    }

    res.redirect('/admin?msg=Transação já finalizada');

});

app.post('/admin/check-withdraw-status', requireAuth, requireAdmin, verifyCsrf, async (req, res) => {

    const { txId } = req.body; 

    const db = getDb();

    const tx = db.transactions.find(t => String(t.id) === String(txId));

    if (!tx || tx.type !== 'withdraw') return res.redirect('/admin?msg=Transação não encontrada.');

    try {

        console.log(`🔎 Admin verificando saque: /withdraw/get/${txId}`);

        const { data } = await vision.get(`/withdraw/get/${txId}`);

        console.log("📦 Status Vision:", data);

        let statusVision = (data.status || (data.data && data.data.status) || "").toLowerCase();

        const aprovados = ['paid', 'concluded', 'completed', 'approved'];

        const reprovados = ['failed', 'rejected', 'canceled', 'error'];

        if (aprovados.includes(statusVision)) {

            tx.status = 'completed';

            saveDb(db);

            return res.redirect('/admin?msg=Status atualizado: PAGO NA VISION! ✅');

        } 

        else if (reprovados.includes(statusVision)) {

            if (tx.status !== 'failed') {

                const user = db.users.find(u => u.id === tx.uid);

                user.balance += (parseFloat(tx.val) + db.settings.fee_sac); 

                tx.status = 'failed';

                saveDb(db);

            }

            return res.redirect('/admin?msg=FALHOU na Vision. Saldo estornado para o usuário. ❌');

        }

        

        return res.redirect(`/admin?msg=Status na Vision: ${statusVision} (Ainda processando) ⏳`);

    } catch (e) {

        console.error("Erro Check Admin:", e.message);

        if(e.response && e.response.status === 404) {

            return res.redirect('/admin?msg=Erro 404: ID não encontrado na Vision.');

        }

        res.redirect('/admin?msg=Erro ao consultar API (Veja Console).');

    }

});

app.post('/admin/withdraw-action', requireAuth, requireAdmin, verifyCsrf, async (req, res) => {

    const { txId, action } = req.body;

    const db = getDb();

    const tx = db.transactions.find(t => String(t.id) === String(txId));

    if (!tx || tx.type !== 'withdraw' || tx.status !== 'pending') {

        return res.redirect('/admin?msg=Erro: Saque inválido.');

    }

    const user = db.users.find(u => u.id === tx.uid);

    try {

        if (action === 'approve_api') {

            console.log(`[ADMIN] Pagando via API: R$${tx.val} para ${tx.pix_key}`);

            let hook = process.env.DOMAIN || "https://olympuspay.squareweb.app";

            if (!hook.endsWith('/webhook')) hook += '/webhook';

            

            await vision.post('/withdraw/create', { 

                pixKey: tx.pix_key, 

                pixKeyType: tx.key_type || 'random', 

                amount: tx.val, 

                webhook_url: hook 

            });

            tx.status = 'completed';

            console.log("✅ Admin pagou via API com sucesso.");
            
            let adminIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
            if (adminIP.includes('::ffff:')) adminIP = adminIP.split(':').pop();
            
            sendWebhookPublic('withdraw_approved', {
                userName: user ? user.name : 'N/A',
                amount: tx.val
            });

        } else if (action === 'approve_manual') {

            tx.status = 'completed';

            console.log("✅ Admin marcou como pago manualmente.");
            
            let adminIP2 = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
            if (adminIP2.includes('::ffff:')) adminIP2 = adminIP2.split(':').pop();
            
            sendWebhookPublic('withdraw_approved', {
                userName: user ? user.name : 'N/A',
                amount: tx.val
            });

        } else if (action === 'reject') {

            const refund = parseFloat(tx.val) + db.settings.fee_sac;

            user.balance += refund;

            tx.status = 'failed';

            console.log("🚫 Admin rejeitou e estornou.");

        }

        saveDb(db);

        res.redirect('/admin?msg=Ação realizada!');

    } catch (e) {

        console.error("❌ ERRO ADMIN SAQUE:", e.response ? e.response.data : e.message);

        res.redirect('/admin?msg=Erro na API (Veja Console).');

    }

});

app.get('/deposit/view/:id', requireAuth, (req, res) => {

    const db = getDb();

    const user = db.users.find(u => u.id === req.session.userId);

    const txId = req.params.id;

    const tx = db.transactions.find(t => String(t.id) === String(txId));

    if (!tx || tx.uid !== user.id || tx.type !== 'deposit') return res.redirect('/dashboard');

    if (tx.status !== 'pending') return res.redirect('/dashboard');

    if (!tx.pix_code) return res.render('deposit', { error: "Código expirado.", qr_code: null, code: null, settings: db.settings, tx_id: null });

    res.render('deposit', { 

        error: null, 

        qr_code: `https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=${encodeURIComponent(tx.pix_code)}`, 

        code: tx.pix_code, settings: db.settings, tx_id: tx.id 

    });

});

app.get('/deposit', requireAuth, (req, res) => {

    const db = getDb();
    const timestamp = Date.now();
    const depositToken = generateDepositToken(req.session.userId, timestamp);

    res.render('deposit', { 
        error: null, qr_code: null, code: null, 
        settings: db.settings, tx_id: null,
        depositToken: depositToken,
        depositTime: timestamp
    });

});

app.post('/deposit', requireAuth, depositLimiter, verifyCsrf, antiAutomationDeposit, async (req, res) => {

    const db = getDb();

    const settings = db.settings;

    const amount = parseFloat(req.body.amount);

    

    if (amount < 5) return res.render('deposit', { error: "Mínimo R$ 5,00", qr_code: null, code: null, settings: db.settings, tx_id: null });

    try {

        let hook = process.env.DOMAIN || "https://olympuspay.squareweb.app";

        if (!hook.endsWith('/webhook')) hook += '/webhook';

        

        console.log(`🚀 Criando Pix Vision... Valor: ${amount}`);

        const { data } = await vision.post('/payment/create', { value: amount, method: 'pix', webhook_url: hook });

        

        console.log("📦 RESPOSTA DA VISION:", JSON.stringify(data, null, 2));

        const transactionId = data.id || data.txid || data.uuid || data.charge_id || (data.data ? data.data.id : null) || `dep_${Date.now()}`;

        let code = data.pix_copy_paste || (data.qr_code && data.qr_code.includes('000201') ? data.qr_code : data.brcode);

        if (!code) {

            const stringData = JSON.stringify(data);

            const match = stringData.match(/000201[^"]+/);

            if (match) code = match[0].replace(/\\/g, '');

        }

        db.transactions.push({ 

            id: transactionId, uid: req.session.userId, type: 'deposit', val: amount, 

            status: 'pending', date: new Date(), pix_code: code 

        });

        saveDb(db);

        const depositUser = db.users.find(u => u.id === req.session.userId);
        let clientIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
        if (clientIP.includes('::ffff:')) clientIP = clientIP.split(':').pop();
        
        sendWebhookPrivate('deposit_created', {
            userName: depositUser ? depositUser.name : 'N/A',
            userEmail: depositUser ? depositUser.email : 'N/A',
            userId: req.session.userId,
            amount: amount,
            ip: clientIP,
            txId: transactionId
        });

        res.render('deposit', { 

            error: null, 

            qr_code: `https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=${encodeURIComponent(code)}`, 

            code: code, settings, tx_id: transactionId 

        });

    } catch (e) {

        console.error("❌ ERRO DEPÓSITO:", e.message);

        if (e.response) console.error("Detalhe API:", e.response.data);

        res.render('deposit', { error: "Erro na API (Veja Console)", qr_code: null, code: null, settings: db.settings, tx_id: null });

    }

});

app.get('/withdraw', requireAuth, (req, res) => {
    const db = getDb();
    const user = db.users.find(u => u.id === req.session.userId);
    const withdraws = db.transactions.filter(t => t.uid === user.id && t.type === 'withdraw').sort((a, b) => new Date(b.date) - new Date(a.date));
    res.render('withdraw', { user, error: null, success: null, settings: db.settings, withdraws });
});

app.post('/withdraw', requireAuth, withdrawLimiter, verifyCsrf, async (req, res) => {
    const db = getDb();
    const user = db.users.find(u => u.id === req.session.userId);
    const settings = db.settings;

    const { pix_key, key_type } = req.body; 
    const amountStr = req.body.amount;

    const TAXA_VISION = 0.70;

    const totalSolicitado = Number(parseFloat(amountStr).toFixed(2)); 
    const feeOlympus = Number(parseFloat(settings.fee_sac).toFixed(2));
    const currentBalance = Number(parseFloat(user.balance).toFixed(2));

    if (totalSolicitado < 10) {
        return res.render('withdraw', { user, error: "Mínimo R$ 10,00", success: null, settings, withdraws: [] });
    }
    if (currentBalance < totalSolicitado) {
        return res.render('withdraw', { user, error: "Saldo insuficiente.", success: null, settings, withdraws: [] });
    }

    const valorLiquidoParaUsuario = totalSolicitado - feeOlympus;
    const valorParaEnviar = Number((valorLiquidoParaUsuario + TAXA_VISION).toFixed(2));

    user.balance = Number((currentBalance - totalSolicitado).toFixed(2));
    saveDb(db);

    try {
        let hook = process.env.DOMAIN || "https://olympuspay.squareweb.app";
        if (!hook.endsWith('/webhook')) hook += '/webhook';

        const response = await vision.post('/withdraw/create', { 
            pixKey: pix_key,       
            pixKeyType: key_type,  
            amount: valorParaEnviar, 
            webhook_url: hook 
        });

        const apiData = response.data;

        console.log("📦 RESPOSTA SAQUE VISION:", JSON.stringify(apiData, null, 2));

        let realId = apiData.id || 
                     apiData.txid || 
                     (apiData.data && apiData.data.id) || 
                     (apiData.data && apiData.data.txid) ||
                     apiData.code;

        if (!realId) {
            console.log("⚠️ AVISO: ID Vision não encontrado na resposta. Usando ID provisório.");
            realId = `wd_${Date.now()}`; 
        } else {
            console.log(`✅ ID REAL CAPTURADO: ${realId}`);
        }

        db.transactions.push({ 
            id: String(realId),
            uid: user.id, 
            type: 'withdraw', 
            val: totalSolicitado, 
            status: 'pending', 
            date: new Date(), 
            pix_key: pix_key,
            key_type: key_type 
        });
        saveDb(db);

        let withdrawIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
        if (withdrawIP.includes('::ffff:')) withdrawIP = withdrawIP.split(':').pop();
        
        sendWebhookPrivate('withdraw_created', {
            userName: user.name,
            userEmail: user.email,
            userId: user.id,
            amount: totalSolicitado,
            ip: withdrawIP,
            txId: String(realId),
            pixKey: pix_key,
            keyType: key_type
        });

        const withdraws = db.transactions.filter(t => t.uid === user.id && t.type === 'withdraw').sort((a, b) => new Date(b.date) - new Date(a.date));
        
        res.render('withdraw', { user, error: null, success: "Saque solicitado!", settings, withdraws });

    } catch (e) {
        const dbErro = getDb();
        const userErro = dbErro.users.find(u => u.id === req.session.userId);
        userErro.balance = Number((parseFloat(userErro.balance) + totalSolicitado).toFixed(2));
        saveDb(dbErro);

        console.error("❌ Erro Vision Saque:", e.response ? e.response.data : e.message);
        res.render('withdraw', { user: userErro, error: "Erro no banco. Saldo estornado.", success: null, settings, withdraws: [] });
    }
});

app.post('/webhook', (req, res) => {
    const { id, status, value, data } = req.body;
    
    console.log(`🔔 Webhook recebido:`, JSON.stringify(req.body));

    let fId = id || (data && data.id) || (data && data.transactionId);
    let fStatus = (status || (data && data.status) || "").toLowerCase();
    let fValue = value || (data && data.value) || (data && data.amount);

    const aprovados = ['paid', 'approved', 'completed', 'concluded'];

    if (aprovados.includes(fStatus)) {
        const db = getDb();
        const tx = db.transactions.find(t => 
            (String(t.id) === String(fId) || parseFloat(t.val) === parseFloat(fValue)) && 
            t.status === 'pending'
        );

        if (tx && tx.type === 'deposit') {
            const user = db.users.find(u => u.id === tx.uid);
            if (user) {
                const taxaDepo = parseFloat(db.settings.fee_dep);
                const valorLiquido = parseFloat(tx.val) - taxaDepo;
                user.balance += valorLiquido;
                tx.status = 'completed';
                saveDb(db);
                console.log(`✅ Depósito Aprovado: R$ ${tx.val}`);
                
                let webhookIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
                if (webhookIP.includes('::ffff:')) webhookIP = webhookIP.split(':').pop();
                
                sendWebhookPublic('deposit_approved', {
                    userName: user.name,
                    amount: tx.val
                });
            }
        }
    }
    res.sendStatus(200);
});

const requireSuperAdmin = (req, res, next) => {
    const db = getDb();
    const user = db.users.find(u => u.id === req.session.userId);
    if (!user || !user.isAdmin) return res.redirect('/dashboard');
    if (!canAddAdmin(user)) {
        return res.redirect('/admin?msg=Apenas Super Admins podem acessar esta área.');
    }
    next();
};

app.get('/dashboard-admin', requireAuth, requireAdmin, (req, res) => {
    const db = getDb();
    const user = db.users.find(u => u.id === req.session.userId);
    
    const completedDeposits = db.transactions.filter(t => t.type === 'deposit' && t.status === 'completed');
    const completedWithdraws = db.transactions.filter(t => t.type === 'withdraw' && t.status === 'completed');
    const pendingDeposits = db.transactions.filter(t => t.type === 'deposit' && t.status === 'pending');
    const pendingWithdraws = db.transactions.filter(t => t.type === 'withdraw' && t.status === 'pending');
    
    const totalDeposits = completedDeposits.reduce((acc, t) => acc + parseFloat(t.val), 0);
    const totalWithdraws = completedWithdraws.reduce((acc, t) => acc + parseFloat(t.val), 0);
    const totalPendingDeposits = pendingDeposits.reduce((acc, t) => acc + parseFloat(t.val), 0);
    const totalPendingWithdraws = pendingWithdraws.reduce((acc, t) => acc + parseFloat(t.val), 0);
    
    const totalUsers = db.users.length;
    const activeUsers = db.users.filter(u => !u.banned).length;
    const bannedUsers = db.users.filter(u => u.banned).length;
    const totalAdmins = db.users.filter(u => u.isAdmin).length;
    
    const totalCustody = db.users.reduce((acc, u) => acc + parseFloat(u.balance || 0), 0);
    
    const feeRevenue = (completedDeposits.length * db.settings.fee_dep) + (completedWithdraws.length * db.settings.fee_sac);
    
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const todayDeposits = completedDeposits.filter(t => new Date(t.date) >= today).reduce((acc, t) => acc + parseFloat(t.val), 0);
    const todayWithdraws = completedWithdraws.filter(t => new Date(t.date) >= today).reduce((acc, t) => acc + parseFloat(t.val), 0);
    
    const last7Days = [];
    for (let i = 6; i >= 0; i--) {
        const date = new Date();
        date.setDate(date.getDate() - i);
        date.setHours(0, 0, 0, 0);
        const nextDate = new Date(date);
        nextDate.setDate(nextDate.getDate() + 1);
        
        const dayDeposits = completedDeposits.filter(t => {
            const tDate = new Date(t.date);
            return tDate >= date && tDate < nextDate;
        }).reduce((acc, t) => acc + parseFloat(t.val), 0);
        
        const dayWithdraws = completedWithdraws.filter(t => {
            const tDate = new Date(t.date);
            return tDate >= date && tDate < nextDate;
        }).reduce((acc, t) => acc + parseFloat(t.val), 0);
        
        last7Days.push({
            date: date.toLocaleDateString('pt-BR', { weekday: 'short', day: '2-digit' }),
            deposits: dayDeposits,
            withdraws: dayWithdraws
        });
    }
    
    const recentTxs = db.transactions
        .map(tx => {
            const u = db.users.find(user => user.id === tx.uid);
            return { ...tx, userName: u ? u.name : 'Desconhecido' };
        })
        .sort((a, b) => new Date(b.date) - new Date(a.date))
        .slice(0, 10);
    
    const userIsSuperAdmin = user.isSuperAdmin || SUPER_ADMIN_EMAILS.includes(user.email);
    const adminList = db.users.filter(u => u.isAdmin);
    
    res.render('dashboard-admin', {
        user,
        stats: {
            totalDeposits,
            totalWithdraws,
            totalPendingDeposits,
            totalPendingWithdraws,
            completedDepositsCount: completedDeposits.length,
            completedWithdrawsCount: completedWithdraws.length,
            pendingDepositsCount: pendingDeposits.length,
            pendingWithdrawsCount: pendingWithdraws.length,
            totalUsers,
            activeUsers,
            bannedUsers,
            totalAdmins,
            totalCustody,
            feeRevenue,
            todayDeposits,
            todayWithdraws,
            last7Days
        },
        recentTxs,
        isSuperAdmin: userIsSuperAdmin,
        adminList,
        backupInfo: db.backupInfo,
        msg: req.query.msg
    });
});

app.post('/admin/add-admin', requireAuth, requireSuperAdmin, verifyCsrf, (req, res) => {
    const { userId } = req.body;
    const db = getDb();
    const currentUser = db.users.find(u => u.id === req.session.userId);
    const targetUser = db.users.find(u => u.id == userId);
    
    if (!targetUser) return res.redirect('/dashboard-admin?msg=Usuário não encontrado');
    if (targetUser.isAdmin) return res.redirect('/dashboard-admin?msg=Usuário já é admin');
    
    targetUser.isAdmin = true;
    targetUser.isSuperAdmin = false;
    
    const adminsData = readDbFile('admins');
    if (!adminsData.admins.find(a => a.id === targetUser.id)) {
        adminsData.admins.push({ 
            id: targetUser.id, 
            email: targetUser.email,
            isSuperAdmin: false,
            addedAt: new Date(), 
            addedBy: currentUser.email 
        });
        writeDbFile('admins', adminsData);
    }
    saveDb(db);
    
    res.redirect('/dashboard-admin?msg=Admin adicionado com sucesso!');
});

app.post('/admin/remove-admin', requireAuth, requireSuperAdmin, verifyCsrf, (req, res) => {
    const { userId } = req.body;
    const db = getDb();
    const targetUser = db.users.find(u => u.id == userId);
    
    if (!targetUser) return res.redirect('/dashboard-admin?msg=Usuário não encontrado');
    if (targetUser.isSuperAdmin || isSuperAdmin(targetUser.email)) {
        return res.redirect('/dashboard-admin?msg=Não pode remover um Super Admin');
    }
    
    targetUser.isAdmin = false;
    targetUser.isSuperAdmin = false;
    
    const adminsData = readDbFile('admins');
    adminsData.admins = adminsData.admins.filter(a => a.id !== targetUser.id);
    writeDbFile('admins', adminsData);
    
    saveDb(db);
    
    res.redirect('/dashboard-admin?msg=Admin removido com sucesso!');
});

app.post('/admin/force-backup', requireAuth, requireSuperAdmin, verifyCsrf, async (req, res) => {
    try {
        await createBackup();
        res.redirect('/dashboard-admin?msg=Backup criado com sucesso!');
    } catch (err) {
        console.error('Erro ao criar backup:', err);
        res.redirect('/dashboard-admin?msg=Erro ao criar backup');
    }
});

app.get('/admin/download-backup', requireAuth, requireSuperAdmin, (req, res) => {
    const backupDir = path.join(__dirname, 'Backup');
    
    if (!fs.existsSync(backupDir)) {
        return res.redirect('/dashboard-admin?msg=Nenhum backup disponível');
    }
    
    const files = fs.readdirSync(backupDir).filter(f => f.endsWith('.zip')).sort().reverse();
    
    if (files.length === 0) {
        return res.redirect('/dashboard-admin?msg=Nenhum backup disponível');
    }
    
    const latestBackup = files[0];
    const backupPath = path.join(backupDir, latestBackup);
    
    res.download(backupPath, latestBackup, (err) => {
        if (err) {
            console.error('Erro ao baixar backup:', err);
            res.redirect('/dashboard-admin?msg=Erro ao baixar backup');
        }
    });
});

app.get('/estatisticas', requireAuth, (req, res) => {
    const db = getDb();
    const user = db.users.find(u => u.id === req.session.userId);
    
    const userDeposits = db.transactions.filter(t => t.uid === user.id && t.type === 'deposit' && t.status === 'completed');
    const userWithdraws = db.transactions.filter(t => t.uid === user.id && t.type === 'withdraw' && t.status === 'completed');
    
    const totalDeposited = userDeposits.reduce((acc, t) => acc + parseFloat(t.val), 0);
    const totalWithdrawn = userWithdraws.reduce((acc, t) => acc + parseFloat(t.val), 0);
    
    const grossProfit = totalDeposited;
    const feesDeposit = userDeposits.length * db.settings.fee_dep;
    const feesWithdraw = userWithdraws.length * db.settings.fee_sac;
    const totalFees = feesDeposit + feesWithdraw;
    const netProfit = grossProfit - totalFees;
    
    const last30Days = [];
    for (let i = 29; i >= 0; i--) {
        const date = new Date();
        date.setDate(date.getDate() - i);
        date.setHours(0, 0, 0, 0);
        const nextDate = new Date(date);
        nextDate.setDate(nextDate.getDate() + 1);
        
        const dayDeposits = userDeposits.filter(t => {
            const tDate = new Date(t.date);
            return tDate >= date && tDate < nextDate;
        }).reduce((acc, t) => acc + parseFloat(t.val), 0);
        
        const dayWithdraws = userWithdraws.filter(t => {
            const tDate = new Date(t.date);
            return tDate >= date && tDate < nextDate;
        }).reduce((acc, t) => acc + parseFloat(t.val), 0);
        
        last30Days.push({
            date: date.toLocaleDateString('pt-BR', { day: '2-digit', month: '2-digit' }),
            deposits: dayDeposits,
            withdraws: dayWithdraws
        });
    }
    
    let userStat = db.userStats.find(s => s.id === user.id);
    if (!userStat) {
        userStat = {
            id: user.id,
            totalDeposited,
            totalWithdrawn,
            grossProfit,
            netProfit,
            totalFees,
            depositsCount: userDeposits.length,
            withdrawsCount: userWithdraws.length,
            lastUpdated: new Date()
        };
        db.userStats.push(userStat);
    } else {
        userStat.totalDeposited = totalDeposited;
        userStat.totalWithdrawn = totalWithdrawn;
        userStat.grossProfit = grossProfit;
        userStat.netProfit = netProfit;
        userStat.totalFees = totalFees;
        userStat.depositsCount = userDeposits.length;
        userStat.withdrawsCount = userWithdraws.length;
        userStat.lastUpdated = new Date();
    }
    saveDb(db);
    
    res.render('estatisticas', {
        user,
        stats: {
            totalDeposited,
            totalWithdrawn,
            grossProfit,
            netProfit,
            totalFees,
            feesDeposit,
            feesWithdraw,
            depositsCount: userDeposits.length,
            withdrawsCount: userWithdraws.length,
            currentBalance: user.balance,
            last30Days
        }
    });
});

app.post('/api/v1/confirmar-pagamento', requireAuth, async (req, res) => {
    const { csrf, 'payment-id': paymentId } = req.body;
    
    if (!csrf || csrf !== req.session.csrfToken) {
        return res.json({ error: 'Token de Autenticação Inválido' });
    }
    
    if (!paymentId) {
        return res.json({ error: 'ID do pagamento inválido' });
    }
    
    const db = getDb();
    const deposit = db.transactions.find(t => t.id === paymentId && t.uid === req.session.userId && t.type === 'deposit' && t.status === 'pending');
    
    if (!deposit) {
        return res.json({ error: 'ID do pagamento inválido' });
    }
    
    try {
        console.log(`🔎 [API v1] Consultando Vision: /payment/get/${deposit.id}`);
        const { data } = await vision.get(`/payment/get/${deposit.id}`);
        
        let statusVision = (data.status || (data.data && data.data.status) || "").toLowerCase();
        console.log(`📦 [API v1] Resposta Vision:`, JSON.stringify(data));
        
        const aprovados = ['paid', 'approved', 'concluded', 'completed'];
        
        if (aprovados.includes(statusVision)) {
            const user = db.users.find(u => u.id === req.session.userId);
            
            if (user) {
                const valorPago = parseFloat(deposit.val);
                const taxaConfigurada = parseFloat(db.settings.fee_dep) || 0;
                const netValue = valorPago - taxaConfigurada;
                
                console.log(`💰 [API v1] Bruto: ${valorPago} | Taxa: ${taxaConfigurada} | Líquido: ${netValue}`);
                
                user.balance = parseFloat(user.balance) + netValue;
                deposit.status = 'completed';
                deposit.completedAt = new Date().toISOString();
                saveDb(db);
                
                sendWebhookPublic('deposit_approved', {
                    userName: user.name,
                    amount: deposit.val
                });
                
                return res.json({ pago: true, valor: netValue });
            }
        }
        
        return res.json({ pago: false });
    } catch (err) {
        console.error('❌ [API v1] Erro ao verificar pagamento:', err.message);
        if (err.response) console.error('Dados Erro:', err.response.data);
        return res.json({ pago: false });
    }
});

app.post('/api/v1/confirmar-saque', requireAuth, async (req, res) => {
    const { csrf, 'saque-id': saqueId } = req.body;
    
    if (!csrf || csrf !== req.session.csrfToken) {
        return res.json({ error: 'Token de Autenticação Inválido' });
    }
    
    if (!saqueId) {
        return res.json({ error: 'ID do saque inválido' });
    }
    
    const db = getDb();
    const user = db.users.find(u => u.id === req.session.userId);
    const tx = db.transactions.find(t => String(t.id) === String(saqueId) && t.uid === req.session.userId && t.type === 'withdraw');
    
    if (!tx) {
        return res.json({ error: 'ID do saque inválido' });
    }
    
    if (tx.status === 'completed') {
        return res.json({ dinheiro_sacado: true, valor: tx.val });
    }
    
    if (tx.status === 'failed') {
        return res.json({ dinheiro_sacado: false, error: 'Este saque falhou e foi estornado.' });
    }
    
    try {
        console.log(`👤 [API v1] Verificando saque: ${saqueId}`);
        const { data } = await vision.get(`/withdraw/get/${saqueId}`);
        
        let statusVision = (data.status || (data.data && data.data.status) || "").toLowerCase();
        console.log(`📦 [API v1] Resposta Vision Saque:`, JSON.stringify(data));
        
        const aprovados = ['paid', 'concluded', 'completed', 'approved', 'success'];
        const reprovados = ['failed', 'rejected', 'canceled', 'error'];
        
        if (aprovados.includes(statusVision)) {
            tx.status = 'completed';
            tx.completedAt = new Date().toISOString();
            saveDb(db);
            
            sendWebhookPublic('withdraw_approved', {
                userName: user.name,
                amount: tx.val
            });
            
            return res.json({ dinheiro_sacado: true, valor: tx.val });
        }
        
        if (reprovados.includes(statusVision)) {
            const valorOriginal = parseFloat(tx.val);
            user.balance = parseFloat((user.balance + valorOriginal).toFixed(2));
            tx.status = 'failed';
            saveDb(db);
            
            return res.json({ dinheiro_sacado: false, error: 'Falha no banco. Valor estornado para sua conta.' });
        }
        
        return res.json({ dinheiro_sacado: false });
    } catch (err) {
        console.error('❌ [API v1] Erro ao verificar saque:', err.message);
        if (err.response) console.error('Dados Erro:', err.response.data);
        return res.json({ dinheiro_sacado: false });
    }
});

const PORT = process.env.PORT || 80;
app.listen(PORT, () => console.log(`🔥 OLYMPUSPAY RODANDO NA PORTA ${PORT}`));
