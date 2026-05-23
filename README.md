# Olimpo Pay

Plataforma de pagamentos e carteira digital construída com Node.js e Express. Permite que usuários depositem saldo via PIX, realizem saques, gerem cobranças via API e acompanhem transações em tempo real.

---

## Funcionalidades

- **Carteira digital** — saldo por usuário com histórico completo de transações
- **Depósito via PIX** — integração com gateway de pagamento (VisionPay) para geração de QR Code
- **Saque via PIX** — solicitação e processamento de saques com aprovação admin
- **API de cobranças** — gere e consulte pagamentos via API Key
- **Painel Admin** — gestão de usuários, transações, saques e configurações
- **Super Admin** — gestão de admins, backups manuais e download de backup
- **Estatísticas** — gráficos de depósitos, saques e uso por usuário
- **Desenvolvedor** — geração de API Key, webhook configurável e documentação integrada
- **Proteções de segurança** — rate limiting, CSRF, XSS, helmet, anti-automação, geolocalização por IP
- **Perfil** — upload de avatar, edição de dados

---

## Stack

| Camada | Tecnologia |
|---|---|
| Runtime | Node.js |
| Framework | Express |
| Template engine | EJS |
| Autenticação | express-session + bcrypt |
| Pagamentos | VisionPay (PIX) |
| Segurança | helmet, xss, express-rate-limit |
| Geolocalização | geoip-lite + express-useragent |
| Upload de arquivos | multer |
| Banco de dados | JSON em arquivos (pasta `DBs/`) |
| Deploy | SquareCloud |

---

## Pré-requisitos

- Node.js 18+
- npm

---

## Instalação

```bash
# Clone o repositório
git clone https://github.com/lucasribeiroxzz/gateway-src
cd gateway-src

# Instale as dependências
npm install

# Configure as variáveis de ambiente
cp .env.example .env
# Edite o .env com suas credenciais

# Inicie o servidor
npm start
```

---

## Variáveis de Ambiente

| Variável | Descrição |
|---|---|
| `VISION_KEY` | Chave de API do gateway VisionPay |
| `DOMAIN` | URL base do seu domínio |
| `SESSION_SECRET` | Segredo para criptografar sessões |
| `PORT` | Porta do servidor (padrão: 80) |
| `NODE_ENV` | Ambiente (`production` ou `development`) |
| `ADMIN_EMAIL` | E-mail do administrador principal |
| `WEBHOOK_URL` | URL de webhook privado (notificações admin) |
| `WEBHOOK_PUBLIC_URL` | URL de webhook público |

---

## Estrutura

```
olimpo-pay/
├── index.js          # Servidor principal, todas as rotas e lógica
├── views/            # Templates EJS
│   ├── landing.ejs         # Página inicial
│   ├── login.ejs           # Login
│   ├── register.ejs        # Cadastro
│   ├── dashboard.ejs       # Painel do usuário
│   ├── dashboard-admin.ejs # Painel admin completo
│   ├── admin.ejs           # Gestão de usuários/transações
│   ├── deposit.ejs         # Depósito via PIX
│   ├── withdraw.ejs        # Saque via PIX
│   ├── developer.ejs       # API Key e webhook
│   ├── estatisticas.ejs    # Gráficos e estatísticas
│   ├── docs.ejs            # Documentação da API
│   ├── terms.ejs           # Termos de uso
│   └── partials/
│       └── footer.ejs
├── public/           # Arquivos estáticos
│   ├── style.css
│   └── avatars/      # Avatars de usuários (gerado em runtime)
├── DBs/              # Banco de dados JSON (gerado em runtime)
│   ├── users.json
│   ├── admins.json
│   ├── transactions.json
│   ├── pending.json
│   ├── stats.json
│   ├── settings.json
│   └── backups.json
├── package.json
├── squarecloud.config
└── .env
```

---

## API

Autenticação via header `Authorization: Bearer <api_key>` ou query param `?api_key=`.

| Método | Endpoint | Descrição |
|---|---|---|
| GET | `/api/v1/balance` | Saldo da conta |
| POST | `/api/v1/pay` | Gerar cobrança PIX |
| GET | `/api/v1/payment/:id` | Consultar status de cobrança |
| POST | `/api/v1/withdraw` | Solicitar saque |
| GET | `/api/v1/withdraw/:id` | Consultar status de saque |

Documentação completa disponível em `/docs` na aplicação.

---

## Deploy (SquareCloud)

O arquivo `squarecloud.config` já está configurado. Basta fazer upload do projeto no [SquareCloud](https://squarecloud.app) e configurar as variáveis de ambiente no painel.

---

## Licença

Projeto privado. Todos os direitos reservados.
