# BF Barbearia — Revisão de segurança do backend

**Data:** 14/10/2026
**Âmbito:** `src/` (Flask + SQLAlchemy + APScheduler + integração Evolution API), commit `4aa6749`
**Tipo:** revisão manual de código. Não foram feitos testes de intrusão contra o servidor em produção.

## Resumo

Foram encontrados **5 problemas críticos**, **5 altos** e **6 médios**. Os críticos podem ser explorados hoje por qualquer pessoa, sem conta e sem conhecimentos avançados:

- cancelar todas as marcações e ver os dados pessoais dos clientes;
- fazer-se passar por um cliente no fluxo do Caça-Vagas;
- injetar código JavaScript na página de cancelamento;
- forjar a sessão de admin, se a API key da Evolution vazar ou se as variáveis de ambiente faltarem.

**Ordem de correção sugerida:** C1 → C2 → C4/C5 → C3 → A3/A4 → restantes.

| # | Severidade | Problema | Ficheiro |
|---|---|---|---|
| C1 | 🔴 Crítico | Cancelamento público com IDs sequenciais | `src/rotas/cliente.py:460` |
| C2 | 🔴 Crítico | Webhook do WhatsApp sem autenticação + wildcard no `LIKE` | `src/rotas/cliente.py:257` |
| C3 | 🔴 Crítico | XSS guardado na página de cancelamento | `src/rotas/cliente.py:493, 519` |
| C4 | 🔴 Crítico | `FLASK_SECRET_KEY` usada também como API key da Evolution | `admin.py:220, 315` · `cliente.py:167, 411` |
| C5 | 🔴 Crítico | Credenciais e chave de sessão com valores por defeito | `src/rotas/admin.py:31-32` · `src/__init__.py:39` |
| A1 | 🟠 Alto | Login sem limite de tentativas, password em texto simples | `src/rotas/admin.py:35` |
| A2 | 🟠 Alto | Formulário público sem proteção contra bots | `src/rotas/cliente.py:21` |
| A3 | 🟠 Alto | Sem validação dos campos recebidos no backend | `src/rotas/cliente.py:30-37` |
| A4 | 🟠 Alto | Condição de corrida permite marcações duplicadas | `src/rotas/cliente.py:72` |
| A5 | 🟠 Alto | Sem CSRF e cookies de sessão sem flags de segurança | `src/__init__.py`, rotas admin |
| M1–M6 | 🟡 Médio | Ver secção própria | — |

---

## 🔴 Crítico

### C1 — Qualquer pessoa pode cancelar marcações e ver dados de clientes
**Onde:** `src/rotas/cliente.py:460` (`/cancelar_vaga/<int:id_agendamento>`)

O link de cancelamento enviado por WhatsApp usa o ID da base de dados, que é sequencial. Basta percorrer `/cancelar_vaga/1`, `/2`, `/3`… para:
- ver o nome, o dia e a hora de cada cliente (pedido GET);
- cancelar todas as marcações (pedido POST);
- pôr o Caça-Vagas a enviar WhatsApps em cadeia para outros clientes.

**Correção:** acrescentar ao modelo um token aleatório, gerá-lo ao criar cada marcação e usá-lo no link.

```python
# models.py
import secrets
token = db.Column(db.String(32), unique=True, default=lambda: secrets.token_urlsafe(16))

# rota
@cliente_bp.route('/cancelar/<token>', methods=['GET', 'POST'])
...
agendamento = Agendamentos.query.filter_by(token=token).first()
```

### C2 — Webhook do WhatsApp sem autenticação
**Onde:** `src/rotas/cliente.py:257` (`/webhook/confirmar-antecipacao`)

O endpoint aceita qualquer POST. Um atacante pode enviar um JSON com o número de um cliente e aceitar ou recusar a vaga por ele. Além disso, a pesquisa `Agendamentos.telemovel.like(f"%{telemovel_remetente}%")` aceita wildcards: um `remoteJid` igual a `%@s.whatsapp.net` encaixa em **qualquer** cliente com proposta pendente.

**Correção:**
1. Configurar o webhook na Evolution API com um segredo (header próprio ou token no URL) e rejeitar pedidos sem esse segredo:
   ```python
   if not hmac.compare_digest(request.headers.get('X-Webhook-Token', ''), os.environ['WEBHOOK_TOKEN']):
       abort(403)
   ```
2. Normalizar o número e fazer comparação exata (`==`), sem `LIKE`.

### C3 — XSS guardado na página de cancelamento
**Onde:** `src/rotas/cliente.py:493` e `:519`

As páginas de cancelamento são montadas com f-strings e o `agendamento.nome` é inserido sem escape. Uma marcação feita com o nome `<script>…</script>` executa esse código no browser de quem abrir o link de cancelamento.

**Correção:** passar estas duas páginas para templates Jinja (`render_template`), que fazem o escape automático. Isto também elimina o HTML duplicado no Python. Nota: há uma tag inválida `</name_cliente>` na linha 498.

### C4 — A chave de sessão do Flask é enviada como API key da Evolution
**Onde:** `src/rotas/admin.py:220` e `:315`, `src/rotas/cliente.py:167` e `:411`

`os.getenv("FLASK_SECRET_KEY")` é usado como header `apikey` em todos os pedidos à Evolution API, que passam por um túnel ngrok. Quem obtiver este valor consegue assinar um cookie de sessão com `admin_logado=True` e entrar no painel sem password.

**Correção:** criar uma variável `EVOLUTION_API_KEY` separada e mudar a `FLASK_SECRET_KEY` em produção (a atual deve ser considerada comprometida).

### C5 — Segredos com valores por defeito
**Onde:** `src/rotas/admin.py:31-32`, `src/__init__.py:39`

Se o `.env` não for carregado em produção:
- o login de admin fica `chave_local` / `chave_local`;
- a chave de sessão fica `chave-secreta-provisoria-para-dev`, que está publicada no código.

**Correção:** sem valores por defeito, para a app recusar arrancar se faltar alguma variável:
```python
SECRET_KEY = os.environ["FLASK_SECRET_KEY"]
```

---

## 🟠 Alto

### A1 — Login sem proteção contra força bruta
**Onde:** `src/rotas/admin.py:35`

Não há limite de tentativas, a password é guardada em texto simples na variável de ambiente e a comparação (`==`) não é de tempo constante.

**Correção:** guardar a password como hash (`werkzeug.security.generate_password_hash` / `check_password_hash`) e limitar as tentativas, por exemplo com Flask-Limiter (`5 per minute` na rota de login).

### A2 — Formulário público sem proteção contra bots
**Onde:** `src/rotas/cliente.py:21` (`/agendar`)

Um bot pode encher a agenda inteira e pôr o número da barbearia a enviar WhatsApps para números de terceiros. Isto arrisca o banimento do número pelo WhatsApp.

**Correção:** limitar pedidos por IP (Flask-Limiter) e acrescentar um campo honeypot invisível ou o Cloudflare Turnstile.

### A3 — Sem validação de input no backend
**Onde:** `src/rotas/cliente.py:30-37`

`servico`, `barbeiro`, `hora`, `canal` e `data` são aceites tal como chegam. Na prática dá para:
- marcar a horas fora de `HORARIOS` (ex.: `03:00`);
- marcar ao domingo ou à segunda (o bloqueio só existe em `/verificar-disponibilidade`, não em `/agendar`);
- usar valores de barbeiro ou serviço inventados;
- enviar uma `data` inválida, que passa a comparação de strings com a data atual;
- provocar um erro 500 com um nome maior do que a coluna (100 caracteres).

**Correção:** validar contra listas permitidas (`HORARIOS`, serviços, barbeiros, canais), fazer `datetime.strptime` à data, repetir o bloqueio de domingo e segunda, e limitar o tamanho do nome.

### A4 — Marcações duplicadas por condição de corrida
**Onde:** `src/rotas/cliente.py:72` e `src/rotas/admin.py:129`

O código verifica se o horário está livre e só depois insere. Dois pedidos em simultâneo passam ambos na verificação.

**Correção:** índice único parcial no PostgreSQL e tratamento do `IntegrityError`:
```sql
CREATE UNIQUE INDEX uniq_vaga_ativa ON agendamentos (data, hora, barbeiro) WHERE status = 'ativo';
```

### A5 — Sem CSRF e cookies sem flags de segurança
**Onde:** `src/__init__.py`, rotas `POST /admin/cancelar/<id>` e `/admin/marcar`

**Correção:**
```python
app.config.update(SESSION_COOKIE_SECURE=True, SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_HTTPONLY=True)
```
Acrescentar `CSRFProtect` (Flask-WTF) e mudar `/admin/logout` para POST.

---

## 🟡 Médio

| # | Problema | Onde | Correção |
|---|---|---|---|
| M1 | URL ngrok no código como valor por defeito. Se a variável faltar, dados de clientes e a API key vão para um domínio ngrok que pode passar para outra pessoa. Em `cliente.py:166` esse valor por defeito já inclui o caminho, por isso o URL final fica com o caminho repetido. | `admin.py:219, 314` · `cliente.py:166, 409` | Variável obrigatória, sem valor por defeito |
| M2 | Dados pessoais (nomes, telemóveis, mensagens completas) escritos nos logs com `print`. Ficam guardados no Render e contam para o RGPD. | `cliente.py`, `admin.py` | Usar `logging` e registar só os IDs |
| M3 | Link de cancelamento em `http://` | `cliente.py:127` | `https://` |
| M4 | Sem headers de segurança: o painel pode ser carregado dentro de um iframe noutro site (clickjacking) | global | `X-Frame-Options: DENY` + CSP básica num `after_request` |
| M5 | Mensagens de erro com HTML montado à mão e valores do pedido inseridos sem escape (XSS refletido no admin, explorável via CSRF) | `admin.py:137` | Templates ou `markupsafe.escape` |
| M6 | Dependências sem versão fixa (`APScheduler>=3.10.0`, `pytz`) | `requirements.txt` | Fixar versões e correr `pip-audit` periodicamente |

---

## Nota de fiabilidade (fora do âmbito de segurança)

O APScheduler arranca dentro de `create_app()`, ou seja, dentro de cada worker do gunicorn:
- com mais de 1 worker, os lembretes das 08:00 saem em duplicado;
- os temporizadores de 30 minutos do Caça-Vagas ficam só em memória e perdem-se a cada restart ou deploy.

**Sugestão:** correr o scheduler num processo próprio (por exemplo, um worker separado no `Procfile`) ou usar um job store persistente (`SQLAlchemyJobStore`).
