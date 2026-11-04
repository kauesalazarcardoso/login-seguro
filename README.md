# 🔐 Sistema de Login Seguro

Um sistema simples de autenticação feito em **Python com Flask**, rodando dentro do **Docker**.

A ideia do projeto é mostrar, na prática, como fazer um login que não seja só "funcionar", mas que também proteja os usuários contra os ataques mais comuns.

---

## 📋 O que o sistema faz

| Requisito | Como foi atendido |
|---|---|
| Cadastro de usuários | Tela de cadastro com usuário, e-mail e senha |
| Senhas com hash seguro | Senhas guardadas com **scrypt** (com salt), nunca em texto puro |
| Validação de login | Confere usuário e senha e cria uma sessão protegida |
| Controle de tentativas | Depois de **5 erros seguidos**, a conta fica bloqueada por **15 minutos** |
| Recuperação de senha | Link com token aleatório, válido por **15 minutos** e de **uso único** |

---

## 🗂️ Estrutura do projeto

```
login-seguro/
├── app.py                  # Todo o código do sistema (rotas, banco e segurança)
├── templates/              # Telas em HTML
│   ├── base.html
│   ├── cadastro.html
│   ├── login.html
│   ├── painel.html
│   ├── esqueci_senha.html
│   └── redefinir_senha.html
├── requirements.txt        # Bibliotecas usadas
├── Dockerfile              # Como montar a imagem do sistema
├── docker-compose.yml      # Como subir o container
├── .env.example            # Modelo das variáveis de ambiente
└── .gitignore
```

**Tecnologias:** Python 3.12, Flask 3, SQLite (banco em arquivo), Gunicorn (servidor) e Docker.

---

## 🚀 Como rodar o projeto (passo a passo)

### Pré-requisito
Ter o **Docker** e o **Docker Compose** instalados ([Docker Desktop](https://www.docker.com/products/docker-desktop/) já traz os dois).

### Passo 1 – Baixar o projeto
```bash
git clone https://github.com/kauesalazarcardoso/login-seguro.git
cd login-seguro
```

### Passo 2 – Criar o arquivo `.env`
Copie o modelo:
```bash
cp .env.example .env
```
(no Windows, dá pra só copiar o arquivo e renomear para `.env`)

Depois abra o `.env` e troque o valor de `SECRET_KEY` por uma chave aleatória. Para gerar uma:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### Passo 3 – Subir o container
```bash
docker compose up --build
```

### Passo 4 – Abrir no navegador
Acesse **http://localhost:5000** 🎉

> Se a porta 5000 já estiver ocupada no seu computador, troque o valor de `PORTA` no `.env` (por exemplo `PORTA=5001`) e acesse `http://localhost:5001`.

Para parar o sistema, aperte `Ctrl + C` ou rode `docker compose down`.

---

## 🧪 Como testar cada requisito

**1. Cadastro**
Clique em "Criar conta". Tente uma senha fraca como `123456`: o sistema não deixa. Use algo como `Senha@123`.

**2. Hash da senha**
Para ver como a senha ficou guardada no banco, rode:
```bash
docker compose exec web python -c "import sqlite3; print(sqlite3.connect('dados/usuarios.db').execute('select usuario, senha_hash from usuarios').fetchall())"
```
Vai aparecer algo como `scrypt:32768:8:1$...` em vez da senha.

**3. Login**
Entre com o usuário e a senha cadastrados. Você vai para o painel (área protegida). Se tentar abrir `/painel` sem estar logado, o sistema manda de volta para o login.

**4. Controle de tentativas**
Erre a senha 5 vezes seguidas. A conta fica bloqueada por 15 minutos, **mesmo se você acertar a senha depois**.

**5. Recuperação de senha**
Clique em "Esqueci minha senha" e digite o e-mail cadastrado. Como o projeto não tem um servidor de e-mail de verdade, o "e-mail" aparece no **terminal do Docker**, assim:
```
[E-MAIL SIMULADO] Para: voce@email.com
Link de recuperação: http://localhost:5000/redefinir-senha/abc123...
```
Abra o link, crie a nova senha e faça login com ela. Se tentar usar o mesmo link de novo, ele não funciona mais.

---

## 🛡️ Medidas de segurança (explicação passo a passo)

### 1. Hash seguro das senhas
A senha **nunca** é salva do jeito que o usuário digitou. Usamos a função `generate_password_hash` do Werkzeug (biblioteca que vem com o Flask), que aplica o algoritmo **scrypt**.

- **Por que hash?** O hash é um caminho de mão única: dá pra transformar a senha em hash, mas não dá pra voltar do hash para a senha. Se alguém roubar o banco, não vê as senhas.
- **Por que scrypt e não MD5 ou SHA-256?** MD5 e SHA são rápidos demais, o que facilita um atacante testar bilhões de senhas por segundo. O scrypt é feito para ser **lento e gastar memória** de propósito, o que torna ataques de força bruta muito caros.
- **Salt:** cada senha recebe um valor aleatório (salt) antes do hash. Assim, duas pessoas com a mesma senha têm hashes diferentes, e tabelas prontas de hashes (rainbow tables) não servem para nada.

Na hora do login, usamos `check_password_hash`, que faz o mesmo cálculo e compara o resultado.

### 2. Senha forte obrigatória
No cadastro e na troca de senha, a senha precisa ter **pelo menos 8 caracteres**, com **letra maiúscula, minúscula, número e símbolo**. Isso dificulta que alguém adivinhe a senha.

### 3. Controle de tentativas de acesso (contra força bruta)
Cada usuário tem um contador de erros no banco (`tentativas_falhas`).

1. Errou a senha → o contador sobe 1.
2. Chegou a **5 erros** → a conta é bloqueada por **15 minutos** (campo `bloqueado_ate`).
3. Durante o bloqueio, nem a senha certa entra.
4. Acertou a senha (fora do bloqueio) → o contador volta para zero.

O bloqueio também fica registrado no log do servidor, para quem administra o sistema perceber um possível ataque.

### 4. Mensagens genéricas (não entregar informação)
Quando o login falha, a mensagem é sempre **"Usuário ou senha inválidos"**, sem dizer qual dos dois está errado. Assim, um atacante não descobre quais usuários existem.

Além disso, quando o usuário não existe, o sistema mesmo assim faz uma verificação de hash "falsa". Isso deixa o tempo de resposta parecido nos dois casos, para que ninguém consiga descobrir usuários só medindo o tempo.

Na recuperação de senha acontece a mesma coisa: a resposta é sempre *"Se o e-mail estiver cadastrado, você vai receber um link"*.

### 5. Recuperação de senha segura
1. O usuário informa o e-mail.
2. O sistema gera um token com `secrets.token_urlsafe(32)`, que é **aleatório e impossível de adivinhar**.
3. No banco, guardamos só o **hash SHA-256 do token**, e não o token em si. Se o banco vazar, os links não podem ser usados.
4. O link vale por apenas **15 minutos**.
5. O token é de **uso único**: depois de trocar a senha, ele é marcado como usado. Pedir um link novo também cancela os anteriores.
6. Ao trocar a senha, o bloqueio da conta é zerado.

> Num sistema real, o link seria enviado por e-mail (com SMTP). Aqui ele aparece no log do servidor só para facilitar o teste.

### 6. Proteção contra SQL Injection
Todas as consultas ao banco usam **parâmetros** (`?`), por exemplo:
```python
db.execute("SELECT * FROM usuarios WHERE usuario = ?", (usuario,))
```
Assim, o que o usuário digita é sempre tratado como **texto**, nunca como comando SQL.

### 7. Proteção contra CSRF
CSRF é quando um site malicioso tenta fazer o seu navegador enviar um formulário sem você saber. Para evitar isso, todo formulário tem um **token CSRF** escondido, gerado para cada sessão. Se o token não vier ou estiver errado, o sistema recusa a requisição (erro 400). A comparação é feita com `secrets.compare_digest`, que é segura contra ataques de tempo.

O botão de "Sair" também é um formulário com token, para ninguém conseguir deslogar o usuário por um link.

### 8. Sessão protegida
- `SECRET_KEY` vem de **variável de ambiente** (arquivo `.env`), e não fica escrita no código nem vai para o GitHub.
- O cookie de sessão é **HttpOnly** (JavaScript não consegue ler, o que ajuda contra XSS).
- **SameSite=Lax** (ajuda contra CSRF).
- **Secure** pode ser ligado com `COOKIE_SEGURO=1` quando o site usar HTTPS.
- A sessão expira em **30 minutos**.
- No login, a sessão antiga é apagada (`session.clear()`) e uma nova é criada. Isso evita o ataque de **fixação de sessão**.

### 9. Cabeçalhos de segurança
Toda resposta vai com alguns cabeçalhos HTTP que deixam o navegador mais protegido:
- `X-Frame-Options: DENY` → impede que o site seja colocado dentro de outro (contra *clickjacking*).
- `X-Content-Type-Options: nosniff` → o navegador não "adivinha" o tipo dos arquivos.
- `Content-Security-Policy` → só permite carregar conteúdo do próprio site.
- `Referrer-Policy: no-referrer` → evita vazar o link de recuperação para outros sites.

### 10. Proteção contra XSS
As telas usam o **Jinja2** (motor de templates do Flask), que escapa automaticamente tudo o que é exibido. Se alguém cadastrar algo como `<script>`, isso aparece como texto e não é executado. O cadastro também só aceita letras, números e `_` no nome de usuário.

### 11. Docker com usuário comum
O container roda com um usuário chamado `appuser`, e **não como root**. Se alguém conseguir invadir a aplicação, terá menos poder dentro do container. O sistema usa o **Gunicorn**, que é um servidor próprio para produção (o servidor de desenvolvimento do Flask não é recomendado para isso).

### 12. Arquivos sensíveis fora do Git
O `.gitignore` impede que o `.env` (com a chave secreta) e o banco de dados (`dados/`) sejam enviados para o GitHub.

---

## ⚠️ Limitações (o que melhoraria numa versão real)

- Envio de e-mail de verdade (SMTP) na recuperação de senha.
- HTTPS na frente da aplicação (por exemplo com Nginx ou um serviço como Cloudflare).
- Limite de tentativas também por IP, e não só por conta.
- Autenticação em dois fatores (2FA).
- Um banco mais robusto, como PostgreSQL, se houver muitos usuários.

---

## 👤 Autor

**Kauê Salazar Cardoso**
Análise e Desenvolvimento de Sistemas – IFRS Campus Rolante
