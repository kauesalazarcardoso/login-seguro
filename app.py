"""
Sistema de Login Seguro - Flask
Cadastro, login com hash de senha, bloqueio por tentativas e recuperação de senha.
"""
import hashlib
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

# ------------------------------------------------------------------
# Configurações
# ------------------------------------------------------------------
app = Flask(__name__)

# A chave secreta vem de variável de ambiente (nunca fica fixa no código)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

# Cookie de sessão protegido
app.config["SESSION_COOKIE_HTTPONLY"] = True      # JavaScript não lê o cookie
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"     # ajuda contra CSRF
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SEGURO", "0") == "1"  # só HTTPS
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)

CAMINHO_BANCO = os.environ.get("CAMINHO_BANCO", "dados/usuarios.db")
MAX_TENTATIVAS = 5                 # erros seguidos antes de bloquear
TEMPO_BLOQUEIO = timedelta(minutes=15)
VALIDADE_TOKEN = timedelta(minutes=15)

# Hash "falso" usado quando o usuário não existe, para o tempo de resposta
# ser parecido e não entregar quais usuários existem
HASH_FALSO = generate_password_hash("senha-qualquer-para-igualar-tempo")


# ------------------------------------------------------------------
# Banco de dados (SQLite)
# ------------------------------------------------------------------
def banco():
    if "db" not in g:
        g.db = sqlite3.connect(CAMINHO_BANCO)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def fechar_banco(_erro):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def criar_tabelas():
    os.makedirs(os.path.dirname(CAMINHO_BANCO) or ".", exist_ok=True)
    with sqlite3.connect(CAMINHO_BANCO) as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            senha_hash TEXT NOT NULL,
            tentativas_falhas INTEGER NOT NULL DEFAULT 0,
            bloqueado_ate TEXT
        );
        CREATE TABLE IF NOT EXISTS tokens_recuperacao (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL,
            expira_em TEXT NOT NULL,
            usado INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
        );
        """)


# ------------------------------------------------------------------
# Funções de apoio
# ------------------------------------------------------------------
def senha_forte(senha):
    """Mínimo de 8 caracteres, com letra maiúscula, minúscula, número e símbolo."""
    return (len(senha) >= 8
            and re.search(r"[a-z]", senha)
            and re.search(r"[A-Z]", senha)
            and re.search(r"\d", senha)
            and re.search(r"[^A-Za-z0-9]", senha))


def hash_token(token):
    """Guardamos só o hash do token de recuperação, nunca o token puro."""
    return hashlib.sha256(token.encode()).hexdigest()


def token_csrf():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(32)
    return session["csrf"]


app.jinja_env.globals["token_csrf"] = token_csrf


@app.before_request
def verificar_csrf():
    """Todo formulário (POST) precisa mandar o token CSRF certo."""
    if request.method == "POST":
        enviado = request.form.get("csrf", "")
        if not secrets.compare_digest(enviado, session.get("csrf", "")):
            abort(400, "Token CSRF inválido")


@app.after_request
def cabecalhos_seguranca(resposta):
    resposta.headers["X-Content-Type-Options"] = "nosniff"
    resposta.headers["X-Frame-Options"] = "DENY"
    resposta.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'"
    resposta.headers["Referrer-Policy"] = "no-referrer"
    return resposta


def login_obrigatorio(func):
    @wraps(func)
    def protegida(*args, **kwargs):
        if "usuario_id" not in session:
            flash("Faça login para continuar.")
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return protegida


# ------------------------------------------------------------------
# Rotas
# ------------------------------------------------------------------
@app.route("/")
def inicio():
    if "usuario_id" in session:
        return redirect(url_for("painel"))
    return redirect(url_for("login"))


@app.route("/cadastro", methods=["GET", "POST"])
def cadastro():
    if request.method == "POST":
        usuario = request.form.get("usuario", "").strip()
        email = request.form.get("email", "").strip().lower()
        senha = request.form.get("senha", "")
        confirmar = request.form.get("confirmar", "")

        if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", usuario):
            flash("Usuário deve ter de 3 a 30 letras, números ou _.")
        elif not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            flash("E-mail inválido.")
        elif not senha_forte(senha):
            flash("A senha precisa ter 8+ caracteres, maiúscula, minúscula, número e símbolo.")
        elif senha != confirmar:
            flash("As senhas não conferem.")
        else:
            try:
                # Consulta parametrizada (?): evita SQL Injection
                banco().execute(
                    "INSERT INTO usuarios (usuario, email, senha_hash) VALUES (?, ?, ?)",
                    (usuario, email, generate_password_hash(senha)),
                )
                banco().commit()
                flash("Cadastro feito! Agora é só entrar.")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("Usuário ou e-mail já cadastrado.")
    return render_template("cadastro.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        usuario = request.form.get("usuario", "").strip()
        senha = request.form.get("senha", "")
        db = banco()
        user = db.execute("SELECT * FROM usuarios WHERE usuario = ?", (usuario,)).fetchone()

        # Usuário não existe: confere com hash falso e devolve a mesma mensagem genérica
        if user is None:
            check_password_hash(HASH_FALSO, senha)
            flash("Usuário ou senha inválidos.")
            return render_template("login.html"), 401

        # Conta bloqueada por excesso de tentativas?
        if user["bloqueado_ate"]:
            bloqueio = datetime.fromisoformat(user["bloqueado_ate"])
            if datetime.utcnow() < bloqueio:
                minutos = int((bloqueio - datetime.utcnow()).total_seconds() // 60) + 1
                flash(f"Conta bloqueada por excesso de tentativas. Tente de novo em {minutos} min.")
                return render_template("login.html"), 429

        if check_password_hash(user["senha_hash"], senha):
            # Deu certo: zera o contador e cria uma sessão nova
            db.execute("UPDATE usuarios SET tentativas_falhas = 0, bloqueado_ate = NULL WHERE id = ?",
                       (user["id"],))
            db.commit()
            session.clear()                  # evita fixação de sessão
            session.permanent = True
            session["usuario_id"] = user["id"]
            session["usuario"] = user["usuario"]
            return redirect(url_for("painel"))

        # Senha errada: soma uma tentativa e bloqueia se passar do limite
        tentativas = user["tentativas_falhas"] + 1
        bloqueado_ate = None
        if tentativas >= MAX_TENTATIVAS:
            bloqueado_ate = (datetime.utcnow() + TEMPO_BLOQUEIO).isoformat()
            tentativas = 0
            app.logger.warning("Conta '%s' bloqueada por excesso de tentativas", usuario)
        db.execute("UPDATE usuarios SET tentativas_falhas = ?, bloqueado_ate = ? WHERE id = ?",
                   (tentativas, bloqueado_ate, user["id"]))
        db.commit()
        if bloqueado_ate:
            flash("Muitas tentativas erradas. Conta bloqueada por 15 minutos.")
            return render_template("login.html"), 429
        flash("Usuário ou senha inválidos.")
        return render_template("login.html"), 401
    return render_template("login.html")


@app.route("/painel")
@login_obrigatorio
def painel():
    return render_template("painel.html", usuario=session["usuario"])


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("Você saiu do sistema.")
    return redirect(url_for("login"))


@app.route("/esqueci-senha", methods=["GET", "POST"])
def esqueci_senha():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        db = banco()
        user = db.execute("SELECT id FROM usuarios WHERE email = ?", (email,)).fetchone()
        if user:
            token = secrets.token_urlsafe(32)   # token aleatório e imprevisível
            db.execute("UPDATE tokens_recuperacao SET usado = 1 WHERE usuario_id = ?", (user["id"],))
            db.execute(
                "INSERT INTO tokens_recuperacao (usuario_id, token_hash, expira_em) VALUES (?, ?, ?)",
                (user["id"], hash_token(token), (datetime.utcnow() + VALIDADE_TOKEN).isoformat()),
            )
            db.commit()
            link = url_for("redefinir_senha", token=token, _external=True)
            # Em um sistema real, isso seria enviado por e-mail.
            # Aqui simulamos o envio mostrando o link no log do servidor.
            print(f"\n[E-MAIL SIMULADO] Para: {email}\nLink de recuperação: {link}\n", flush=True)
        # Mesma mensagem existindo ou não o e-mail (não revela quem é cadastrado)
        flash("Se o e-mail estiver cadastrado, você vai receber um link de recuperação.")
        return redirect(url_for("login"))
    return render_template("esqueci_senha.html")


@app.route("/redefinir-senha/<token>", methods=["GET", "POST"])
def redefinir_senha(token):
    db = banco()
    registro = db.execute(
        "SELECT * FROM tokens_recuperacao WHERE token_hash = ? AND usado = 0",
        (hash_token(token),),
    ).fetchone()

    if registro is None or datetime.utcnow() > datetime.fromisoformat(registro["expira_em"]):
        flash("Link inválido ou expirado. Peça um novo.")
        return redirect(url_for("esqueci_senha"))

    if request.method == "POST":
        senha = request.form.get("senha", "")
        confirmar = request.form.get("confirmar", "")
        if not senha_forte(senha):
            flash("A senha precisa ter 8+ caracteres, maiúscula, minúscula, número e símbolo.")
        elif senha != confirmar:
            flash("As senhas não conferem.")
        else:
            db.execute(
                "UPDATE usuarios SET senha_hash = ?, tentativas_falhas = 0, bloqueado_ate = NULL WHERE id = ?",
                (generate_password_hash(senha), registro["usuario_id"]),
            )
            db.execute("UPDATE tokens_recuperacao SET usado = 1 WHERE id = ?", (registro["id"],))
            db.commit()
            flash("Senha alterada com sucesso! Faça login.")
            return redirect(url_for("login"))
    return render_template("redefinir_senha.html", token=token)


criar_tabelas()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
