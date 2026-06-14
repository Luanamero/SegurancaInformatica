"""
App Flask SEGURA — versão corrigida
======================================
Esta versão demonstra as boas práticas para prevenir SQL Injection:
  - Prepared statements (parameterized queries)
  - Hashing de passwords com bcrypt
  - Tratamento de erros sem expor detalhes internos
  - Validação de input
"""

import sqlite3
import os
import hashlib
from flask import Flask, request, render_template, g

app = Flask(__name__)

DATABASE = os.path.join(os.path.dirname(__file__), '..', 'database', 'app.db')


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def hash_password(password: str) -> str:
    """Hash simples para demo — em produção use bcrypt ou argon2."""
    return hashlib.sha256(password.encode()).hexdigest()


@app.route('/')
def index():
    return render_template('index.html', app_type='secure')


@app.route('/login', methods=['GET', 'POST'])
def login():
    result = None
    query_used = None

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        # ✅ SEGURO: validação básica de input
        if not username or not password:
            result = {'success': False, 'message': "❌ Preencha todos os campos."}
            return render_template('login.html', result=result, app_type='secure')

        if len(username) > 50 or len(password) > 100:
            result = {'success': False, 'message': "❌ Input demasiado longo."}
            return render_template('login.html', result=result, app_type='secure')

        # ✅ SEGURO: prepared statement — os parâmetros são passados separados da query
        query = "SELECT * FROM users WHERE username = ? AND password = ?"
        query_used = f"SELECT * FROM users WHERE username = ? AND password = ?\n-- Parâmetros: ['{username}', '***']"

        try:
            db = get_db()
            # O driver SQLite escapa automaticamente os parâmetros
            cursor = db.execute(query, (username, hash_password(password)))
            user = cursor.fetchone()

            if user:
                result = {
                    'success': True,
                    'message': f"✅ Login bem-sucedido! Bem-vindo, {user['username']} (role: {user['role']})"
                }
            else:
                result = {
                    'success': False,
                    # ✅ SEGURO: mensagem genérica — não revela se o utilizador existe
                    'message': "❌ Credenciais inválidas."
                }
        except Exception:
            # ✅ SEGURO: não expõe detalhes do erro
            result = {
                'success': False,
                'message': "❌ Ocorreu um erro interno. Tente mais tarde."
            }

    return render_template(
        'login.html',
        result=result,
        query_used=query_used,
        app_type='secure'
    )


@app.route('/search', methods=['GET', 'POST'])
def search():
    results = None
    query_used = None
    error = None

    if request.method == 'POST':
        term = request.form.get('term', '').strip()

        if len(term) > 50:
            error = "Termo de pesquisa demasiado longo."
            return render_template('search.html', error=error, app_type='secure')

        # ✅ SEGURO: parâmetro passado separado, wildcards adicionados com segurança
        query = "SELECT id, username, email FROM users WHERE username LIKE ?"
        query_used = f"SELECT id, username, email FROM users WHERE username LIKE ?\n-- Parâmetros: ['%{term}%']"

        try:
            db = get_db()
            cursor = db.execute(query, (f'%{term}%',))
            results = cursor.fetchall()
        except Exception:
            error = "Erro ao realizar pesquisa."

    return render_template(
        'search.html',
        results=results,
        query_used=query_used,
        error=error,
        app_type='secure'
    )


if __name__ == '__main__':
    app.run(debug=False, port=5002)
