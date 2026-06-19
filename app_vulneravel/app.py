"""
App Flask VULNERÁVEL a SQL Injection
======================================
AVISO: Este código é INTENCIONALMENTE inseguro para fins educativos.
NUNCA use este padrão em produção.

Vulnerabilidades demonstradas:
  - Login bypass com ' OR '1'='1
  - UNION-based data extraction
  - Error-based information disclosure
"""

import sqlite3
import os
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


@app.route('/')
def index():
    return render_template('index.html', app_type='vulnerable')


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    result = None
    query_used = None

    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        # VULNERÁVEL: concatenação direta de strings — nunca faça isto!
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        query_used = query

        try:
            db = get_db()
            cursor = db.execute(query)
            user = cursor.fetchone()

            if user:
                result = {
                    'success': True,
                    'message': f" Login bem-sucedido! Bem-vindo, {user['username']} (role: {user['role']})"
                }
            else:
                result = {
                    'success': False,
                    'message': " Credenciais inválidas."
                }
        except Exception as e:
            #  VULNERÁVEL: expõe erros internos da base de dados
            result = {
                'success': False,
                'message': f" Erro SQL: {str(e)}"
            }

    return render_template(
        'login.html',
        error=error,
        result=result,
        query_used=query_used,
        app_type='vulnerable'
    )


@app.route('/search', methods=['GET', 'POST'])
def search():
    results = None
    query_used = None
    error = None

    if request.method == 'POST':
        term = request.form.get('term', '')

        #  VULNERÁVEL: concatenação direta
        query = f"SELECT id, username, email FROM users WHERE username LIKE '%{term}%'"
        query_used = query

        try:
            db = get_db()
            cursor = db.execute(query)
            results = cursor.fetchall()
        except Exception as e:
            error = f"Erro SQL: {str(e)}"

    return render_template(
        'search.html',
        results=results,
        query_used=query_used,
        error=error,
        app_type='vulnerable'
    )


if __name__ == '__main__':
    app.run(debug=True, port=5001)
