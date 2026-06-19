"""
Script de inicialização da base de dados SQLite
================================================
Cria as tabelas e insere dados de teste para ambas as aplicações.
"""

import sqlite3
import hashlib
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'app.db')


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
        print("  Base de dados antiga removida.")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Tabela de utilizadores
    cursor.execute('''
        CREATE TABLE users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT    NOT NULL UNIQUE,
            password TEXT    NOT NULL,
            email    TEXT    NOT NULL,
            role     TEXT    NOT NULL DEFAULT 'user'
        )
    ''')

    # Tabela de segredos (para demonstrar extração via UNION)
    cursor.execute('''
        CREATE TABLE secrets (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            name    TEXT NOT NULL,
            value   TEXT NOT NULL
        )
    ''')

    # Dados de utilizadores (password em hash sha256)
    users = [
        ('admin',   hash_password('admin123'),    'admin@empresa.com',   'admin'),
        ('alice',   hash_password('alice456'),    'alice@empresa.com',   'user'),
        ('bob',     hash_password('bob789'),      'bob@empresa.com',     'user'),
        ('charlie', hash_password('charlie000'),  'charlie@empresa.com', 'manager'),
    ]
    cursor.executemany(
        "INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
        users
    )

    # Dados "secretos" para demonstrar extração via UNION SELECT
    secrets = [
        ('db_password',    'S3cr3tDB!2025'),
        ('api_key',        'sk-prod-xK9mN2pL8qR5vT3w'),
        ('internal_notes', 'Servidor de backup: 192.168.1.50'),
    ]
    cursor.executemany(
        "INSERT INTO secrets (name, value) VALUES (?, ?)",
        secrets
    )

    conn.commit()
    conn.close()

    print(" Base de dados inicializada com sucesso!")
    print(f"   Localização: {DB_PATH}")
    print("\n Utilizadores criados:")
    print("   username  | password    | role")
    print("   ----------|-------------|--------")
    for u in users:
        print(f"   {u[0]:<10}| {u[2].split('@')[0]+'...':12}| {u[3]}")

    print("\n Credenciais para teste:")
    print("   admin / admin123")
    print("   alice / alice456")


if __name__ == '__main__':
    init_db()
