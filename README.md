# SQL Injection — Demonstração de Ataque e Defesa

Projeto prático da disciplina de **Segurança Informática** (2025/2026).

O objetivo é mostrar, de forma concreta e reproduzível, o que é SQL Injection, como funciona na prática e o que muda no código para o prevenir. Para isso foram construídas duas versões da mesma aplicação web — uma propositadamente vulnerável e uma corrigida — mais uma ferramenta que as testa automaticamente.

> Todo o código foi escrito para fins educativos. Os ataques demonstrados só funcionam neste ambiente local e isolado.

---

## O que está incluído

```
projeto-sqli/
├── app_vulneravel/       → App Flask com SQL Injection intencional (porta 5001)
├── app_segura/           → Mesma app, corrigida com prepared statements (porta 5002)
├── scanner/              → Script Python que testa automaticamente os dois endpoints
├── database/             → Base de dados SQLite com utilizadores e dados "secretos"
├── requirements.txt
└── start.sh              → Arranca as duas apps de uma vez
```

As duas apps partilham a mesma base de dados e têm as mesmas páginas (`/`, `/login`, `/search`). A diferença está inteiramente em como cada uma constrói as queries SQL.

---

## Como instalar e correr

**Pré-requisitos:** Python 3.8+ e pip.

```bash
# 1. Entrar na pasta do projeto
cd projeto-sqli

# 2. Instalar as dependências (Flask + requests)
pip install -r requirements.txt

# 3. Criar a base de dados
python3 database/init_db.py

# 4. Arrancar as duas apps
bash start.sh
```

Depois de `bash start.sh`, abrir no browser:

| App | URL |
|---|---|
| ⚠️ Vulnerável | http://localhost:5001 |
| ✅ Segura | http://localhost:5002 |

Se preferir arrancar manualmente (dois terminais separados):

```bash
# Terminal 1
python3 app_vulneravel/app.py

# Terminal 2
python3 app_segura/app.py
```

---

## O que testar

### 1. Login bypass — `http://localhost:5001/login`

A página de login constrói a query assim:

```sql
SELECT * FROM users WHERE username = '{input}' AND password = '{input}'
```

O input do utilizador é colado diretamente na query sem nenhuma sanitização. Isso permite contornar completamente a autenticação.

**Payloads a experimentar no campo username** (password pode ser qualquer coisa):

| Username | O que faz |
|---|---|
| `' OR '1'='1' --` | O `--` comenta o resto da query; `'1'='1'` é sempre verdadeiro → login sem credenciais |
| `admin' --` | Faz login directamente como admin, ignorando a verificação de password |
| `' OR 1=1 --` | Variante com inteiros em vez de strings |

O que aparece no ecrã quando o ataque funciona: a app mostra a query SQL que foi realmente executada e confirma o login com sucesso. Isso não devia ser possível — nenhuma das passwords está correcta.

**Agora abrir `http://localhost:5002/login` e tentar os mesmos payloads.** A app segura trata o input como texto literal, não como SQL. A query executada continua a ser `WHERE username = ? AND password = ?`, os parâmetros são passados separadamente ao driver, e nenhum payload consegue alterar a lógica da query.

---

### 2. Extracção de dados — `http://localhost:5001/search`

A pesquisa de utilizadores constrói:

```sql
SELECT id, username, email FROM users WHERE username LIKE '%{input}%'
```

Com `UNION SELECT`, é possível acrescentar uma segunda query à original e obter dados de qualquer outra tabela — incluindo uma tabela `secrets` que existe na base de dados com passwords e API keys.

**Payloads a experimentar no campo de pesquisa:**

| Payload | O que extrai |
|---|---|
| `' UNION SELECT id,name,value FROM secrets --` | Conteúdo da tabela `secrets` (passwords, API keys, notas internas) |
| `' UNION SELECT 1,name,sql FROM sqlite_master --` | Estrutura completa da base de dados (nomes de tabelas e colunas) |
| `' UNION SELECT 1,username,password FROM users --` | Todos os utilizadores e os seus hashes de password |
| `'` | Provoca um erro SQL que aparece no ecrã, revelando que a BD é SQLite |

O último caso (só uma `'`) é chamado *error-based information disclosure* — mesmo sem extrair dados, saber o tipo e versão da base de dados já ajuda um atacante a planear os passos seguintes.

**Testar os mesmos payloads em `http://localhost:5002/search`.** Os resultados serão sempre zero ou apenas os utilizadores reais — nenhum dado da tabela `secrets` é acessível.

---

### 3. Scanner automático

O `sqli_scanner.py` automatiza os testes acima, enviando dezenas de payloads e analisando as respostas.

```bash
# Testar a app vulnerável
python3 scanner/sqli_scanner.py --url http://localhost:5001

# Testar a app segura
python3 scanner/sqli_scanner.py --url http://localhost:5002

# Comparar as duas de uma vez (ambas as apps têm de estar a correr)
python3 scanner/sqli_scanner.py --compare

# Guardar o relatório num ficheiro
python3 scanner/sqli_scanner.py --url http://localhost:5001 --output relatorio.txt
```

O scanner deteta três tipos de vulnerabilidades: *error-based* (erros SQL na resposta), *boolean-based* (indicadores de login bem-sucedido com payload injectado) e *UNION-based* (respostas com tamanho anómalo). Na app vulnerável encontra ~38 ocorrências; na app segura encontra zero.

---

## Por que o ataque funciona (e como a correção o impede)

O problema não é o SQL em si — é concatenar dados do utilizador diretamente no código SQL.

```python
# ❌ Vulnerável: o input torna-se parte da query
query = f"SELECT * FROM users WHERE username = '{username}'"

# ✅ Seguro: a query e os dados são enviados separadamente ao driver
query = "SELECT * FROM users WHERE username = ?"
cursor.execute(query, (username,))
```

Com *prepared statements*, o driver de base de dados recebe a estrutura da query numa fase e os valores noutra. Mesmo que o utilizador escreva `' OR '1'='1' --`, esse texto é comparado literalmente contra a coluna `username` — não é interpretado como SQL. Não existe nenhum utilizador com esse nome, logo o resultado é vazio.

As outras duas correções na app segura seguem o mesmo princípio:

- **Erros não são expostos** — um `try/except` genérico devolve sempre a mesma mensagem, sem revelar detalhes internos da base de dados.
- **Validação de input** — comprimento máximo e campos obrigatórios, para reduzir a superfície de ataque antes de chegar à query.

---

## Base de dados

A BD SQLite tem duas tabelas criadas pelo `database/init_db.py`:

**`users`** — os utilizadores da aplicação:

| username | password (texto) | role |
|---|---|---|
| admin | admin123 | admin |
| alice | alice456 | user |
| bob | bob789 | user |
| charlie | charlie000 | manager |

As passwords são guardadas como hash SHA-256 — as versões em texto claro acima servem apenas para testar o login legítimo.

**`secrets`** — existe para demonstrar o UNION attack. Contém entradas como `db_password`, `api_key` e `internal_notes` com valores fictícios que simulam dados que nunca deviam ser acessíveis via uma pesquisa de utilizadores.

---

## Referências

- OWASP — SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection
- OWASP Top 10 (A03:2021 — Injection): https://owasp.org/Top10/A03_2021-Injection/
- PortSwigger Web Security Academy — SQL injection: https://portswigger.net/web-security/sql-injection
- Python sqlite3 — Parameterized queries: https://docs.python.org/3/library/sqlite3.html
