#!/usr/bin/env python3
"""
domain_checker.py — Verificador assíncrono de domínios, SSL e conectividade.
Parte do projeto Infra-Vision.

Funcionalidades:
  - Resolução DNS com retry e múltiplos servidores
  - Teste de conectividade TCP
  - Análise completa de certificados SSL/TLS
  - Envio de relatório para Telegram
  - Envio de resultados para o backend Infra-Vision

Uso:
  python3 domain_checker.py

Requer:
  pip install aiohttp aiofiles requests

Configuração:
  - Domínios em /opt/testeporta.txt (um por linha)
  - Variáveis de configuração no bloco CONFIGURAÇÕES abaixo
"""

import os
import socket
import ssl
import datetime
import json
import logging
import sys
import asyncio
import aiofiles
from typing import List, Dict, Any
import time
import aiohttp


# =============================================================================
# CONFIGURAÇÕES
# =============================================================================

# Paths
BASE_DIR = '/opt/'
DOMAINS_FILE = os.path.join(BASE_DIR, 'testeporta.txt')
JSON_OUTPUT = os.path.join(BASE_DIR, 'speed.json')

# Conexão
PORT = 8080
MAX_CONCURRENT_CONNECTIONS = 30
CONNECTION_TIMEOUT = 15
DNS_TIMEOUT = 20

# Alertas
ALERT_EXPIRY_DAYS = 30

# Telegram
SEND_TELEGRAM_ALERTS = True
TELEGRAM_DESTINATIONS = [
    {
        "chat_id": "-1002545279987",
        "thread_id": 2,
        "bot_token": "1943082730:AAH1yjt0xc9hdLs_DjIMx-7bg99tGmV5n3o",
    },
    {
        "chat_id": "-1002471996857",
        "thread_id": 220,
        "bot_token": "8180435774:AAGYxwOLTeQ0_8OjYc-OTwYYFkQqfH0g79Y",
    },
]

# Infra-Vision backend
SEND_TO_INFRAVISION = True
INFRAVISION_URL = os.environ.get("INFRAVISION_URL", "http://127.0.0.1:8000/api/v1/speedtest")
INFRAVISION_TOKEN = os.environ.get("INFRAVISION_TOKEN", "")
INFRAVISION_SOURCE = os.environ.get("INFRAVISION_SOURCE", socket.gethostname())


# =============================================================================
# LOGGING
# =============================================================================

def setup_logging() -> logging.Logger:
    """Configura logging com rotação de arquivos."""
    from logging.handlers import RotatingFileHandler

    formatter = logging.Formatter(
        '%(asctime)s | %(levelname)-8s | %(funcName)-20s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )

    log_file = os.path.join(BASE_DIR, 'domain_checker.log')
    file_handler = RotatingFileHandler(
        log_file, maxBytes=10 * 1024 * 1024, backupCount=5, encoding='utf-8',
    )
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.WARNING)
    console_handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))

    _logger = logging.getLogger('domain_checker')
    _logger.setLevel(logging.INFO)
    _logger.handlers.clear()
    _logger.addHandler(file_handler)
    _logger.addHandler(console_handler)

    return _logger


logger = setup_logging()


# =============================================================================
# DOMAIN ANALYZER
# =============================================================================

class DomainAnalyzer:
    """Análise assíncrona de domínios com controle de concorrência."""

    def __init__(self, max_workers: int = MAX_CONCURRENT_CONNECTIONS):
        self.max_workers = max_workers
        self.semaphore = asyncio.Semaphore(max_workers)
        self.session_stats = {
            'start_time': None,
            'end_time': None,
            'total_domains': 0,
            'processed_domains': 0,
            'errors': 0,
            'timeouts': 0,
        }

    async def check_domain_ssl(self, domain: str, port: int) -> Dict[str, Any]:
        async with self.semaphore:
            return await self._analyze_single_domain(domain, port)

    async def _analyze_single_domain(self, domain: str, port: int) -> Dict[str, Any]:
        start_time = time.time()

        result = {
            "domain": domain,
            "port": port,
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "reachable": False,
            "ssl_enabled": False,
            "certificate_valid": False,
            "certificate_expired": None,
            "days_until_expiry": None,
            "expiry_date": None,
            "issued_date": None,
            "issuer": None,
            "subject": None,
            "san_domains": [],
            "error_message": None,
            "response_time_ms": None,
            "tls_version": None,
            "cipher_suite": None,
        }

        logger.info(f"Analisando: {domain}:{port}")

        try:
            loop = asyncio.get_event_loop()

            # DNS
            try:
                ip_address = await self._resolve_dns_with_retry(domain, loop)
            except asyncio.TimeoutError:
                result["error_message"] = f"Timeout DNS (>{DNS_TIMEOUT}s)"
                self.session_stats['timeouts'] += 1
                return result
            except Exception as dns_error:
                result["error_message"] = f"Erro DNS: {str(dns_error)}"
                return result

            # Conectividade
            connectivity_result = await self._test_connectivity(domain, ip_address, port)
            result.update(connectivity_result)

            # SSL
            if result["reachable"]:
                ssl_result = await self._analyze_ssl_certificate(domain, ip_address, port)
                result.update(ssl_result)

            end_time = time.time()
            result["response_time_ms"] = round((end_time - start_time) * 1000, 2)

            logger.info(
                f"OK {domain}: reachable={result['reachable']} ssl={result['ssl_enabled']} "
                f"valid={result['certificate_valid']} ({result['response_time_ms']}ms)"
            )

        except Exception as e:
            result["error_message"] = f"Erro inesperado: {str(e)}"
            logger.error(f"Erro para {domain}: {e}", exc_info=True)
            self.session_stats['errors'] += 1
        finally:
            self.session_stats['processed_domains'] += 1

        return result

    async def _resolve_dns_with_retry(self, domain: str, loop, max_retries: int = 3) -> str:
        for attempt in range(max_retries):
            try:
                ip_address = await asyncio.wait_for(
                    loop.run_in_executor(None, socket.gethostbyname, domain),
                    timeout=DNS_TIMEOUT,
                )
                return ip_address
            except asyncio.TimeoutError:
                logger.debug(f"DNS timeout {domain} (tentativa {attempt + 1}/{max_retries})")
            except Exception as e:
                logger.debug(f"DNS erro {domain}: {e}")

            if attempt < max_retries - 1:
                await asyncio.sleep(0.5)

        raise asyncio.TimeoutError(f"DNS falhou após {max_retries} tentativas")

    async def _test_connectivity(self, domain: str, ip_address: str, port: int) -> Dict[str, Any]:
        loop = asyncio.get_event_loop()
        try:
            await asyncio.wait_for(
                loop.run_in_executor(None, self._sync_connectivity_test, ip_address, port),
                timeout=CONNECTION_TIMEOUT,
            )
            return {"reachable": True}
        except asyncio.TimeoutError:
            self.session_stats['timeouts'] += 1
            return {"reachable": False, "error_message": "Timeout de conexão"}
        except Exception as e:
            return {"reachable": False, "error_message": f"Erro conectividade: {str(e)}"}

    def _sync_connectivity_test(self, ip_address: str, port: int) -> bool:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(CONNECTION_TIMEOUT)
        try:
            sock.connect((ip_address, port))
            return True
        finally:
            sock.close()

    async def _analyze_ssl_certificate(self, domain: str, ip_address: str, port: int) -> Dict[str, Any]:
        loop = asyncio.get_event_loop()
        try:
            return await loop.run_in_executor(
                None, self._sync_ssl_analysis, domain, ip_address, port
            )
        except Exception as e:
            logger.warning(f"Erro SSL {domain}: {e}")
            return {"ssl_enabled": False, "error_message": f"Erro SSL: {str(e)}"}

    def _sync_ssl_analysis(self, domain: str, ip_address: str, port: int) -> Dict[str, Any]:
        result = {
            "ssl_enabled": False,
            "certificate_valid": False,
            "certificate_expired": None,
            "days_until_expiry": None,
            "expiry_date": None,
            "issued_date": None,
            "issuer": None,
            "subject": None,
            "san_domains": [],
            "tls_version": None,
            "cipher_suite": None,
        }

        try:
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(CONNECTION_TIMEOUT)
                with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                    secure_sock.connect((ip_address, port))

                    result["ssl_enabled"] = True
                    result["tls_version"] = secure_sock.version()
                    result["cipher_suite"] = secure_sock.cipher()[0] if secure_sock.cipher() else None

                    cert = secure_sock.getpeercert()
                    if cert:
                        if 'notAfter' in cert:
                            expiry_date = datetime.datetime.strptime(
                                cert['notAfter'], "%b %d %H:%M:%S %Y %Z"
                            )
                            result["expiry_date"] = expiry_date.isoformat() + "Z"
                            days_until = (expiry_date - datetime.datetime.utcnow()).days
                            result["days_until_expiry"] = days_until
                            result["certificate_expired"] = expiry_date <= datetime.datetime.utcnow()
                            result["certificate_valid"] = expiry_date > datetime.datetime.utcnow()

                        if 'notBefore' in cert:
                            issued_date = datetime.datetime.strptime(
                                cert['notBefore'], "%b %d %H:%M:%S %Y %Z"
                            )
                            result["issued_date"] = issued_date.isoformat() + "Z"

                        if 'issuer' in cert:
                            issuer_dict = dict(x[0] for x in cert['issuer'])
                            result["issuer"] = issuer_dict.get('organizationName', 'Unknown')

                        if 'subject' in cert:
                            subject_dict = dict(x[0] for x in cert['subject'])
                            result["subject"] = subject_dict.get('commonName', domain)

                        if 'subjectAltName' in cert:
                            result["san_domains"] = [
                                name[1] for name in cert['subjectAltName'] if name[0] == 'DNS'
                            ]

        except ssl.SSLError as e:
            result["error_message"] = f"Erro SSL: {str(e)}"
        except Exception as e:
            result["error_message"] = f"Erro análise SSL: {str(e)}"

        return result

    async def analyze_domains_batch(self, domains: List[str], port: int) -> List[Dict[str, Any]]:
        self.session_stats['start_time'] = datetime.datetime.utcnow()
        self.session_stats['total_domains'] = len(domains)

        logger.info(f"Iniciando análise de {len(domains)} domínios ({self.max_workers} workers)")

        tasks = [self.check_domain_ssl(d.strip(), port) for d in domains if d.strip()]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        processed = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Exceção {domains[i]}: {result}")
                processed.append({
                    "domain": domains[i],
                    "port": port,
                    "reachable": False,
                    "error_message": f"Exceção: {str(result)}",
                })
            else:
                processed.append(result)

        self.session_stats['end_time'] = datetime.datetime.utcnow()
        duration = (self.session_stats['end_time'] - self.session_stats['start_time']).total_seconds()
        logger.info(f"Concluído em {duration:.2f}s — {len(processed)} domínios, {self.session_stats['errors']} erros, {self.session_stats['timeouts']} timeouts")

        return processed


# =============================================================================
# OUTPUT — JSON
# =============================================================================

def _get_fastest_domain(results: List[Dict]) -> str | None:
    valid = [r for r in results if r.get("response_time_ms") and r["response_time_ms"] > 0]
    return min(valid, key=lambda x: x["response_time_ms"])["domain"] if valid else None


def _get_slowest_domain(results: List[Dict]) -> str | None:
    valid = [r for r in results if r.get("response_time_ms") and r["response_time_ms"] > 0]
    return max(valid, key=lambda x: x["response_time_ms"])["domain"] if valid else None


def build_grafana_data(results: List[Dict], session_stats: Dict) -> dict:
    """Constrói o JSON final compatível com Grafana e Infra-Vision."""
    total = len(results)
    reachable = sum(1 for r in results if r.get("reachable", False))
    ssl_enabled = sum(1 for r in results if r.get("ssl_enabled", False))
    valid_certs = sum(1 for r in results if r.get("certificate_valid", False))
    expired_certs = sum(1 for r in results if r.get("certificate_expired", False))
    expiring_soon = [r for r in results if r.get("days_until_expiry") is not None and 0 < r["days_until_expiry"] <= ALERT_EXPIRY_DAYS]

    duration = 0
    if session_stats.get('start_time') and session_stats.get('end_time'):
        duration = (session_stats['end_time'] - session_stats['start_time']).total_seconds()

    response_times = [r["response_time_ms"] for r in results if r.get("response_time_ms") and r["response_time_ms"] > 0]
    avg_response = round(sum(response_times) / len(response_times), 2) if response_times else 0

    # TLS versions
    tls_versions = {}
    certificate_authorities = {}
    common_errors = {}
    for r in results:
        if r.get("tls_version"):
            tls_versions[r["tls_version"]] = tls_versions.get(r["tls_version"], 0) + 1
        if r.get("issuer"):
            certificate_authorities[r["issuer"]] = certificate_authorities.get(r["issuer"], 0) + 1
        if r.get("error_message") and not r.get("reachable"):
            etype = r["error_message"].split(":")[0]
            common_errors[etype] = common_errors.get(etype, 0) + 1

    return {
        "metadata": {
            "scan_timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "scan_duration_seconds": round(duration, 2),
            "total_domains": total,
            "processed_domains": session_stats.get('processed_domains', 0),
            "reachable_domains": reachable,
            "ssl_enabled_domains": ssl_enabled,
            "valid_certificates": valid_certs,
            "expired_certificates": expired_certs,
            "expiring_soon_count": len(expiring_soon),
            "errors_count": session_stats.get('errors', 0),
            "timeouts_count": session_stats.get('timeouts', 0),
            "script_version": "4.0-infravision",
            "max_concurrent_connections": MAX_CONCURRENT_CONNECTIONS,
            "source": INFRAVISION_SOURCE,
        },
        "domains": results,
        "summary": {
            "performance_metrics": {
                "avg_response_time_ms": avg_response,
                "fastest_domain": _get_fastest_domain(results),
                "slowest_domain": _get_slowest_domain(results),
            },
            "domains_by_status": {
                "reachable": [r["domain"] for r in results if r.get("reachable")],
                "unreachable": [r["domain"] for r in results if not r.get("reachable")],
                "ssl_enabled": [r["domain"] for r in results if r.get("ssl_enabled")],
                "valid_certs": [r["domain"] for r in results if r.get("certificate_valid")],
                "expired_certs": [r["domain"] for r in results if r.get("certificate_expired")],
                "expiring_soon": [r["domain"] for r in expiring_soon],
                "certificate_warnings": [
                    {"domain": r["domain"], "days_left": r["days_until_expiry"], "expiry_date": r["expiry_date"]}
                    for r in expiring_soon
                ],
            },
            "ssl_analysis": {
                "tls_versions": tls_versions,
                "certificate_authorities": certificate_authorities,
                "common_errors": common_errors,
            },
        },
    }


async def save_json(grafana_data: dict, filename: str) -> bool:
    """Salva JSON no disco."""
    try:
        async with aiofiles.open(filename, 'w', encoding='utf-8') as f:
            await f.write(json.dumps(grafana_data, indent=2, ensure_ascii=False))
        logger.info(f"JSON salvo: {filename}")
        return True
    except Exception as e:
        logger.error(f"Erro ao salvar JSON: {e}")
        return False


# =============================================================================
# INFRA-VISION — Envio para o backend
# =============================================================================

async def send_to_infravision(grafana_data: dict) -> None:
    """Envia resultados para o backend Infra-Vision via POST."""
    if not SEND_TO_INFRAVISION or not INFRAVISION_TOKEN:
        if not INFRAVISION_TOKEN:
            logger.warning("Infra-Vision: INFRAVISION_TOKEN não configurado — envio desabilitado")
        return

    headers = {
        "Authorization": f"Bearer {INFRAVISION_TOKEN}",
        "Content-Type": "application/json",
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(INFRAVISION_URL, json=grafana_data, headers=headers, timeout=30) as resp:
                if resp.status == 201:
                    data = await resp.json()
                    logger.info(
                        f"Infra-Vision: scan enviado com sucesso "
                        f"(scan_id={data.get('scan_id')}, {data.get('domains')} domínios)"
                    )
                else:
                    body = await resp.text()
                    logger.error(f"Infra-Vision: HTTP {resp.status} — {body[:200]}")
    except asyncio.TimeoutError:
        logger.error("Infra-Vision: timeout ao enviar (30s)")
    except Exception as e:
        logger.error(f"Infra-Vision: falha ao enviar — {e}")


# =============================================================================
# TELEGRAM
# =============================================================================

def format_telegram_message(results: List[Dict], session_stats: Dict) -> str:
    """Formata relatório para Telegram."""
    total = len(results)
    reachable = sum(1 for r in results if r.get("reachable", False))
    ssl_enabled = sum(1 for r in results if r.get("ssl_enabled", False))
    valid_certs = sum(1 for r in results if r.get("certificate_valid", False))
    expired_certs = sum(1 for r in results if r.get("certificate_expired", False))

    duration = 0
    if session_stats.get('start_time') and session_stats.get('end_time'):
        duration = (session_stats['end_time'] - session_stats['start_time']).total_seconds()

    success_domains = [r for r in results if r.get("reachable") and r.get("certificate_valid")]
    warning_domains = [r for r in results if r.get("reachable") and not r.get("certificate_valid")]
    error_domains = [r for r in results if not r.get("reachable")]
    expiring_soon = [r for r in results if r.get("days_until_expiry") is not None and 0 < r["days_until_expiry"] <= ALERT_EXPIRY_DAYS]

    response_times = [r["response_time_ms"] for r in results if r.get("response_time_ms") and r["response_time_ms"] > 0]
    avg_time = sum(response_times) / len(response_times) if response_times else 0

    message = f"""
🔍 *RELATÓRIO — VERIFICAÇÃO DE DOMÍNIOS*
════════════════════════════════
⏱ *Execução:* {duration:.2f}s | *Domínios:* {total}

📊 *ESTATÍSTICAS:*
✅ SSL válido: {len(success_domains)} ({len(success_domains)/max(total,1)*100:.1f}%)
⚠️ Com problemas: {len(warning_domains)} ({len(warning_domains)/max(total,1)*100:.1f}%)
❌ Inacessíveis: {len(error_domains)} ({len(error_domains)/max(total,1)*100:.1f}%)

🔒 *SSL:* {ssl_enabled} habilitados | {valid_certs} válidos | {expired_certs} expirados | {len(expiring_soon)} expirando ≤{ALERT_EXPIRY_DAYS}d

⏳ *Performance:* média {avg_time:.0f}ms | erros {session_stats.get('errors', 0)} | timeouts {session_stats.get('timeouts', 0)}
════════════════════════════════"""

    if expiring_soon:
        message += "\n\n*🚨 EXPIRANDO EM BREVE:*\n"
        for d in sorted(expiring_soon, key=lambda x: x['days_until_expiry'])[:5]:
            dn = d['domain'].replace('_', '\\_').replace('*', '\\*')
            message += f"• `{dn}`: {d['days_until_expiry']}d\n"
        if len(expiring_soon) > 5:
            message += f"*... +{len(expiring_soon) - 5} outros*\n"

    if error_domains:
        message += "\n*❌ INACESSÍVEIS:*\n"
        for d in error_domains[:5]:
            dn = d['domain'].replace('_', '\\_').replace('*', '\\*')
            err = (d.get('error_message') or 'Desconhecido').split(':')[0]
            message += f"• `{dn}`: {err}\n"
        if len(error_domains) > 5:
            message += f"*... +{len(error_domains) - 5} outros*\n"

    message += f"\n════════════════════════════════\nℹ️ *{INFRAVISION_SOURCE}* — {datetime.datetime.now().strftime('%d/%m/%Y %H:%M')}"

    return message


async def send_telegram_message_async(chat_id: str, thread_id: int, bot_token: str, message: str) -> bool:
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "message_thread_id": thread_id,
        "text": message,
        "parse_mode": "Markdown",
        "disable_web_page_preview": True,
    }
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, timeout=10) as resp:
                if resp.status == 200:
                    logger.info(f"Telegram: enviado para {chat_id}")
                    return True
                error_text = await resp.text()
                logger.error(f"Telegram HTTP {resp.status}: {error_text[:200]}")
                return False
    except Exception as e:
        logger.error(f"Telegram erro: {e}")
        return False


async def send_telegram_alerts(results: List[Dict], session_stats: Dict) -> None:
    if not SEND_TELEGRAM_ALERTS:
        return

    message = format_telegram_message(results, session_stats)

    enviados = set()
    tasks = []
    for dest in TELEGRAM_DESTINATIONS:
        cid = dest["chat_id"]
        if cid in enviados:
            continue
        enviados.add(cid)
        tasks.append(send_telegram_message_async(cid, dest["thread_id"], dest["bot_token"], message))

    results_send = await asyncio.gather(*tasks, return_exceptions=True)
    ok = sum(1 for r in results_send if r is True)
    logger.info(f"Telegram: {ok}/{len(enviados)} enviados")


# =============================================================================
# RESUMO CONSOLE
# =============================================================================

def print_summary(results: List[Dict], session_stats: Dict):
    total = len(results)
    if total == 0:
        print("Nenhum resultado.")
        return

    reachable = sum(1 for r in results if r.get("reachable", False))
    ssl_enabled = sum(1 for r in results if r.get("ssl_enabled", False))
    valid_certs = sum(1 for r in results if r.get("certificate_valid", False))
    expired_certs = sum(1 for r in results if r.get("certificate_expired", False))

    duration = 0
    if session_stats.get('start_time') and session_stats.get('end_time'):
        duration = (session_stats['end_time'] - session_stats['start_time']).total_seconds()

    print(f"\n{'='*70}")
    print(f"  INFRA-VISION — Domain Checker v4.0")
    print(f"{'='*70}")
    print(f"  Tempo: {duration:.2f}s | Workers: {MAX_CONCURRENT_CONNECTIONS}")
    print(f"  Domínios: {total} | Acessíveis: {reachable} | SSL: {ssl_enabled} | Válidos: {valid_certs} | Expirados: {expired_certs}")
    print(f"  Erros: {session_stats.get('errors', 0)} | Timeouts: {session_stats.get('timeouts', 0)}")

    response_times = [r["response_time_ms"] for r in results if r.get("response_time_ms") and r["response_time_ms"] > 0]
    if response_times:
        print(f"  Response: avg={sum(response_times)/len(response_times):.0f}ms min={min(response_times):.0f}ms max={max(response_times):.0f}ms")

    expiring = [r for r in results if r.get("days_until_expiry") is not None and 0 < r["days_until_expiry"] <= ALERT_EXPIRY_DAYS]
    if expiring:
        print(f"\n  ⚠️  Certificados expirando em {ALERT_EXPIRY_DAYS}d: {len(expiring)}")
        for d in sorted(expiring, key=lambda x: x["days_until_expiry"])[:5]:
            print(f"     • {d['domain']}: {d['days_until_expiry']}d")

    errors = [r for r in results if r.get("error_message") and not r.get("reachable")]
    if errors:
        print(f"\n  ❌ Inacessíveis: {len(errors)}")
        for d in errors[:5]:
            print(f"     • {d['domain']}: {d['error_message'][:60]}")
        if len(errors) > 5:
            print(f"     ... +{len(errors) - 5} outros")

    print(f"{'='*70}\n")


# =============================================================================
# MAIN
# =============================================================================

async def main():
    logger.info("=" * 50)
    logger.info(f"Infra-Vision Domain Checker v4.0 — source={INFRAVISION_SOURCE}")
    logger.info("=" * 50)

    # Carrega domínios
    try:
        async with aiofiles.open(DOMAINS_FILE, mode='r', encoding='utf-8') as f:
            content = await f.read()
            domains = [line.strip() for line in content.splitlines() if line.strip()]
    except FileNotFoundError:
        logger.error(f"Arquivo não encontrado: {DOMAINS_FILE}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Erro ao ler {DOMAINS_FILE}: {e}")
        sys.exit(1)

    if not domains:
        logger.error("Nenhum domínio encontrado. Saindo.")
        sys.exit(1)

    logger.info(f"Carregados {len(domains)} domínios de {DOMAINS_FILE}")

    # Análise
    analyzer = DomainAnalyzer(max_workers=MAX_CONCURRENT_CONNECTIONS)

    try:
        results = await analyzer.analyze_domains_batch(domains, PORT)

        # Monta JSON
        grafana_data = build_grafana_data(results, analyzer.session_stats)

        # Salva no disco
        await save_json(grafana_data, JSON_OUTPUT)

        # Console
        print_summary(results, analyzer.session_stats)

        # Telegram
        await send_telegram_alerts(results, analyzer.session_stats)

        # Infra-Vision backend
        await send_to_infravision(grafana_data)

    except KeyboardInterrupt:
        logger.warning("Interrompido pelo usuário")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Erro crítico: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n⚠️  Interrompido")
        sys.exit(1)
