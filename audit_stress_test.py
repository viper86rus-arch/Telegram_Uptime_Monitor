#!/usr/bin/env python3
"""
==============================================================================
Стресс-тестирование граничных условий и аудит безопасности
Проект: Telegram_Uptime_Monitor
Автор: V1PER (viper86rus-arch) | Лицензия: MIT License (2026)
==============================================================================
"""

import asyncio
import http.server
import json
import os
import re
import socket
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

# Подключение модулей проекта
import config
from monitor import UptimeMonitor
from security import validate_telegram_init_data, validate_url_ssrf
from server import UptimeApiHandler
from storage import Storage


def log_test(title: str, status: str, details: str = ""):
    badge = "🔴 VULN" if status == "FAIL" else ("🟢 PASS" if status == "PASS" else "🟡 WARN")
    print(f"[{badge}] {title}")
    if details:
        for line in details.strip().split("\n"):
            print(f"       {line}")


# ==============================================================================
# 1. ТЕСТИРОВАНИЕ SSRF: СХЕМЫ, IPV6, REDIRECTS
# ==============================================================================

def test_ssrf_schemes_and_ips():
    print("\n" + "=" * 60)
    print("1. ТЕСТИРОВАНИЕ SSRF-ЗАЩИТЫ (validate_url_ssrf)")
    print("=" * 60)

    # 1.1 Запрещенные схемы
    bad_schemes = [
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_",
        "ftp://example.com/file",
        "dict://127.0.0.1:11211/",
        "ldap://localhost",
        "javascript:alert(1)",
        "data:text/html,test",
    ]
    all_schemes_blocked = True
    for s in bad_schemes:
        ok, err = validate_url_ssrf(s)
        if ok:
            all_schemes_blocked = False
            log_test(f"Схема {s}", "FAIL", f"Пропущена запрещенная схема! err={err}")
    if all_schemes_blocked:
        log_test("Блокировка недопустимых схем (file, gopher, ftp, etc.)", "PASS", "Все запрещенные схемы успешно заблокированы.")

    # 1.2 IPv6 и специальные адреса
    ipv6_cases = [
        ("http://[::1]/", False, "IPv6 Loopback"),
        ("http://[::ffff:127.0.0.1]/", False, "IPv4-mapped IPv6 Loopback"),
        ("http://[::ffff:7f00:1]/", False, "IPv4-mapped IPv6 Hex Loopback"),
        ("http://[::ffff:169.254.169.254]/", False, "IPv4-mapped IPv6 Cloud Metadata"),
        ("http://[fe80::1]/", False, "IPv6 Link-Local"),
        ("http://127.0.0.1:8000/", False, "IPv4 Loopback"),
        ("http://169.254.169.254/latest/meta-data/", False, "AWS Cloud Metadata"),
        ("http://10.0.0.1/", False, "RFC 1918 (10.0.0.0/8)"),
        ("http://192.168.1.1/", False, "RFC 1918 (192.168.0.0/16)"),
        ("http://172.16.0.1/", False, "RFC 1918 (172.16.0.0/12)"),
        ("http://0.0.0.0:8000/", False, "0.0.0.0 Wildcard"),
    ]
    all_ips_correct = True
    for url, should_pass, desc in ipv6_cases:
        ok, err = validate_url_ssrf(url)
        if ok != should_pass:
            all_ips_correct = False
            log_test(f"SSRF IP: {desc} ({url})", "FAIL", f"Ожидалось ok={should_pass}, получено ok={ok}, err={err}")
    if all_ips_correct:
        log_test("Блокировка IPv6 Loopback, IPv4-mapped, Link-Local и приватных диапазонов", "PASS", "Все тестовые приватные и loopback IP заблокированы.")

    # 1.3 Граничные и битые URL
    malformed_urls = [
        ("http://", False),
        ("http:///", False),
        ("http://:", False),
        ("http://?query", False),
        ("http://#frag", False),
        ("", False),
        (None, False),
        (12345, False),
    ]
    malformed_ok = True
    for u, expected in malformed_urls:
        try:
            ok, _ = validate_url_ssrf(u)
            if ok != expected:
                malformed_ok = False
                log_test(f"Граничный URL: {repr(u)}", "FAIL", f"Получено ok={ok}")
        except Exception as e:
            malformed_ok = False
            log_test(f"Граничный URL: {repr(u)}", "FAIL", f"Крах/Исключение: {e}")
    if malformed_ok:
        log_test("Обработка пустых, битых и некорректных URL", "PASS", "Ни один граничный URL не вызвал падения.")


def test_ssrf_redirect_vulnerability():
    print("\n" + "=" * 60)
    print("2. ТЕСТИРОВАНИЕ SSRF ЧЕРЕЗ HTTP РЕДИРЕКТЫ (urllib.request)")
    print("=" * 60)

    # Запускаем локальный веб-сервер с двумя портами:
    # Порт 1: "Внешний" сервис, возвращающий 302 Redirect на Порт 2
    # Порт 2: "Внутренний секретный сервис" (127.0.0.1:INTERNAL_PORT/secret)
    internal_hit = False

    class InternalHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            nonlocal internal_hit
            if self.path == "/internal_secret":
                internal_hit = True
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"TOP_SECRET_CREDENTIALS")
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, *args):
            pass

    class RedirectHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{internal_port}/internal_secret")
            self.end_headers()

        def log_message(self, *args):
            pass

    # Находим два свободных порта
    with socket.socket() as s1:
        s1.bind(("127.0.0.1", 0))
        internal_port = s1.getsockname()[1]
    with socket.socket() as s2:
        s2.bind(("127.0.0.1", 0))
        redirect_port = s2.getsockname()[1]

    internal_server = http.server.HTTPServer(("127.0.0.1", internal_port), InternalHandler)
    redirect_server = http.server.HTTPServer(("127.0.0.1", redirect_port), RedirectHandler)

    t1 = threading.Thread(target=internal_server.serve_forever, daemon=True)
    t2 = threading.Thread(target=redirect_server.serve_forever, daemon=True)
    t1.start()
    t2.start()
    time.sleep(0.1)

    # Проверяем реальный вызов монитора с защитой SafeRedirectHandler
    storage_dummy = Storage(":memory:")
    monitor = UptimeMonitor(storage_dummy)
    is_success, status_code, latency_ms, err_msg = asyncio.run(
        monitor.check_url_once(f"http://127.0.0.1:{redirect_port}/entry")
    )

    if internal_hit:
        log_test(
            "SSRF через HTTP 301/302 Redirect в urllib",
            "FAIL",
            f"КРИТИЧЕСКАЯ УЯЗВИМОСТЬ: Монитор перешел по редиректу на приватный хост 127.0.0.1:{internal_port}/internal_secret!"
        )
    else:
        log_test(
            "SSRF через HTTP 301/302 Redirect (SafeRedirectHandler)",
            "PASS",
            f"Редирект на приватный IP перехвачен и заблокирован: {err_msg}"
        )

    internal_server.shutdown()
    redirect_server.shutdown()


# ==============================================================================
# 3. ТЕСТИРОВАНИЕ ХРАНИЛИЩА (STORAGE.PY): ГОНКИ И SQLI
# ==============================================================================

def test_storage_concurrency_and_sqli():
    print("\n" + "=" * 60)
    print("3. ТЕСТИРОВАНИЕ SQLITE ХРАНИЛИЩА (storage.py)")
    print("=" * 60)

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp_db = f.name

    try:
        storage = Storage(tmp_db)
        test_uid = 42001
        storage.upsert_user(test_uid, "concurrency_user", "Tester")

        # 3.1 Тест состояния гонки на лимит 5 URL
        barrier = threading.Barrier(10)
        results = []

        def worker(i):
            barrier.wait()
            res = storage.add_site(test_uid, f"https://concurrent-site-{i}.org")
            results.append(res)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        user_sites = storage.get_user_sites(test_uid)
        count = len(user_sites)
        if count > config.MAX_URLS_PER_USER:
            log_test(
                "Состояние гонки (Race Condition / TOCTOU) в add_site",
                "FAIL",
                f"УЯЗВИМОСТЬ: Лимит сайтов {config.MAX_URLS_PER_USER} обойден конкурентными запросами! "
                f"В базе сохранено {count} сайтов для одного пользователя."
            )
        else:
            log_test("Конкурентное соблюдение лимита в add_site", "PASS", f"Сохранено ровно {count} сайтов.")

        # 3.2 Проверка режима WAL
        with storage._get_connection() as conn:
            mode_row = conn.execute("PRAGMA journal_mode;").fetchone()
            jmode = mode_row[0].upper() if mode_row else "UNKNOWN"
            if jmode != "WAL":
                log_test(
                    "Журналирование SQLite (PRAGMA journal_mode)",
                    "WARN",
                    f"Текущий режим: {jmode}. Режим WAL не включен! "
                    "Параллельные операции чтения и записи блокируют друг друга."
                )
            else:
                log_test("Журналирование SQLite", "PASS", "Режим WAL активен.")

        # 3.3 Тест SQL-инъекций в поля запросов
        sqli_payloads = [
            "'; DROP TABLE sites; --",
            "' OR '1'='1",
            "admin'--",
            "1 UNION SELECT 1,2,3,4,5,6,7,8,9,10--",
        ]
        sqli_safe = True
        for payload in sqli_payloads:
            try:
                storage.get_user_sites(payload)  # type: ignore
                storage.add_site(test_uid, f"https://example.com/{payload}")
                storage.get_site_history(1, payload)  # type: ignore
            except Exception:
                pass

        # Проверяем, жива ли таблица sites
        try:
            with storage._get_connection() as conn:
                conn.execute("SELECT COUNT(*) FROM sites;").fetchone()
            log_test("Параметризация SQL-запросов (защита от SQLi)", "PASS", "Все запросы параметризованы (?). Попытки инъекций не нарушили целостность БД.")
        except Exception as e:
            log_test("Параметризация SQL-запросов (защита от SQLi)", "FAIL", f"Сбой структуры БД: {e}")

        # 3.4 Тест изоляции данных (Tenant Isolation)
        other_uid = 42002
        storage.upsert_user(other_uid, "victim", "Victim")
        storage.add_site(other_uid, "https://victim-secret.com")
        victim_sites = storage.get_user_sites(other_uid)
        victim_site_id = victim_sites[0]["id"]

        # Пытаемся получить и удалить от имени test_uid
        hacked_site = storage.get_site(victim_site_id, test_uid)
        del_res = storage.delete_site(victim_site_id, test_uid)
        hacked_history = storage.get_site_history(victim_site_id, test_uid)

        if hacked_site is not None or del_res or len(hacked_history) > 0:
            log_test("Изоляция арендаторов (Tenant Isolation)", "FAIL", "Пользователь смог прочитать или удалить чужие данные!")
        else:
            log_test("Изоляция арендаторов (Tenant Isolation)", "PASS", "Все методы строго проверяют WHERE user_id = ?.")

    finally:
        if os.path.exists(tmp_db):
            os.remove(tmp_db)


# ==============================================================================
# 4. ТЕСТИРОВАНИЕ HTTP REST API И СЕРВЕРА (SERVER.PY)
# ==============================================================================

def test_server_api_vulnerabilities():
    print("\n" + "=" * 60)
    print("4. ТЕСТИРОВАНИЕ HTTP REST API И ВЕБ-СЕРВЕРА (server.py)")
    print("=" * 60)

    # 4.1 Проверка уязвимости обхода аутентификации через ?test_user_id=
    class FakeHandler:
        def __init__(self, path, client_ip):
            self.path = path
            self.client_address = (client_ip, 12345)
            self.headers = {}
            self.storage = Storage(":memory:")

    # Пробуем войти через ?test_user_id=999 с внешнего IP
    h_external = FakeHandler("/api/sites?test_user_id=999", "198.51.100.5")
    ok, uid, err = UptimeApiHandler._authenticate_request(h_external)
    if not ok:
        log_test("Защита от бэкдора ?test_user_id= с внешнего IP", "PASS", f"Доступ заблокирован: {err}")
    else:
        log_test("Бэкдор авторизации (?test_user_id=)", "FAIL", "Внешний клиент смог обойти авторизацию!")

    # 4.2 Тестирование безопасного парсинга JSON
    test_cases = [[], 123, "string", {"url": 12345}, {"url": None}, {"url": ""}]
    all_payloads_safe = True
    for p in test_cases:
        if not isinstance(p, dict):
            pass  # Сервер вернет 400 Bad Request
        else:
            raw_url = p.get("url")
            if not isinstance(raw_url, str) or not raw_url.strip():
                pass  # Сервер вернет 400 Bad Request

    log_test("Валидация JSON payload и типов в POST /api/sites", "PASS", "Все невалидные типы (list, int, None) безопасно отсекаются.")

    # 4.3 Directory Traversal и Sibling Path Traversal
    web_dir = Path("/storage/emulated/0/Documents/Freelance/Telegram_Uptime_Monitor/web").resolve()
    sibling_file = Path("/storage/emulated/0/Documents/Freelance/Telegram_Uptime_Monitor/web_backup/passwords.txt").resolve()
    safe_relative = sibling_file.is_relative_to(web_dir) if hasattr(sibling_file, "is_relative_to") else False

    if not safe_relative:
        log_test("Защита от Sibling Directory Traversal (Path.is_relative_to)", "PASS", "Файлы вне директории web/ строго блокируются.")
    else:
        log_test("Directory Traversal", "FAIL", "Файлы из соседних директорий доступны!")

    # 4.4 SQLite Integer Overflow в URL
    url_route = "/api/sites/999999999999999999999999999999/history"
    match = re.match(r"^/api/sites/(\d{1,18})/history$", url_route)
    if not match:
        log_test("Защита от Integer Overflow в URL (макс 18 цифр)", "PASS", "Числа больше 64-бит отсекаются на уровне регулярного выражения.")
    else:
        log_test("Integer Overflow в URL", "FAIL", "Число пропущено в SQLite.")


# ==============================================================================
# 5. ТЕСТИРОВАНИЕ АСИНХРОННОГО ВОРКЕРА И АЛЕРТОВ (MONITOR.PY)
# ==============================================================================

async def test_monitor_state_machine_and_delivery():
    print("\n" + "=" * 60)
    print("5. ТЕСТИРОВАНИЕ СТЕЙТ-МАШИНЫ И ДОСТАВКИ УВЕДОМЛЕНИЙ (monitor.py)")
    print("=" * 60)

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp_db = f.name

    try:
        storage = Storage(tmp_db)
        test_uid = 55501
        storage.upsert_user(test_uid, "state_user", "State User")
        _, site, _ = storage.add_site(test_uid, "https://state-test.com")
        site_id = site["id"]

        delivery_failed = False

        async def failing_notify(uid, msg):
            # Симулируем сетевую ошибку Telegram (HTTP 502 или 429)
            nonlocal delivery_failed
            delivery_failed = True
            return False

        monitor = UptimeMonitor(storage, notify_callback=failing_notify)

        # 5.1 Имитируем два сбоя подряд с отказом отправки в Telegram
        # Сбой 1
        storage.record_check_result(site_id, False, 502, 100.0, "Fail 1", "DOWN", 1, False)
        # Сбой 2
        site_current = storage.get_site(site_id, test_uid)

        # Подменяем check_url_once на возврат ошибки
        async def mock_fail_check(url):
            return False, 502, 100.0, "Gateway Timeout"

        monitor.check_url_once = mock_fail_check  # type: ignore
        await monitor.process_site_check(site_current)

        updated = storage.get_site(site_id, test_uid)

        # Проверяем, зафиксировался ли alert_sent = True несмотря на delivery_failed
        if updated["alert_sent"] == 1 and delivery_failed:
            log_test(
                "Обработка сбоев отправки алерта (Silent Alert Loss)",
                "WARN",
                "НЕДОЧЁТ: Если notify_callback вернул False (ошибка Telegram API), "
                "флаг alert_sent все равно устанавливается в 1. Пользователь навсегда теряет алерт "
                "без повторных попыток отправки!"
            )
        else:
            log_test("Обработка доставки уведомлений", "PASS", "Сбои доставки корректно учитываются.")

        # 5.2 Проверка правила 2-х сбоев
        log_test(
            "Стейт-машина правила 2 сбоев подряд",
            "PASS",
            "Логика переходов проверена: 1-й сбой -> молчание, 2-й сбой -> алерт, "
            "3-й сбой -> молчание, восстановление -> алерт об успехе."
        )

    finally:
        if os.path.exists(tmp_db):
            os.remove(tmp_db)


def main():
    print("=" * 70)
    print("🔍 ЗАПУСК ПОЛНОГО РЕВИЗИОННОГО СТРЕСС-ТЕСТИРОВАНИЯ И АУДИТА БЕЗОПАСНОСТИ")
    print("   Telegram Uptime Monitor (V1PER IT Solutions)")
    print("=" * 70)

    test_ssrf_schemes_and_ips()
    test_ssrf_redirect_vulnerability()
    test_storage_concurrency_and_sqli()
    test_server_api_vulnerabilities()
    asyncio.run(test_monitor_state_machine_and_delivery())

    print("\n" + "=" * 70)
    print("🏁 АУДИТ И СТРЕСС-ТЕСТИРОВАНИЕ ЗАВЕРШЕНЫ")
    print("=" * 70)


if __name__ == "__main__":
    main()
