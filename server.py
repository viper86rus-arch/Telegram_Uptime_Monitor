#!/usr/bin/env python3
"""
==============================================================================
HTTP и REST API Сервер: Telegram Uptime Monitor (server.py)
==============================================================================
Автор: V1PER (viper86rus-arch)
GitHub: https://github.com/viper86rus-arch/Telegram_Uptime_Monitor
Лицензия: MIT License (2026)
Назначение: Обслуживание Telegram Mini App (статические файлы HTML/CSS/JS),
            REST API для управления списком сайтов, защиты от SSRF и истории проверок.
==============================================================================
"""

import asyncio
import json
import mimetypes
import re
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import config
from monitor import UptimeMonitor
from security import validate_telegram_init_data, validate_url_ssrf
from storage import Storage

logger = config.logger
WEB_DIR = config.BASE_DIR / "web"


class UptimeApiHandler(BaseHTTPRequestHandler):
    """Обработчик HTTP и REST API запросов для Telegram Mini App."""

    server_version = "TelegramUptimeMonitor/1.0"

    # Ссылки на shared сервисы
    storage: Storage = None  # type: ignore
    monitor: UptimeMonitor = None  # type: ignore
    event_loop: asyncio.AbstractEventLoop = None  # type: ignore

    def _send_cors_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Telegram-Init-Data")

    def _send_json(self, status: int, data: Dict[str, Any]) -> None:
        raw_body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw_body)))
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(raw_body)

    def _send_error_json(self, status: int, error_message: str) -> None:
        self._send_json(status, {"ok": False, "error": error_message})

    def do_OPTIONS(self) -> None:
        """Поддержка CORS preflight запросов."""
        self.send_response(HTTPStatus.NO_CONTENT)
        self._send_cors_headers()
        self.end_headers()

    # ==========================================================================
    # АВТОРИЗАЦИЯ И ИДЕНТИФИКАЦИЯ TELEGRAM
    # ==========================================================================

    def _authenticate_request(self) -> Tuple[bool, Optional[int], Optional[str]]:
        """
        Извлечение и валидация данных Telegram Mini App (initData):
        Поддерживает:
        1. Заголовок 'Authorization: tma <initData>'
        2. Заголовок 'X-Telegram-Init-Data: <initData>'
        3. Query param '?initData=...'
        4. Режим демо-тестирования при передаче '?test_user_id=...'
        """
        init_data = ""
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("tma "):
            init_data = auth_header[4:].strip()
        elif "X-Telegram-Init-Data" in self.headers:
            init_data = self.headers.get("X-Telegram-Init-Data", "").strip()

        # Поиск в query params
        parsed_url = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed_url.query)
        if not init_data and "initData" in qs:
            init_data = qs["initData"][0]

        # Поддержка локального теста без Telegram (строго в режиме DEBUG и с localhost)
        if "test_user_id" in qs:
            client_ip = self.client_address[0] if self.client_address else ""
            if config.DEBUG and client_ip in ("127.0.0.1", "::1", "localhost"):
                try:
                    test_id = int(qs["test_user_id"][0])
                    self.storage.upsert_user(test_id, "test_dev", "Developer Test")
                    return True, test_id, None
                except (ValueError, IndexError):
                    return False, None, "Некорректный test_user_id"
            else:
                logger.warning(f"[Auth Guard] Заблокирована попытка неавторизованного входа через test_user_id (DEBUG={config.DEBUG}, IP={client_ip})")
                return False, None, "Параметр test_user_id запрещён в боевом режиме."

        if not init_data:
            return False, None, "Отсутствуют данные авторизации Telegram (initData)"

        is_valid, user_data, err = validate_telegram_init_data(init_data)
        if not is_valid:
            return False, None, err or "Ошибка проверки подлинности Telegram"

        if not user_data or "id" not in user_data:
            return False, None, "В initData отсутствуют данные о пользователе Telegram"

        user_id = int(user_data["id"])
        username = user_data.get("username")
        first_name = user_data.get("first_name")
        self.storage.upsert_user(user_id, username, first_name)
        return True, user_id, None

    # ==========================================================================
    # ОБРАБОТКА GET ЗАПРОСОВ
    # ==========================================================================

    def do_GET(self) -> None:
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        # 1. Healthcheck
        if path == "/health":
            self._send_json(HTTPStatus.OK, {
                "ok": True,
                "service": "Telegram_Uptime_Monitor",
                "status": "healthy",
                "max_urls": config.MAX_URLS_PER_USER,
                "check_interval_sec": config.CHECK_INTERVAL_SECONDS,
            })
            return

        # 2. REST API: /api/me
        if path == "/api/me":
            ok, user_id, err = self._authenticate_request()
            if not ok or not user_id:
                self._send_error_json(HTTPStatus.UNAUTHORIZED, err or "Не авторизован")
                return

            sites = self.storage.get_user_sites(user_id)
            self._send_json(HTTPStatus.OK, {
                "ok": True,
                "user_id": user_id,
                "sites_count": len(sites),
                "max_sites": config.MAX_URLS_PER_USER,
                "max_history": config.MAX_HISTORY_PER_URL,
            })
            return

        # 3. REST API: /api/sites
        if path == "/api/sites":
            ok, user_id, err = self._authenticate_request()
            if not ok or not user_id:
                self._send_error_json(HTTPStatus.UNAUTHORIZED, err or "Не авторизован")
                return

            sites = self.storage.get_user_sites(user_id)
            self._send_json(HTTPStatus.OK, {"ok": True, "sites": sites})
            return

        # 4. REST API: /api/sites/{id}/history (числовой ID до 18 знаков во избежание Integer Overflow)
        history_match = re.match(r"^/api/sites/(\d{1,18})/history$", path)
        if history_match:
            site_id = int(history_match.group(1))
            ok, user_id, err = self._authenticate_request()
            if not ok or not user_id:
                self._send_error_json(HTTPStatus.UNAUTHORIZED, err or "Не авторизован")
                return

            history = self.storage.get_site_history(site_id, user_id, limit=config.MAX_HISTORY_PER_URL)
            self._send_json(HTTPStatus.OK, {"ok": True, "site_id": site_id, "history": history})
            return

        # 5. Статические файлы для Telegram Mini App (/web)
        self._serve_static(path)

    # ==========================================================================
    # ОБРАБОТКА POST ЗАПРОСОВ
    # ==========================================================================

    def do_POST(self) -> None:
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        # Безопасное чтение Content-Length (максимум 64 КБ для защиты от DoS)
        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except (ValueError, TypeError):
            self._send_error_json(HTTPStatus.BAD_REQUEST, "Некорректный заголовок Content-Length.")
            return

        if content_length > 65536:
            self._send_error_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Превышен максимальный размер тела запроса (64 КБ).")
            return

        body_bytes = self.rfile.read(content_length) if content_length > 0 else b""
        payload = {}
        if body_bytes:
            try:
                payload = json.loads(body_bytes.decode("utf-8"))
            except Exception:
                self._send_error_json(HTTPStatus.BAD_REQUEST, "Некорректный JSON в теле запроса.")
                return

        # 1. REST API: Добавление сайта (POST /api/sites)
        if path == "/api/sites":
            ok, user_id, err = self._authenticate_request()
            if not ok or not user_id:
                self._send_error_json(HTTPStatus.UNAUTHORIZED, err or "Не авторизован")
                return

            if not isinstance(payload, dict):
                self._send_error_json(HTTPStatus.BAD_REQUEST, "Тело запроса должно быть JSON-объектом.")
                return

            raw_url = payload.get("url")
            if not isinstance(raw_url, str) or not raw_url.strip():
                self._send_error_json(HTTPStatus.BAD_REQUEST, "Поле 'url' обязательно и должно быть строкой.")
                return

            raw_url = raw_url.strip()
            if len(raw_url) > 2048:
                self._send_error_json(HTTPStatus.BAD_REQUEST, "Превышена максимальная длина URL (2048 символов).")
                return

            # Проверка безопасности: SSRF Guard
            is_safe, ssrf_err = validate_url_ssrf(raw_url)
            if not is_safe:
                self._send_error_json(HTTPStatus.BAD_REQUEST, ssrf_err or "Запрещённый URL (SSRF).")
                return

            # Добавление в БД с проверкой лимита (до 5 сайтов)
            success, new_site, add_err = self.storage.add_site(user_id, raw_url)
            if not success or not new_site:
                self._send_error_json(HTTPStatus.BAD_REQUEST, add_err or "Не удалось добавить сайт.")
                return

            # Мгновенная проверка первого статуса в фоне
            if self.monitor and self.event_loop:
                asyncio.run_coroutine_threadsafe(
                    self.monitor.process_site_check(new_site),
                    self.event_loop
                )

            self._send_json(HTTPStatus.CREATED, {"ok": True, "site": new_site})
            return

        # 2. REST API: Ручная мгновенная проверка (POST /api/sites/{id}/check)
        check_match = re.match(r"^/api/sites/(\d{1,18})/check$", path)
        if check_match:
            site_id = int(check_match.group(1))
            ok, user_id, err = self._authenticate_request()
            if not ok or not user_id:
                self._send_error_json(HTTPStatus.UNAUTHORIZED, err or "Не авторизован")
                return

            site = self.storage.get_site(site_id, user_id)
            if not site:
                self._send_error_json(HTTPStatus.NOT_FOUND, "Сайт не найден или у вас нет прав доступа.")
                return

            if self.monitor and self.event_loop:
                future = asyncio.run_coroutine_threadsafe(
                    self.monitor.process_site_check(site),
                    self.event_loop
                )
                try:
                    future.result(timeout=15.0)
                except Exception as e:
                    logger.error(f"[Server] Ошибка немедленной проверки: {e}")

            updated_site = self.storage.get_site(site_id, user_id)
            self._send_json(HTTPStatus.OK, {"ok": True, "site": updated_site})
            return

        self._send_error_json(HTTPStatus.NOT_FOUND, f"Маршрут POST {path} не найден.")

    # ==========================================================================
    # ОБРАБОТКА DELETE ЗАПРОСОВ
    # ==========================================================================

    def do_DELETE(self) -> None:
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        # REST API: Удаление сайта (DELETE /api/sites/{id})
        delete_match = re.match(r"^/api/sites/(\d{1,18})$", path)
        if delete_match:
            site_id = int(delete_match.group(1))
            ok, user_id, err = self._authenticate_request()
            if not ok or not user_id:
                self._send_error_json(HTTPStatus.UNAUTHORIZED, err or "Не авторизован")
                return

            deleted = self.storage.delete_site(site_id, user_id)
            if not deleted:
                self._send_error_json(HTTPStatus.NOT_FOUND, "Сайт не найден или у вас нет прав на его удаление.")
                return

            self._send_json(HTTPStatus.OK, {"ok": True, "deleted_site_id": site_id})
            return

        self._send_error_json(HTTPStatus.NOT_FOUND, f"Маршрут DELETE {path} не найден.")

    # ==========================================================================
    # РАЗДАЧА СТАТИЧЕСКИХ ФАЙЛОВ TELEGRAM MINI APP
    # ==========================================================================

    def _serve_static(self, request_path: str) -> None:
        clean_path = request_path.lstrip("/")
        if not clean_path or clean_path == "/":
            clean_path = "index.html"

        file_path = (WEB_DIR / clean_path).resolve()

        # Строгая защита от Directory Traversal
        try:
            if not file_path.is_relative_to(WEB_DIR):
                self._send_error_json(HTTPStatus.FORBIDDEN, "Доступ запрещён.")
                return
        except AttributeError:
            if not str(file_path).startswith(str(WEB_DIR) + os.sep) and file_path != WEB_DIR:
                self._send_error_json(HTTPStatus.FORBIDDEN, "Доступ запрещён.")
                return

        if not file_path.is_file():
            self._send_error_json(HTTPStatus.NOT_FOUND, f"Файл {clean_path} не найден.")
            return

        mime_type, _ = mimetypes.guess_type(str(file_path))
        if not mime_type:
            mime_type = "application/octet-stream"
        if mime_type.startswith("text/") or mime_type in ("application/javascript", "application/json"):
            mime_type += "; charset=utf-8"

        try:
            content = file_path.read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", mime_type)
            self.send_header("Content-Length", str(len(content)))
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            logger.error(f"[Server] Ошибка отправки статического файла {file_path}: {e}")
            self._send_error_json(HTTPStatus.INTERNAL_SERVER_ERROR, "Ошибка чтения файла.")


class UptimeServer:
    """Обертка управления жизненным циклом сервера."""

    def __init__(self, storage: Storage, monitor: UptimeMonitor, loop: asyncio.AbstractEventLoop):
        self.storage = storage
        self.monitor = monitor
        self.loop = loop
        self.httpd: Optional[ThreadingHTTPServer] = None

    def start(self) -> None:
        UptimeApiHandler.storage = self.storage
        UptimeApiHandler.monitor = self.monitor
        UptimeApiHandler.event_loop = self.loop

        addr = (config.SERVER_HOST, config.SERVER_PORT)
        self.httpd = ThreadingHTTPServer(addr, UptimeApiHandler)
        logger.info(f"[Server] HTTP & REST API сервер запущен на http://{config.SERVER_HOST}:{config.SERVER_PORT}")
        self.httpd.serve_forever()

    def stop(self) -> None:
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            logger.info("[Server] HTTP сервер успешно остановлен.")
