#!/usr/bin/env python3
"""
==============================================================================
Модуль безопасности: Telegram Uptime Monitor (security.py)
==============================================================================
Автор: V1PER (viper86rus-arch)
GitHub: https://github.com/viper86rus-arch/Telegram_Uptime_Monitor
Лицензия: MIT License (2026)
Назначение: Защита от SSRF (Server-Side Request Forgery) и криптографическая
            валидация подлинности данных авторизации Telegram Mini App (HMAC-SHA256).
==============================================================================
"""

import hashlib
import hmac
import http.client
import ipaddress
import json
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional, Tuple

import config

logger = config.logger

# ==============================================================================
# 1. ЗАЩИТА ОТ SSRF (Server-Side Request Forgery) ПО ТЗ
# ==============================================================================

FORBIDDEN_HOSTNAMES = {
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    "metadata.google.internal",
}


def validate_url_ssrf(url: str) -> Tuple[bool, Optional[str]]:
    """
    Строгая валидация URL на отсутствие уязвимостей SSRF:
    1. Проверка схемы (только http или https).
    2. Проверка домена и DNS-резолв.
    3. Отсечение приватных, петлевых (loopback), link-local и служебных IP.
    """
    if not url or not isinstance(url, str):
        return False, "URL не указан или имеет некорректный формат."

    url = url.strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        return False, "Поддерживаются только веб-адреса с протоколами http:// или https://"

    try:
        parsed = urllib.parse.urlparse(url)
    except Exception as e:
        return False, f"Некорректный синтаксис URL: {e}"

    if not parsed.scheme or parsed.scheme.lower() not in ("http", "https"):
        return False, "Схема адреса должна быть строго http или https."

    hostname = parsed.hostname
    if not hostname:
        return False, "Не удалось определить хост в указанном URL."

    hostname_lower = hostname.lower()

    # Запрет явных локальных хостов
    if hostname_lower in FORBIDDEN_HOSTNAMES or hostname_lower.endswith(".local") or hostname_lower.endswith(".internal"):
        return False, "Обращение к локальным, приватным или служебным хостам запрещено (SSRF)."

    # Резолв DNS в IP-адреса и проверка каждого IP
    try:
        addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror:
        return False, f"Не удалось разрешить доменное имя '{hostname}'. Проверьте правильность адреса."
    except Exception as e:
        return False, f"Ошибка сетевой валидации хоста '{hostname}': {e}"

    if not addr_info:
        return False, f"Хост '{hostname}' не вернул сетевых адресов."

    for family, _, _, _, sockaddr in addr_info:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False, f"Недопустимый сетевой адрес: {ip_str}"

        # Запрет всех приватных и внутренних диапазонов по RFC 1918, RFC 3927 и др.
        is_bad_ip = (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        )

        # Проверка IPv4-mapped IPv6 (например ::ffff:127.0.0.1)
        if not is_bad_ip and hasattr(ip, "ipv4_mapped") and ip.ipv4_mapped:
            mapped = ip.ipv4_mapped
            if (
                mapped.is_private
                or mapped.is_loopback
                or mapped.is_link_local
                or mapped.is_reserved
                or mapped.is_multicast
                or mapped.is_unspecified
            ):
                is_bad_ip = True

        if is_bad_ip:
            logger.warning(f"[SSRF Guard] Блокировка попытки добавления приватного адреса: {url} -> {ip_str}")
            return False, f"Добавление локальных и служебных адресов ({ip_str}) строго запрещено политикой безопасности."

    # Фиксация проверенного IP-адреса для предотвращения атак DNS Rebinding (TOCTOU)
    first_verified_ip = addr_info[0][4][0]
    pin_dns_record(hostname, first_verified_ip)

    return True, None


_PINNED_DNS_REGISTRY: Dict[str, Tuple[str, float]] = {}


def pin_dns_record(hostname: str, ip: str, ttl: float = 60.0) -> None:
    """Фиксирует проверенный IP-адрес для предотвращения атак DNS Rebinding (TOCTOU)."""
    _PINNED_DNS_REGISTRY[hostname.lower()] = (ip, time.time() + ttl)


def get_pinned_ip(hostname: str) -> Optional[str]:
    """Возвращает проверенный IP-адрес, если срок валидации не истек."""
    entry = _PINNED_DNS_REGISTRY.get(hostname.lower())
    if entry:
        ip, expires_at = entry
        if time.time() <= expires_at:
            return ip
    return None


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """
    Безопасный перехватчик HTTP-редиректов (301, 302, 303, 307, 308).
    Предотвращает SSRF-атаки через редирект внешнего сайта на приватные/локальные адреса.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        is_safe, err = validate_url_ssrf(newurl)
        if not is_safe:
            logger.warning(f"[SSRF Guard] Блокировка попытки обхода через HTTP {code} редирект: {newurl} ({err})")
            raise urllib.error.HTTPError(
                newurl,
                code,
                f"SSRF Redirect Blocked: {err}",
                headers,
                fp,
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTP-соединение, привязанное к предварительно валидированному IP (Anti-DNS-Rebinding)."""

    def connect(self):
        target_ip = get_pinned_ip(self.host) or self.host
        self.sock = self._create_connection(
            (target_ip, self.port), self.timeout, self.source_address
        )


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS-соединение с привязкой к проверенному IP и сохранением SNI-домена для TLS."""

    def connect(self):
        target_ip = get_pinned_ip(self.host) or self.host
        self.sock = self._create_connection(
            (target_ip, self.port), self.timeout, self.source_address
        )
        server_hostname = self._tunnel_host if self._tunnel_host else self.host
        self.sock = self.context.wrap_socket(self.sock, server_hostname=server_hostname)


class PinnedDNSHTTPHandler(urllib.request.HTTPHandler):
    """Обработчик HTTP с защитой от изменения DNS между проверкой и запросом (TOCTOU Shield)."""

    def http_open(self, req):
        return self.do_open(PinnedHTTPConnection, req)


class PinnedDNSHTTPSHandler(urllib.request.HTTPSHandler):
    """Обработчик HTTPS с защитой от изменения DNS между проверкой и запросом (TOCTOU Shield)."""

    def https_open(self, req):
        return self.do_open(
            PinnedHTTPSConnection,
            req,
            context=self._context,
            check_hostname=self._check_hostname,
        )


# ==============================================================================
# 2. ВАЛИДАЦИЯ АВТОРИЗАЦИИ TELEGRAM (initData HMAC-SHA256) ПО ТЗ
# ==============================================================================

def validate_telegram_init_data(init_data: str, bot_token: Optional[str] = None, max_age_seconds: int = 86400) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    """
    Официальная серверная валидация подлинности initData от Telegram Mini App:
    1. Извлекается хэш подписи.
    2. Формируется строка data_check_string по алфавиту ключей.
    3. Вычисляется HMAC-SHA256(HMAC-SHA256("WebAppData", bot_token), data_check_string).
    4. Сверяется подпись через time-safe hmac.compare_digest.
    5. Проверяется давность auth_date (по умолчанию до 24 часов).
    """
    token = (bot_token or config.TELEGRAM_BOT_TOKEN).strip()
    if not token:
        return False, None, "Токен бота не настроен на сервере."

    if not init_data:
        return False, None, "Отсутствуют данные авторизации Telegram (initData)."

    try:
        parsed_params = urllib.parse.parse_qsl(init_data, keep_blank_values=True)
    except Exception as e:
        return False, None, f"Ошибка парсинга initData: {e}"

    data_dict = dict(parsed_params)
    received_hash = data_dict.pop("hash", None)

    if not received_hash:
        return False, None, "Параметр hash отсутствует в initData."

    # Сортировка ключей по алфавиту и сборка проверочной строки
    data_check_arr = [f"{k}={v}" for k, v in sorted(data_dict.items())]
    data_check_string = "\n".join(data_check_arr)

    # Вычисление секретного ключа: HMAC_SHA256("WebAppData", bot_token)
    secret_key = hmac.new(b"WebAppData", token.encode("utf-8"), hashlib.sha256).digest()

    # Вычисление подписи
    calculated_hash = hmac.new(secret_key, data_check_string.encode("utf-8"), hashlib.sha256).hexdigest()

    if not hmac.compare_digest(calculated_hash, received_hash):
        logger.warning("[Auth Guard] Несовпадение цифровой подписи initData Telegram")
        return False, None, "Недействительная цифровая подпись Telegram."

    # Проверка актуальности времени auth_date
    auth_date_str = data_dict.get("auth_date")
    if auth_date_str and auth_date_str.isdigit():
        auth_date = int(auth_date_str)
        current_time = int(time.time())
        if current_time - auth_date > max_age_seconds:
            return False, None, "Сессия Telegram устарела. Перезапустите приложение."

    # Извлечение данных пользователя
    user_json = data_dict.get("user")
    user_data = None
    if user_json:
        try:
            user_data = json.loads(user_json)
        except Exception:
            user_data = None

    return True, user_data, None
