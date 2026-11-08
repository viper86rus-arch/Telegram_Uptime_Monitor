#!/usr/bin/env python3
"""
==============================================================================
Модуль мониторинга: Telegram Uptime Monitor (monitor.py)
==============================================================================
Автор: V1PER (viper86rus-arch)
GitHub: https://github.com/viper86rus-arch/Telegram_Uptime_Monitor
Лицензия: MIT License (2026)
Назначение: Асинхронная проверка доступности сайтов, замер времени ответа (latency),
            стейт-машина алертов (уведомление строго после 2 сбоев подряд и при восстановлении).
==============================================================================
"""

import asyncio
import ssl
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Coroutine, Dict, Optional, Tuple

import config
from security import validate_url_ssrf
from storage import Storage

logger = config.logger

# Callback тип для отправки сообщений ботом
NotificationCallback = Optional[Callable[[int, str], Coroutine[Any, Any, bool]]]


class UptimeMonitor:
    """Асинхронный движок фоновой проверки доступности веб-ресурсов."""

    def __init__(self, storage: Storage, notify_callback: NotificationCallback = None):
        self.storage = storage
        self.notify_callback = notify_callback
        self._running = False
        self._task: Optional[asyncio.Task] = None

    async def check_url_once(self, url: str) -> Tuple[bool, Optional[int], float, Optional[str]]:
        """
        Единичная проверка URL с замером времени ответа и предварительной защитой от SSRF:
        Возвращает: (is_success, status_code, response_time_ms, error_message).
        """
        # 1. Защита от SSRF
        is_safe, ssrf_err = validate_url_ssrf(url)
        if not is_safe:
            return False, None, 0.0, f"SSRF Блокировка: {ssrf_err}"

        # 2. Выполнение HTTP/HTTPS запроса с замером времени
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; Telegram-Uptime-Monitor/1.0; +https://github.com/viper86rus-arch)",
                "Accept": "*/*",
            },
        )

        ctx = ssl.create_default_context()
        # В тестах допускаются сертификаты системы
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        start_time = time.perf_counter()

        def _do_request():
            try:
                with urllib.request.urlopen(req, timeout=config.HTTP_CHECK_TIMEOUT, context=ctx) as resp:
                    code = resp.getcode()
                    # 2xx и 3xx считаются успешной доступностью
                    success = 200 <= code < 400
                    return success, code, None
            except urllib.error.HTTPError as e:
                # Сервер ответил ошибкой 4xx или 5xx
                return False, e.code, f"HTTP {e.code}: {e.reason}"
            except urllib.error.URLError as e:
                # Ошибка сети / DNS / таймаут
                reason_str = str(e.reason)
                if "timed out" in reason_str.lower():
                    return False, None, f"Таймаут соединения (> {config.HTTP_CHECK_TIMEOUT}с)"
                return False, None, f"Сетевая ошибка: {reason_str}"
            except Exception as e:
                return False, None, f"Исключение при запросе: {type(e).__name__} ({e})"

        is_success, status_code, err_msg = await asyncio.to_thread(_do_request)
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return is_success, status_code, elapsed_ms, err_msg

    async def process_site_check(self, site: Dict[str, Any]) -> None:
        """
        Полная обработка одной проверки сайта со стейт-машиной алертов:
        - 2 сбоя подряд -> алерт пользователю;
        - повторные сбои (3, 4...) -> без спама;
        - следующий успех -> алерт о восстановлении работы.
        """
        site_id = site["id"]
        user_id = site["user_id"]
        url = site["url"]
        prev_consecutive_fails = site.get("consecutive_fails", 0)
        prev_alert_sent = bool(site.get("alert_sent", 0))

        is_success, status_code, latency_ms, err_msg = await self.check_url_once(url)

        if is_success:
            new_status = "UP"
            new_consecutive_fails = 0
            new_alert_sent = False

            # Если ранее отправлялся алерт о сбое, шлём алерт о восстановлении!
            if prev_alert_sent:
                logger.info(f"[Monitor] Сайт {url} (User {user_id}) восстановил доступность! Отправка уведомления.")
                if self.notify_callback:
                    msg = (
                        f"🟢 <b>Сайт восстановил работу!</b>\n\n"
                        f"🔗 <code>{url}</code>\n"
                        f"📊 Код ответа: <b>{status_code} OK</b>\n"
                        f"⚡ Время ответа: <b>{latency_ms:.1f} мс</b>"
                    )
                    await self.notify_callback(user_id, msg)
        else:
            new_status = "DOWN"
            new_consecutive_fails = prev_consecutive_fails + 1
            new_alert_sent = prev_alert_sent

            logger.warning(
                f"[Monitor] Сбой сайта {url} (User {user_id}): {err_msg} "
                f"(Сбоев подряд: {new_consecutive_fails})"
            )

            # Триггер алерта строго после CONSECUTIVE_FAILS_THRESHOLD (по ТЗ: 2 подряд сбоя)
            if new_consecutive_fails == config.CONSECUTIVE_FAILS_THRESHOLD and not prev_alert_sent:
                logger.info(f"[Monitor] 2 подряд сбоя для {url}. Отправка алерта пользователю {user_id}!")
                new_alert_sent = True
                if self.notify_callback:
                    code_str = f"HTTP {status_code}" if status_code else "Сетевой сбой"
                    msg = (
                        f"🔴 <b>Внимание: сайт недоступен!</b>\n\n"
                        f"🔗 <code>{url}</code>\n"
                        f"⚠️ Причина: <b>{err_msg or code_str}</b>\n"
                        f"❌ Зафиксировано 2 сбоя подряд с интервалом 5 мин.\n\n"
                        f"<i>Следующее уведомление придёт, когда сайт восстановит работу.</i>"
                    )
                    await self.notify_callback(user_id, msg)

        # Сохранение результатов в БД и ротация истории
        self.storage.record_check_result(
            site_id=site_id,
            is_success=is_success,
            status_code=status_code,
            response_time_ms=latency_ms,
            error_message=err_msg,
            new_status=new_status,
            consecutive_fails=new_consecutive_fails,
            alert_sent=new_alert_sent,
        )

    async def run_round(self) -> None:
        """Один раунд проверки всех активных сайтов."""
        sites = self.storage.get_all_active_sites()
        if not sites:
            return

        logger.info(f"[Monitor] Старт раунда проверки для {len(sites)} URL...")
        # Проверка сайтов параллельно с ограничением нагрузки (semaphore)
        semaphore = asyncio.Semaphore(10)

        async def _bound_check(s):
            async with semaphore:
                try:
                    await self.process_site_check(s)
                except Exception as e:
                    logger.error(f"[Monitor] Ошибка проверки сайта {s.get('url')}: {e}")

        await asyncio.gather(*[_bound_check(s) for s in sites])
        logger.info("[Monitor] Раунд проверок успешно завершён.")

    async def start(self) -> None:
        """Запуск бесконечного цикла фонового мониторинга."""
        self._running = True
        logger.info(f"[Monitor] Фоновый воркер запущен. Интервал: {config.CHECK_INTERVAL_SECONDS} секунд.")
        while self._running:
            try:
                await self.run_round()
            except Exception as e:
                logger.error(f"[Monitor] Ошибка в цикле мониторинга: {e}")

            # Ожидание следующего раунда с возможностью мгновенной остановки
            for _ in range(config.CHECK_INTERVAL_SECONDS):
                if not self._running:
                    break
                await asyncio.sleep(1)

    def stop(self) -> None:
        """Остановка воркера."""
        self._running = False
        logger.info("[Monitor] Фоновый воркер остановлен.")
