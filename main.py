#!/usr/bin/env python3
"""
==============================================================================
Главная точка входа: Telegram Uptime Monitor (main.py)
==============================================================================
Автор: V1PER (viper86rus-arch)
GitHub: https://github.com/viper86rus-arch/Telegram_Uptime_Monitor
Лицензия: MIT License (2026)
Назначение: Запуск единой экосистемы: HTTP REST API, Telegram Mini App,
            фонового воркера мониторинга (каждые 5 мин) и бота уведомлений.
==============================================================================
"""

import asyncio
import signal
import sys
import threading
from typing import Optional

import config
from bot import TelegramBot
from monitor import UptimeMonitor
from server import UptimeServer
from storage import Storage

logger = config.logger


class Application:
    """Управление жизненным циклом компонентов сервиса мониторинга."""

    def __init__(self):
        self.storage = Storage()
        self.bot = TelegramBot(self.storage)
        self.monitor = UptimeMonitor(self.storage, notify_callback=self.bot.send_notification)
        self.server: Optional[UptimeServer] = None
        self.server_thread: Optional[threading.Thread] = None
        self._shutdown_event = asyncio.Event()

    async def run(self) -> None:
        loop = asyncio.get_running_loop()

        print("\n" + "=" * 70)
        print("🚀 ЗАПУСК СЕРВИСА: Telegram Uptime Monitor (V1PER IT Solutions)")
        print("=" * 70)
        print(f"📊 База данных: {config.DB_PATH}")
        print(f"🌐 HTTP & Mini App: http://{config.SERVER_HOST}:{config.SERVER_PORT}")
        print(f"⏱️  Интервал проверок: каждые {config.CHECK_INTERVAL_SECONDS} секунд (5 минут)")
        print(f"🔒 Лимиты по ТЗ: макс {config.MAX_URLS_PER_USER} сайтов, 20 записей истории")
        print(f"🛡️  Безопасность: SSRF Guard (RFC 1918) + Telegram HMAC-SHA256 Auth")
        print("-" * 70)

        # 1. Запуск HTTP REST API сервера в отдельном потоке
        self.server = UptimeServer(self.storage, self.monitor, loop)
        self.server_thread = threading.Thread(target=self.server.start, daemon=True, name="HttpServerThread")
        self.server_thread.start()

        # 2. Запуск фоновых асинхронных задач
        tasks = [
            asyncio.create_task(self.monitor.start(), name="MonitorWorker"),
            asyncio.create_task(self.bot.start_polling(), name="BotPolling"),
        ]

        # 3. Регистрация сигналов остановки
        def _on_signal():
            logger.info("[App] Получен сигнал завершения. Остановка сервисов...")
            self._shutdown_event.set()

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, _on_signal)
            except NotImplementedError:
                pass  # Для сред без поддержки add_signal_handler

        try:
            await self._shutdown_event.wait()
        except asyncio.CancelledError:
            pass
        finally:
            logger.info("[App] Завершение работы...")
            self.monitor.stop()
            self.bot.stop()
            if self.server:
                self.server.stop()

            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            logger.info("[App] Все сервисы благополучно остановлены.")


def main():
    app = Application()
    try:
        asyncio.run(app.run())
    except KeyboardInterrupt:
        logger.info("[App] Сервис остановлен пользователем (SIGINT).")
        sys.exit(130)


if __name__ == "__main__":
    main()
