#!/usr/bin/env python3
"""
==============================================================================
Модуль Telegram-бота: Telegram Uptime Monitor (bot.py)
==============================================================================
Автор: V1PER (viper86rus-arch)
GitHub: https://github.com/viper86rus-arch/Telegram_Uptime_Monitor
Лицензия: MIT License (2026)
Назначение: Обработка команды /start, запуск Telegram Mini App через WebApp кнопку
            и асинхронная доставка push-уведомлений о сбоях и восстановлениях.
==============================================================================
"""

import asyncio
import json
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

import config
from storage import Storage

logger = config.logger


class TelegramBot:
    """Асинхронный клиент Telegram Bot API на чистом Python Standard Library (Zero-Pip)."""

    def __init__(self, storage: Storage):
        self.storage = storage
        self.token = config.TELEGRAM_BOT_TOKEN
        self.api_url = f"https://api.telegram.org/bot{self.token}"
        self._running = False
        self._last_update_id = 0

    async def _api_call(self, method: str, payload: Dict[str, Any], timeout: int = 15) -> Dict[str, Any]:
        """Отправка асинхронного POST-запроса к Telegram Bot API."""
        url = f"{self.api_url}/{method}"
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
        )

        def _do_call():
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))

        return await asyncio.to_thread(_do_call)

    async def send_notification(self, user_id: int, text: str) -> bool:
        """Отправка уведомления пользователю с HTML-форматированием."""
        if not self.token:
            logger.warning(f"[Bot] Токен не настроен. Симуляция отправки сообщения пользователю {user_id}: {text}")
            return True

        try:
            payload = {
                "chat_id": user_id,
                "text": text,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
            }
            res = await self._api_call("sendMessage", payload)
            return res.get("ok", False)
        except Exception as e:
            logger.error(f"[Bot] Ошибка отправки сообщения пользователю {user_id}: {e}")
            return False

    async def handle_start(self, chat_id: int, username: Optional[str], first_name: Optional[str]) -> None:
        """Обработка команды /start: регистрация пользователя и кнопка запуска Mini App."""
        self.storage.upsert_user(chat_id, username, first_name)

        welcome_text = (
            f"👋 <b>Добро пожаловать, {first_name or 'пользователь'}!</b>\n\n"
            f"🛡️ <b>Telegram Uptime Monitor</b> — автономный сервис контроля доступности сайтов.\n\n"
            f"📌 <b>Возможности:</b>\n"
            f"• Мониторинг до {config.MAX_URLS_PER_USER} сайтов (HTTP/HTTPS)\n"
            f"• Проверка каждые 5 минут 24/7 (даже при закрытом приложении)\n"
            f"• Защита от ложных тревог: алерт строго после 2 сбоев подряд\n"
            f"• Мгновенное оповещение о восстановлении работы\n"
            f"• История последних {config.MAX_HISTORY_PER_URL} проверок и замер миллисекунд\n\n"
            f"Нажмите кнопку ниже, чтобы открыть панель управления:"
        )

        webapp_url = config.WEBAPP_URL
        reply_markup = {
            "inline_keyboard": [
                [
                    {
                        "text": "📊 Открыть Mini App мониторинга",
                        "web_app": {"url": webapp_url},
                    }
                ]
            ]
        }

        payload = {
            "chat_id": chat_id,
            "text": welcome_text,
            "parse_mode": "HTML",
            "reply_markup": reply_markup,
        }
        try:
            await self._api_call("sendMessage", payload)
        except Exception as e:
            logger.error(f"[Bot] Ошибка отправки приветствия: {e}")

    async def start_polling(self) -> None:
        """Асинхронный long-polling обновлений от Telegram."""
        if not self.token:
            logger.warning("[Bot] Токен бота не задан, polling не запускается.")
            return

        self._running = True
        logger.info("[Bot] Запуск Telegram Long-Polling...")

        poll_timeout = 20
        client_timeout = poll_timeout + 10

        while self._running:
            try:
                payload = {
                    "offset": self._last_update_id + 1,
                    "timeout": poll_timeout,
                    "allowed_updates": ["message"],
                }
                res = await self._api_call("getUpdates", payload, timeout=client_timeout)
                if res.get("ok"):
                    for update in res.get("result", []):
                        self._last_update_id = update["update_id"]
                        msg = update.get("message")
                        if not msg:
                            continue

                        text = msg.get("text", "").strip()
                        from_user = msg.get("from", {})
                        user_id = from_user.get("id")
                        username = from_user.get("username")
                        first_name = from_user.get("first_name")

                        if text.startswith("/start") and user_id:
                            await self.handle_start(user_id, username, first_name)
            except asyncio.CancelledError:
                break
            except TimeoutError:
                # Нормальное поведение long-polling при отсутствии новых сообщений
                continue
            except Exception as e:
                # В случае сетевых перебоев или таймаутов urllib
                err_str = str(e)
                if "timed out" in err_str.lower():
                    continue
                logger.warning(f"[Bot] Временная заминка в long-polling цикле: {e}")
                await asyncio.sleep(2)

    def stop(self) -> None:
        """Остановка polling."""
        self._running = False
        logger.info("[Bot] Telegram Long-Polling остановлен.")
