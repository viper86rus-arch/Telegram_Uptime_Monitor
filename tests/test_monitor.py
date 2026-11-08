#!/usr/bin/env python3
"""
==============================================================================
Модульные тесты мониторинга: Стейт-машина 2-х сбоев и восстановление
==============================================================================
Автор: V1PER (viper86rus-arch) | Лицензия: MIT License (2026)
==============================================================================
"""

import asyncio
import os
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from monitor import UptimeMonitor
from storage import Storage


class TestMonitor(unittest.IsolatedAsyncioTestCase):
    """Тестирование логики уведомлений и сбоев по ТЗ."""

    async def asyncSetUp(self):
        self.tmp_fd, self.tmp_path = tempfile.mkstemp(suffix=".db")
        self.storage = Storage(db_path=self.tmp_path)
        self.user_id = 777
        self.storage.upsert_user(self.user_id, "test_user", "Tester")
        _, self.site, _ = self.storage.add_site(self.user_id, "https://test-target.com")
        self.notifications = []

        async def _mock_notify(uid, msg):
            self.notifications.append((uid, msg))
            return True

        self.monitor = UptimeMonitor(self.storage, notify_callback=_mock_notify)

    async def asyncTearDown(self):
        os.close(self.tmp_fd)
        if os.path.exists(self.tmp_path):
            os.remove(self.tmp_path)

    async def test_two_consecutive_fails_rule(self):
        """
        Проверка ключевого правила ТЗ:
        - 1-й сбой -> алерт НЕ отправляется.
        - 2-й сбой подряд -> алерт отправляется!
        - 3-й сбой подряд -> повторный алерт НЕ отправляется (без спама).
        - 4-й шаг: восстановление -> алерт о восстановлении отправляется!
        - 5-й шаг: стабильный успех -> повторный алерт не шлётся.
        """
        # Шаг 1: 1-й сбой
        with patch.object(self.monitor, "check_url_once", new_callable=AsyncMock) as mock_check:
            mock_check.return_value = (False, 502, 120.0, "Bad Gateway")
            site_data = self.storage.get_site(self.site["id"], self.user_id)
            await self.monitor.process_site_check(site_data)

            self.assertEqual(len(self.notifications), 0, "После первого сбоя уведомление НЕ должно отправляться")
            updated = self.storage.get_site(self.site["id"], self.user_id)
            self.assertEqual(updated["consecutive_fails"], 1)
            self.assertEqual(updated["alert_sent"], 0)

        # Шаг 2: 2-й сбой подряд
        with patch.object(self.monitor, "check_url_once", new_callable=AsyncMock) as mock_check:
            mock_check.return_value = (False, 502, 115.0, "Bad Gateway")
            site_data = self.storage.get_site(self.site["id"], self.user_id)
            await self.monitor.process_site_check(site_data)

            self.assertEqual(len(self.notifications), 1, "Ровно после 2-го сбоя подряд ДОЛЖНО уйти уведомление!")
            self.assertIn("сайт недоступен", self.notifications[0][1])
            updated = self.storage.get_site(self.site["id"], self.user_id)
            self.assertEqual(updated["consecutive_fails"], 2)
            self.assertEqual(updated["alert_sent"], 1)

        # Шаг 3: 3-й сбой подряд (продолжение лежания)
        with patch.object(self.monitor, "check_url_once", new_callable=AsyncMock) as mock_check:
            mock_check.return_value = (False, 502, 110.0, "Bad Gateway")
            site_data = self.storage.get_site(self.site["id"], self.user_id)
            await self.monitor.process_site_check(site_data)

            self.assertEqual(len(self.notifications), 1, "При 3-м сбое подряд спам-уведомление НЕ отправляется")
            updated = self.storage.get_site(self.site["id"], self.user_id)
            self.assertEqual(updated["consecutive_fails"], 3)
            self.assertEqual(updated["alert_sent"], 1)

        # Шаг 4: Восстановление доступности!
        with patch.object(self.monitor, "check_url_once", new_callable=AsyncMock) as mock_check:
            mock_check.return_value = (True, 200, 45.0, None)
            site_data = self.storage.get_site(self.site["id"], self.user_id)
            await self.monitor.process_site_check(site_data)

            self.assertEqual(len(self.notifications), 2, "При восстановлении ДОЛЖНО уйти сообщение об успехе!")
            self.assertIn("восстановил работу", self.notifications[1][1])
            updated = self.storage.get_site(self.site["id"], self.user_id)
            self.assertEqual(updated["consecutive_fails"], 0)
            self.assertEqual(updated["alert_sent"], 0)
            self.assertEqual(updated["status"], "UP")

        # Шаг 5: Повторный стабильный успех
        with patch.object(self.monitor, "check_url_once", new_callable=AsyncMock) as mock_check:
            mock_check.return_value = (True, 200, 40.0, None)
            site_data = self.storage.get_site(self.site["id"], self.user_id)
            await self.monitor.process_site_check(site_data)

            self.assertEqual(len(self.notifications), 2, "Повторный успех не шлёт лишних сообщений")


if __name__ == "__main__":
    unittest.main()
