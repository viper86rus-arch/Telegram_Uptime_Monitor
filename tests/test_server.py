#!/usr/bin/env python3
"""
==============================================================================
Модульные тесты REST API: Telegram Uptime Monitor
==============================================================================
Автор: V1PER (viper86rus-arch) | Лицензия: MIT License (2026)
==============================================================================
"""

import asyncio
import json
import os
import tempfile
import threading
import time
import unittest
import urllib.request

import config
from monitor import UptimeMonitor
from server import UptimeServer
from storage import Storage


class TestServerApi(unittest.TestCase):
    """Тестирование REST API endpoints сервера."""

    @classmethod
    def setUpClass(cls):
        cls.tmp_fd, cls.tmp_path = tempfile.mkstemp(suffix=".db")
        cls.storage = Storage(db_path=cls.tmp_path)
        cls.user_id = 12345
        cls.storage.upsert_user(cls.user_id, "api_tester", "Tester")

        cls.monitor = UptimeMonitor(cls.storage)
        cls.loop = asyncio.new_event_loop()

        # Запуск сервера на свободном порту 8899
        config.SERVER_HOST = "127.0.0.1"
        config.SERVER_PORT = 8899
        cls.base_url = f"http://127.0.0.1:{config.SERVER_PORT}"

        cls.server = UptimeServer(cls.storage, cls.monitor, cls.loop)
        cls.server_thread = threading.Thread(target=cls.server.start, daemon=True)
        cls.server_thread.start()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        os.close(cls.tmp_fd)
        if os.path.exists(cls.tmp_path):
            os.remove(cls.tmp_path)

    def _api_call(self, method: str, endpoint: str, data: dict = None) -> tuple:
        url = f"{self.base_url}{endpoint}"
        body = json.dumps(data).encode("utf-8") if data else None
        req = urllib.request.Request(url, data=body, method=method)
        req.add_header("Content-Type", "application/json")

        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                res_body = json.loads(resp.read().decode("utf-8"))
                return resp.status, res_body
        except urllib.error.HTTPError as e:
            res_body = json.loads(e.read().decode("utf-8"))
            return e.code, res_body

    def test_health(self):
        status, body = self._api_call("GET", "/health")
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertEqual(body["service"], "Telegram_Uptime_Monitor")

    def test_sites_crud_and_limits(self):
        # 1. Список изначально пуст
        status, body = self._api_call("GET", f"/api/sites?test_user_id={self.user_id}")
        self.assertEqual(status, 200)
        self.assertEqual(len(body["sites"]), 0)

        # 2. Добавление SSRF URL должно отклоняться (400)
        status, body = self._api_call("POST", f"/api/sites?test_user_id={self.user_id}", {"url": "http://127.0.0.1:8000"})
        self.assertEqual(status, 400)
        self.assertFalse(body["ok"])
        self.assertIn("запрещено", body["error"])

        # 3. Добавление валидного публичного URL
        status, body = self._api_call("POST", f"/api/sites?test_user_id={self.user_id}", {"url": "https://example.com"})
        self.assertEqual(status, 201)
        self.assertTrue(body["ok"])
        site_id = body["site"]["id"]

        # 4. Проверка появления в списке
        status, body = self._api_call("GET", f"/api/sites?test_user_id={self.user_id}")
        self.assertEqual(status, 200)
        self.assertEqual(len(body["sites"]), 1)
        self.assertEqual(body["sites"][0]["url"], "https://example.com")

        # 5. Получение истории
        status, body = self._api_call("GET", f"/api/sites/{site_id}/history?test_user_id={self.user_id}")
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])

        # 6. Удаление сайта
        status, body = self._api_call("DELETE", f"/api/sites/{site_id}?test_user_id={self.user_id}")
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])

        # 7. Проверка, что сайт удален
        status, body = self._api_call("GET", f"/api/sites?test_user_id={self.user_id}")
        self.assertEqual(status, 200)
        self.assertEqual(len(body["sites"]), 0)


if __name__ == "__main__":
    unittest.main()
