#!/usr/bin/env python3
"""
==============================================================================
Модульные тесты хранилища: Изоляция, лимит 5 URL и ротация истории 20 записей
==============================================================================
Автор: V1PER (viper86rus-arch) | Лицензия: MIT License (2026)
==============================================================================
"""

import os
import tempfile
import unittest

from storage import Storage


class TestStorage(unittest.TestCase):
    """Тестирование SQLite хранилища и бизнес-правил по ТЗ."""

    def setUp(self):
        self.tmp_fd, self.tmp_path = tempfile.mkstemp(suffix=".db")
        self.storage = Storage(db_path=self.tmp_path)
        self.user1 = 10001
        self.user2 = 10002
        self.storage.upsert_user(self.user1, "user1", "User One")
        self.storage.upsert_user(self.user2, "user2", "User Two")

    def tearDown(self):
        os.close(self.tmp_fd)
        if os.path.exists(self.tmp_path):
            os.remove(self.tmp_path)

    def test_site_limit_max_5(self):
        """Проверка строгого лимита: не более 5 сайтов на одного пользователя по ТЗ."""
        for i in range(1, 6):
            url = f"https://site{i}.example.com"
            ok, site, err = self.storage.add_site(self.user1, url)
            self.assertTrue(ok, f"Сайт {i} должен успешно добавиться: {err}")
            self.assertIsNotNone(site)

        # 6-й сайт должен вызвать ошибку лимита
        ok6, site6, err6 = self.storage.add_site(self.user1, "https://site6.example.com")
        self.assertFalse(ok6)
        self.assertIsNone(site6)
        self.assertIn("Достигнут лимит", err6)

        # Но для другого пользователя лимит независим!
        ok_u2, site_u2, err_u2 = self.storage.add_site(self.user2, "https://site_u2.example.com")
        self.assertTrue(ok_u2)

    def test_tenant_isolation(self):
        """Проверка изоляции: пользователь не видит и не может удалить чужие сайты."""
        ok1, site1, _ = self.storage.add_site(self.user1, "https://user1-site.com")
        ok2, site2, _ = self.storage.add_site(self.user2, "https://user2-site.com")

        # User 1 видит только свой сайт
        u1_sites = self.storage.get_user_sites(self.user1)
        self.assertEqual(len(u1_sites), 1)
        self.assertEqual(u1_sites[0]["url"], "https://user1-site.com")

        # User 1 пытается получить или удалить сайт User 2
        foreign_site = self.storage.get_site(site2["id"], self.user1)
        self.assertIsNone(foreign_site)

        deleted = self.storage.delete_site(site2["id"], self.user1)
        self.assertFalse(deleted)

        # Сайт User 2 по-прежнему на месте
        u2_sites = self.storage.get_user_sites(self.user2)
        self.assertEqual(len(u2_sites), 1)

    def test_history_capping_max_20(self):
        """Проверка ограничения истории: строго последние 20 проверок на сайт по ТЗ."""
        ok, site, _ = self.storage.add_site(self.user1, "https://monitor-history.com")
        site_id = site["id"]

        # Записываем 28 проверок
        for i in range(1, 29):
            self.storage.record_check_result(
                site_id=site_id,
                is_success=True,
                status_code=200,
                response_time_ms=50.0 + i,
                error_message=None,
                new_status="UP",
                consecutive_fails=0,
                alert_sent=False,
            )

        # Проверяем, что в истории осталось ровно 20 записей
        history = self.storage.get_site_history(site_id, self.user1, limit=50)
        self.assertEqual(len(history), 20)
        # Самая свежая запись (28-я) должна быть первой
        self.assertEqual(history[0]["response_time_ms"], 78.0)


if __name__ == "__main__":
    unittest.main()
