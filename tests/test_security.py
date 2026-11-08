#!/usr/bin/env python3
"""
==============================================================================
Модульные тесты безопасности: SSRF Guard & Telegram HMAC Validation
==============================================================================
Автор: V1PER (viper86rus-arch) | Лицензия: MIT License (2026)
==============================================================================
"""

import hashlib
import hmac
import time
import unittest
import urllib.parse

from security import validate_telegram_init_data, validate_url_ssrf


class TestSecurity(unittest.TestCase):
    """Тестирование механизмов безопасности по ТЗ."""

    def test_ssrf_forbidden_addresses(self):
        """Проверка отсечения локальных, петлевых и приватных адресов."""
        forbidden_urls = [
            "http://localhost",
            "http://localhost:8000/api",
            "http://127.0.0.1",
            "http://127.0.0.1:8080/admin",
            "http://0.0.0.0",
            "http://10.0.0.1",
            "http://192.168.1.1/router",
            "http://172.16.0.5",
            "http://169.254.169.254/latest/meta-data/",
            "ftp://example.com",
            "javascript:alert(1)",
            "",
            "not_a_url",
        ]

        for url in forbidden_urls:
            is_valid, err = validate_url_ssrf(url)
            self.assertFalse(is_valid, f"URL должен быть заблокирован: {url}")
            self.assertIsNotNone(err)

    def test_ssrf_valid_public_urls(self):
        """Проверка разрешения валидных публичных адресов."""
        valid_urls = [
            "https://google.com",
            "https://yandex.ru",
            "http://example.com",
            "https://github.com",
        ]

        for url in valid_urls:
            is_valid, err = validate_url_ssrf(url)
            self.assertTrue(is_valid, f"URL должен быть разрешён: {url} (Ошибка: {err})")

    def test_telegram_init_data_validation(self):
        """Проверка валидации HMAC-SHA256 подписи Telegram WebApp."""
        test_bot_token = "123456789:ABCdefGHIjklMNOpqrSTUvwxYZ"
        user_id = 998877
        auth_date = int(time.time())

        # Генерация валидного initData
        raw_params = {
            "auth_date": str(auth_date),
            "query_id": "AAHdF6IQAAAAAN0XohDhrP_1",
            "user": f'{{"id":{user_id},"first_name":"V1PER","username":"viper86"}}',
        }

        # data_check_string
        check_arr = [f"{k}={v}" for k, v in sorted(raw_params.items())]
        check_str = "\n".join(check_arr)

        secret_key = hmac.new(b"WebAppData", test_bot_token.encode("utf-8"), hashlib.sha256).digest()
        calc_hash = hmac.new(secret_key, check_str.encode("utf-8"), hashlib.sha256).hexdigest()

        valid_init_data = f"auth_date={auth_date}&query_id={raw_params['query_id']}&user={urllib.parse.quote(raw_params['user'])}&hash={calc_hash}"

        # 1. Валидный хэш должен успешно пройти
        is_valid, user_data, err = validate_telegram_init_data(valid_init_data, bot_token=test_bot_token)
        self.assertTrue(is_valid, f"Валидный initData должен пройти проверку. Ошибка: {err}")
        self.assertIsNotNone(user_data)
        self.assertEqual(user_data["id"], user_id)

        # 2. Поддельный хэш должен быть отклонён
        tampered_data = valid_init_data.replace(calc_hash, "fake_hash_12345")
        is_valid_fake, _, err_fake = validate_telegram_init_data(tampered_data, bot_token=test_bot_token)
        self.assertFalse(is_valid_fake)
        self.assertIn("Недействительная цифровая подпись", err_fake)

        # 3. Устаревшая сессия (> 24 часов)
        old_auth_date = int(time.time()) - 100000
        old_params = raw_params.copy()
        old_params["auth_date"] = str(old_auth_date)
        old_check_str = "\n".join([f"{k}={v}" for k, v in sorted(old_params.items())])
        old_hash = hmac.new(secret_key, old_check_str.encode("utf-8"), hashlib.sha256).hexdigest()
        old_init_data = f"auth_date={old_auth_date}&query_id={old_params['query_id']}&user={urllib.parse.quote(old_params['user'])}&hash={old_hash}"

        is_valid_old, _, err_old = validate_telegram_init_data(old_init_data, bot_token=test_bot_token)
        self.assertFalse(is_valid_old)
        self.assertIn("Сессия Telegram устарела", err_old)


if __name__ == "__main__":
    unittest.main()
