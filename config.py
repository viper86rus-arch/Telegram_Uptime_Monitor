#!/usr/bin/env python3
"""
==============================================================================
Конфигурационный модуль: Telegram Uptime Monitor (config.py)
==============================================================================
Автор: V1PER (viper86rus-arch)
GitHub: https://github.com/viper86rus-arch/Telegram_Uptime_Monitor
Лицензия: MIT License (2026)
Назначение: Загрузка переменных окружения без внешних зависимостей (Zero-Pip),
            валидация настроек и централизованное логирование.
==============================================================================
"""

import logging
import os
import sys
from pathlib import Path

# ==============================================================================
# 1. ПУТИ И ОКРУЖЕНИЕ
# ==============================================================================

BASE_DIR = Path(__file__).resolve().parent
ENV_PATH = BASE_DIR / ".env"


def load_env(filepath: Path) -> None:
    """Безопасный парсинг .env без внешних зависимостей (Zero-Pip)."""
    if not filepath.exists():
        return
    with filepath.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip().strip("'\"")
                if key and key not in os.environ:
                    os.environ[key] = val


load_env(ENV_PATH)

# ==============================================================================
# 2. ПАРАМЕТРЫ СЕРВИСА И ЛИМИТЫ ПО ТЗ
# ==============================================================================

TELEGRAM_BOT_TOKEN: str = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()

SERVER_HOST: str = os.getenv("SERVER_HOST", "0.0.0.0")
SERVER_PORT: int = int(os.getenv("SERVER_PORT", "8000"))
WEBAPP_URL: str = os.getenv("WEBAPP_URL", f"http://{SERVER_HOST}:{SERVER_PORT}").rstrip("/")

# Периодичность проверок URL (по ТЗ: каждые 5 минут = 300 секунд)
CHECK_INTERVAL_SECONDS: int = int(os.getenv("CHECK_INTERVAL_SECONDS", "300"))

# Лимиты по ТЗ
MAX_URLS_PER_USER: int = int(os.getenv("MAX_URLS_PER_USER", "5"))
MAX_HISTORY_PER_URL: int = int(os.getenv("MAX_HISTORY_PER_URL", "20"))
CONSECUTIVE_FAILS_THRESHOLD: int = int(os.getenv("CONSECUTIVE_FAILS_THRESHOLD", "2"))

# HTTP таймаут при проверке сайтов (в секундах)
HTTP_CHECK_TIMEOUT: float = float(os.getenv("HTTP_CHECK_TIMEOUT", "10.0"))

# Путь к SQLite базе данных
DB_PATH: Path = BASE_DIR / os.getenv("DB_PATH", "uptime_monitor.db")

# ==============================================================================
# 3. НАСТРОЙКА ЛОГИРОВАНИЯ
# ==============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)

logger = logging.getLogger("UptimeMonitor")
