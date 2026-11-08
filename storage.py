#!/usr/bin/env python3
"""
==============================================================================
Модуль хранилища данных: Telegram Uptime Monitor (storage.py)
==============================================================================
Автор: V1PER (viper86rus-arch)
GitHub: https://github.com/viper86rus-arch/Telegram_Uptime_Monitor
Лицензия: MIT License (2026)
Назначение: Управление базой данных SQLite (пользователи, сайты, история проверок),
            изоляция арендаторов (tenants), лимиты 5 сайтов и 20 записей истории.
==============================================================================
"""

import contextlib
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

import config

logger = config.logger


class Storage:
    """Потокобезопасный слой работы с базой данных SQLite для мониторинга сайтов."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = str(db_path or config.DB_PATH)
        self._write_lock = threading.Lock()
        self._init_db()

    @contextlib.contextmanager
    def _get_connection(self):
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA busy_timeout = 5000;")
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Инициализация схемы таблиц с индексами и триггерами защиты."""
        with self._get_connection() as conn:
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA synchronous = NORMAL;")
            conn.executescript(f"""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    username TEXT,
                    first_name TEXT,
                    created_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS sites (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    url TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'PENDING',
                    last_status_code INTEGER,
                    last_response_time_ms REAL,
                    last_checked_at INTEGER,
                    consecutive_fails INTEGER NOT NULL DEFAULT 0,
                    alert_sent INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                    UNIQUE (user_id, url)
                );

                CREATE TABLE IF NOT EXISTS check_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    site_id INTEGER NOT NULL,
                    checked_at INTEGER NOT NULL,
                    is_success INTEGER NOT NULL,
                    status_code INTEGER,
                    response_time_ms REAL NOT NULL,
                    error_message TEXT,
                    FOREIGN KEY (site_id) REFERENCES sites (id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_sites_user ON sites(user_id);
                CREATE INDEX IF NOT EXISTS idx_history_site ON check_history(site_id, checked_at DESC);

                -- Триггер защиты от Race Condition: запрет добавления > MAX_URLS_PER_USER на уровне движка БД
                CREATE TRIGGER IF NOT EXISTS trg_enforce_max_sites
                BEFORE INSERT ON sites
                FOR EACH ROW
                WHEN (SELECT COUNT(*) FROM sites WHERE user_id = NEW.user_id) >= {config.MAX_URLS_PER_USER}
                BEGIN
                    SELECT RAISE(ABORT, 'Лимит сайтов исчерпан: максимум {config.MAX_URLS_PER_USER} по ТЗ');
                END;
            """)
        logger.info(f"[Storage] База данных SQLite успешно инициализирована (WAL Mode): {self.db_path}")

    # ==========================================================================
    # 1. ПОЛЬЗОВАТЕЛИ
    # ==========================================================================

    def upsert_user(self, user_id: int, username: Optional[str] = None, first_name: Optional[str] = None) -> None:
        now = int(time.time())
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO users (id, username, first_name, created_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    username = excluded.username,
                    first_name = excluded.first_name
            """, (user_id, username or "", first_name or "", now))

    # ==========================================================================
    # 2. САЙТЫ (Соблюдение изоляции и лимита до 5 URL на пользователя)
    # ==========================================================================

    def get_user_sites(self, user_id: int) -> List[Dict[str, Any]]:
        """Получить все сайты конкретного пользователя (изоляция данных)."""
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT id, user_id, url, status, last_status_code,
                       last_response_time_ms, last_checked_at, consecutive_fails, alert_sent, created_at
                FROM sites
                WHERE user_id = ?
                ORDER BY id ASC
            """, (user_id,)).fetchall()
            return [dict(r) for r in rows]

    def get_site(self, site_id: int, user_id: int) -> Optional[Dict[str, Any]]:
        """Получить сайт с обязательной проверкой принадлежности пользователю."""
        with self._get_connection() as conn:
            row = conn.execute("""
                SELECT id, user_id, url, status, last_status_code,
                       last_response_time_ms, last_checked_at, consecutive_fails, alert_sent, created_at
                FROM sites
                WHERE id = ? AND user_id = ?
            """, (site_id, user_id)).fetchone()
            return dict(row) if row else None

    def add_site(self, user_id: int, url: str) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        """
        Добавление нового сайта с контролем лимита 5 URL и защитой от Race Condition:
        Возвращает (success, site_dict, error_message).
        """
        norm_url = url.strip()
        now = int(time.time())

        with self._write_lock:
            with self._get_connection() as conn:
                # 1. Проверка текущего количества сайтов пользователя
                count_row = conn.execute("SELECT COUNT(*) as cnt FROM sites WHERE user_id = ?", (user_id,)).fetchone()
                current_count = count_row["cnt"] if count_row else 0

                if current_count >= config.MAX_URLS_PER_USER:
                    return False, None, f"Достигнут лимит: максимум {config.MAX_URLS_PER_USER} сайтов на одного пользователя."

                # 2. Проверка дубликата
                existing = conn.execute("SELECT id FROM sites WHERE user_id = ? AND url = ?", (user_id, norm_url)).fetchone()
                if existing:
                    return False, None, "Этот сайт уже добавлен в ваш список мониторинга."

                # 3. Вставка с проверкой триггера БД
                try:
                    cur = conn.execute("""
                        INSERT INTO sites (user_id, url, status, created_at)
                        VALUES (?, ?, 'PENDING', ?)
                    """, (user_id, norm_url, now))
                    new_id = cur.lastrowid
                except sqlite3.OperationalError as e:
                    if "Лимит сайтов исчерпан" in str(e):
                        return False, None, f"Достигнут лимит: максимум {config.MAX_URLS_PER_USER} сайтов на одного пользователя."
                    return False, None, f"Ошибка сохранения сайта: {e}"
                except Exception as e:
                    return False, None, f"Ошибка сохранения сайта: {e}"

                site_row = conn.execute("SELECT * FROM sites WHERE id = ?", (new_id,)).fetchone()
                return True, dict(site_row), None

    def delete_site(self, site_id: int, user_id: int) -> bool:
        """Удаление сайта с гарантией проверки прав доступа."""
        with self._get_connection() as conn:
            cur = conn.execute("DELETE FROM sites WHERE id = ? AND user_id = ?", (site_id, user_id))
            return cur.rowcount > 0

    def get_all_active_sites(self) -> List[Dict[str, Any]]:
        """Получить все сайты системы для фонового воркера мониторинга."""
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT s.id, s.user_id, s.url, s.status, s.last_status_code,
                       s.last_response_time_ms, s.last_checked_at, s.consecutive_fails, s.alert_sent,
                       u.username
                FROM sites s
                LEFT JOIN users u ON s.user_id = u.id
            """).fetchall()
            return [dict(r) for r in rows]

    # ==========================================================================
    # 3. ИСТОРИЯ ПРОВЕРОК (Ограничение: строго последние 20 проверок на сайт)
    # ==========================================================================

    def record_check_result(
        self,
        site_id: int,
        is_success: bool,
        status_code: Optional[int],
        response_time_ms: float,
        error_message: Optional[str],
        new_status: str,
        consecutive_fails: int,
        alert_sent: bool,
    ) -> None:
        """
        Фиксация результата проверки:
        1. Обновление текущего статуса сайта и счетчиков сбоев.
        2. Запись в историю.
        3. Обрезка истории до последних 20 записей (MAX_HISTORY_PER_URL) по ТЗ.
        """
        now = int(time.time())
        with self._get_connection() as conn:
            # Обновление записи сайта
            conn.execute("""
                UPDATE sites
                SET status = ?,
                    last_status_code = ?,
                    last_response_time_ms = ?,
                    last_checked_at = ?,
                    consecutive_fails = ?,
                    alert_sent = ?
                WHERE id = ?
            """, (
                new_status,
                status_code,
                round(response_time_ms, 2),
                now,
                consecutive_fails,
                1 if alert_sent else 0,
                site_id,
            ))

            # Добавление в историю
            conn.execute("""
                INSERT INTO check_history (site_id, checked_at, is_success, status_code, response_time_ms, error_message)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                site_id,
                now,
                1 if is_success else 0,
                status_code,
                round(response_time_ms, 2),
                error_message,
            ))

            # Ротация: удаление старых записей сверх лимита 20
            conn.execute("""
                DELETE FROM check_history
                WHERE site_id = ?
                  AND id NOT IN (
                      SELECT id FROM check_history
                      WHERE site_id = ?
                      ORDER BY checked_at DESC, id DESC
                      LIMIT ?
                  )
            """, (site_id, site_id, config.MAX_HISTORY_PER_URL))

    def get_site_history(self, site_id: int, user_id: int, limit: int = 20) -> List[Dict[str, Any]]:
        """Получить историю проверок (до 20 записей) с валидацией владельца."""
        with self._get_connection() as conn:
            # Проверка владельца
            owner = conn.execute("SELECT id FROM sites WHERE id = ? AND user_id = ?", (site_id, user_id)).fetchone()
            if not owner:
                return []

            rows = conn.execute("""
                SELECT id, site_id, checked_at, is_success, status_code, response_time_ms, error_message
                FROM check_history
                WHERE site_id = ?
                ORDER BY checked_at DESC, id DESC
                LIMIT ?
            """, (site_id, min(limit, config.MAX_HISTORY_PER_URL))).fetchall()
            return [dict(r) for r in rows]
