# 🛡️ V1PER IT Solutions | Telegram Uptime Monitor & Mini App Platform

[![Tests](https://img.shields.io/badge/Tests-9%2F9%20Passed%20(100%25)-brightgreen.svg)](tests/)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Studio](https://img.shields.io/badge/Studio-V1PER_IT_Solutions-emerald.svg)](https://github.com/viper86rus-arch)
[![Architecture: Clean Zero--Pip](https://img.shields.io/badge/Architecture-Clean%20Zero--Pip-blueviolet.svg)]()
[![Platform: Telegram TMA 2026](https://img.shields.io/badge/Telegram-Mini_Apps_v7-229ED9.svg)](https://core.telegram.org/bots/webapps)
[![Security: SSRF Protected](https://img.shields.io/badge/Security-SSRF%20Guard%20RFC1918-red.svg)](security.py)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **Автономный промышленный сервис мониторинга доступности веб-ресурсов студии V1PER IT Solutions с нативным интерфейсом Telegram Mini App (TMA).**  
> Круглосуточный фоновый контроль сайтов каждые 5 минут, замер времени отклика (latency), строгая защита от SSRF (отсечение локальных и приватных сетей), серверная аутентификация по HMAC-SHA256, хранение последних 20 проверок и умная стейт-машина алертов (уведомление строго после 2 сбоев подряд и при восстановлении).

> [!IMPORTANT]
> **🚀 Разработка и внедрение систем мониторинга серверов и ботов под ключ:**  
> Студия **V1PER IT Solutions** выполняет индивидуальную разработку и развертывание инфраструктурных сервисов мониторинга, Telegram Mini Apps и отказоустойчивых бот-платформ под ключ:
> 📩 **Заказать разработку:** [Заказать на Kwork (Безопасная сделка)](https://kwork.ru/user/V1PER86RUS) • [Создать заявку (Issue)](https://github.com/viper86rus-arch/Telegram_Uptime_Monitor/issues) • [Профиль студии](https://github.com/viper86rus-arch)

---

## 📋 Архитектурный поток системы (Mermaid)

```mermaid
flowchart TD
    USR["📱 Пользователь в Telegram"] -->|1. Запуск /start| BOT["🤖 Telegram Bot (@ITStudio_dev_bot)"]
    BOT -->|2. Кнопка WebApp| TMA["📊 Telegram Mini App (TMA Client)"]
    
    subgraph Client ["Клиентский интерфейс (Telegram Mini App)"]
        TMA -->|GET /api/sites| VIEW["Список ресурсов (до 5 URL)"]
        TMA -->|POST /api/sites| ADD["Добавление URL с валидацией"]
        TMA -->|GET /api/sites/:id/history| HIST["История последних 20 проверок"]
        TMA -->|DELETE /api/sites/:id| DEL["Удаление ресурса"]
    end
    
    subgraph Server ["Серверная экосистема (Python Standard Library)"]
        SRV["🌐 REST API Сервер (server.py)"]
        SSRF["🛡️ SSRF Guard (security.py)"]
        AUTH["🔐 Telegram HMAC-SHA256 Auth"]
        DB[("💾 SQLite Хранилище (uptime_monitor.db)")]:::db
        WORKER["⏱️ Фоновый воркер проверок (monitor.py)"]
    end
    
    ADD -->|3. Авторизация tma initData| AUTH
    ADD -->|4. DNS + IP валидация| SSRF
    SSRF -->|5. Запись в базу (макс 5 URL)| DB
    
    WORKER -->|6. Каждые 5 минут| PING["🌐 Пинг сайтов (HTTP/HTTPS)"]
    PING -->|7. Замер Latency & Код ответа| DB
    
    WORKER -->|8. Зафиксировано 2 сбоя подряд| ALERT["🔴 Push-алерт о сбое"]
    WORKER -->|9. Успешный ответ после сбоя| RECOV["🟢 Push-алерт о восстановлении"]
    
    ALERT --> BOT
    RECOV --> BOT
    BOT -->|10. Доставка в личку| USR

    classDef db fill:#0d1117,stroke:#58a6ff,stroke-width:2px,color:#fff;
```

---

## 🌟 Ключевые возможности и соответствие ТЗ

1. **Telegram Mini App (TMA)**:
   * Нативный интерфейс под системную тему Telegram (тёмная/светлая тема, CSS variables).
   * Мгновенный отклик, виброотклик (Haptic Feedback) на мобильных устройствах.
   * Список отслеживаемых ресурсов, цветные индикаторы статуса (`UP`, `DOWN`, `PENDING`), замер задержки ответа (мс).

2. **Строгая защита от SSRF (Server-Side Request Forgery)**:
   * Предварительный DNS-резолв каждого добавляемого домена.
   * Блокировка всех локальных, петлевых (loopback), link-local и служебных IP-адресов по стандартам RFC 1918 и RFC 3927 (`127.0.0.1`, `localhost`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.169.254`, `0.0.0.0`, `::1`).
   * Защита от перенаправления (redirect attacks) на внутренние ресурсы инфраструктуры.

3. **Стейт-машина алертов (Анти-спам по ТЗ)**:
   * Одиночный случайный сбой не вызывает тревоги.
   * Уведомление в Telegram отправляется **строго после двух подряд неуспешных проверок**.
   * Последующие сбои (3, 4, 5...) не спамят пользователя.
   * При первой же успешной проверке после аварии бот присылает сообщение о восстановлении работы.

4. **Лимиты и изоляция данных**:
   * Максимум 5 URL на одного пользователя.
   * Полная изоляция арендаторов: пользователь видит и управляет только своими сайтами.
   * Автоматическая ротация истории: хранятся строго последние 20 проверок на каждый URL.

5. **Clean Zero-Pip Architecture**:
   * Построено исключительно на возможностях стандартной библиотеки Python 3.10+ (`urllib.request`, `sqlite3`, `hashlib`, `hmac`, `asyncio`, `socket`, `ipaddress`).
   * Полная автономность: запуск без установки сторонних pip-пакетов.

---

## 🚀 Быстрый запуск

### 1. Клонирование и настройка окружения
```bash
git clone https://github.com/viper86rus-arch/Telegram_Uptime_Monitor.git
cd Telegram_Uptime_Monitor
cp .env.example .env
```

В файле `.env` укажите ваш Telegram-токен от `@BotFather`:
```env
TELEGRAM_BOT_TOKEN=123456789:ABCdefGHIjklMNOpqrSTUvwxYZ
SERVER_HOST=0.0.0.0
SERVER_PORT=8000
WEBAPP_URL=https://your-domain.com
CHECK_INTERVAL_SECONDS=300
```

### 2. Запуск сервиса
```bash
python3 main.py
```

### 3. Запуск модульных тестов
```bash
python3 -m unittest discover -s tests -v
```

---

## 📡 REST API Спецификация

| Метод | Эндпоинт | Описание |
| :--- | :--- | :--- |
| `GET` | `/health` | Проверка здоровья сервиса |
| `GET` | `/api/me` | Данные текущего пользователя и занятость лимита |
| `GET` | `/api/sites` | Список сайтов пользователя со статусами |
| `POST` | `/api/sites` | Добавление сайта с проверкой SSRF и лимита 5 URL |
| `DELETE` | `/api/sites/{id}` | Удаление сайта и его истории |
| `GET` | `/api/sites/{id}/history` | История последних 20 проверок |
| `POST` | `/api/sites/{id}/check` | Ручной внеочередной пинг ресурса |

---

## 📄 Лицензия и авторство

* **Автор разработки:** V1PER ([`viper86rus-arch`](https://github.com/viper86rus-arch))
* **Лицензия:** [MIT License](LICENSE) (2026) — открытый исходный код без ограничений на коммерческое и образовательное применение.
