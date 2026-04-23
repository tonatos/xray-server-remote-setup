# xray-server

Автоматизированный деплой [Xray-core](https://github.com/XTLS/Xray-core) на удалённый VPS через [Fabric](https://www.fabfile.org/).

Поддерживаемые протоколы:
- **VLESS + XTLS-Reality** (порт 443) — работает без домена
- **VLESS + xHTTP + TLS** (порт 8443) — требует домен с Let's Encrypt-сертификатом

---

## Требования

**Локально:**
- Python 3.11+
- [Poetry](https://python-poetry.org/docs/#installation)
- SSH-доступ к серверу по публичному ключу

**На сервере:**
- Ubuntu/Debian (или другой Linux)
- Docker (устанавливается автоматически при первом деплое)

---

## Быстрый старт

### 1. Установить зависимости

```bash
poetry install
```

### 2. Настроить переменные окружения

```bash
cp .env.example .env
```

Отредактировать `.env`:

```env
SSH_HOST=your-server-ip
SSH_USER=root
STACK_PATH=~/xray-server

# Домен опционален. Без него работает только Reality.
DOMAIN=your-domain.com
CERTBOT_EMAIL=your@email.com
```

### 3. Задеплоить

```bash
poetry run fab deploy
```

Команда выполнит:
1. Проверку/установку Docker на сервере
2. Генерацию секретов xray (UUID, ключи Reality) — **только если не существуют**
3. Сборку `config.json` из шаблона и загрузку файлов
4. Получение TLS-сертификата через certbot — **только если не существует**
5. Запуск docker-compose стека

После успешного деплоя в выводе будут показаны параметры для подключения (Public key, Short ID).

---

## Команды

| Команда | Описание |
|---|---|
| `poetry run fab deploy` | Полный деплой / идемпотентное переразвёртывание |
| `poetry run fab add-client --name=alice` | Добавить клиента и получить ссылки |
| `poetry run fab list-clients` | Список всех клиентов с vless-ссылками |
| `poetry run fab status` | Статус контейнеров (`docker compose ps`) |
| `poetry run fab logs` | Последние 50 строк логов xray |
| `poetry run fab logs --lines=200` | Указать количество строк логов |
| `poetry run fab restart` | Перезапустить xray-контейнер |
| `poetry run fab --list` | Список всех доступных задач |

---

## Конфигурация

### Переменные окружения

| Переменная | Обязательна | По умолчанию | Описание |
|---|---|---|---|
| `SSH_HOST` | да | — | IP или hostname сервера |
| `SSH_USER` | нет | `root` | SSH-пользователь |
| `SSH_PASSWORD` | нет | — | SSH-пароль (если без ключа) |
| `STACK_PATH` | нет | `~/xray-server` | Путь к стеку на сервере |
| `DOMAIN` | нет | — | Домен для TLS (если не задан — только Reality) |
| `CERTBOT_EMAIL` | при DOMAIN | — | Email для Let's Encrypt |

### config.json

Файл `config.json` — шаблон конфигурации Xray. Он содержит плейсхолдеры, которые подставляются при деплое:

| Плейсхолдер | Что подставляется |
|---|---|
| `YOUR_UUID` | UUID клиента (генерируется один раз) |
| `YOUR_PRIVATE_KEY` | Приватный ключ Reality (x25519) |
| `YOUR_SHORT_ID` | Short ID для Reality |
| `YOUR_DOMAIN` | Домен из переменной `DOMAIN` |

Файл можно редактировать напрямую — при следующем `fab deploy` структурные изменения применятся, а список клиентов сохранится.

---

## Управление клиентами

### Добавить клиента

```bash
poetry run fab add-client --name=alice
poetry run fab add-client --name=bob --level=1   # другой уровень политики
```

Параметры:

| Параметр | По умолчанию | Описание |
|---|---|---|
| `--name` | обязателен | Имя клиента (используется как метка в логах) |
| `--level` | `0` | Уровень политики (см. ниже) |

Команда:
1. Проверяет, что клиент с таким именем не существует
2. Генерирует новый UUID для клиента
3. Добавляет клиента во все активные инбаунды с указанным уровнем
4. Перезапускает xray
5. Выводит готовые vless-ссылки

Пример вывода:
```
✓ Клиент 'alice' добавлен  (UUID: 3f2a1b4c-..., level: 0)

  VLESS Reality:
  vless://3f2a1b4c-...@1.2.3.4:443?encryption=none&flow=xtls-rprx-vision&...#alice-Reality

  VLESS xHTTP+TLS:
  vless://3f2a1b4c-...@1.2.3.4:8443?encryption=none&security=tls&...#alice-xHTTP-TLS
```

### Список клиентов

```bash
poetry run fab list-clients
```

### Настройки клиентов в xray-core

xray-core поддерживает следующие поля для каждого клиента VLESS:

| Поле | Описание |
|---|---|
| `id` | UUID (генерируется автоматически) |
| `email` | Метка в логах и статистике, формат `name@inbound` |
| `flow` | Управление потоком: `xtls-rprx-vision` для Reality, пусто для xHTTP |
| `level` | Уровень политики — привязывает клиента к настройкам из секции `policy` |

> **Ограничение:** xray-core не имеет встроенного per-client rate limiting (ограничения полосы пропускания). Для шейпинга трафика используются внешние инструменты — `tc` (traffic control) или `iptables`.

### Управление политиками через `level`

Уровень `level` — единственный способ разграничить клиентов в xray. Через секцию `policy` в `config.json` можно назначить разные настройки для разных уровней:

```json
"policy": {
  "levels": {
    "0": {
      "connIdle": 300,
      "handshake": 4,
      "uplinkOnly": 2,
      "downlinkOnly": 5,
      "bufferSize": 512,
      "statsUserUplink": false,
      "statsUserDownlink": false,
      "statsUserOnline": false
    },
    "1": {
      "connIdle": 600,
      "bufferSize": 4096,
      "statsUserUplink": true,
      "statsUserDownlink": true,
      "statsUserOnline": true
    }
  }
}
```

| Параметр политики | Описание |
|---|---|
| `connIdle` | Таймаут простоя соединения (сек, default 300) |
| `handshake` | Таймаут рукопожатия (сек, default 4) |
| `uplinkOnly` | Ожидание после закрытия downlink (сек, default 2) |
| `downlinkOnly` | Ожидание после закрытия uplink (сек, default 5) |
| `bufferSize` | Размер буфера на соединение (KB, default 512) — косвенно влияет на пропускную способность |
| `statsUserUplink` | Учёт исходящего трафика клиентов уровня |
| `statsUserDownlink` | Учёт входящего трафика клиентов уровня |
| `statsUserOnline` | Учёт онлайн-статуса (активность за 20 сек) |

После добавления `policy` в `config.json` — запусти `fab deploy`, чтобы применить изменения.

---

## Структура проекта

```
xray-server/
├── fabfile.py          # Fabric-задачи (деплой, управление клиентами)
├── pyproject.toml      # Python-зависимости (Poetry)
├── config.json         # Шаблон конфигурации xray (редактируется)
├── docker-compose.yml  # Стек: xray + certbot + nginx (ACME)
├── nginx-acme.conf     # Nginx для ACME challenge
├── .env                # Локальные переменные окружения (git-ignored)
├── .env.example        # Шаблон .env
└── init-keys.sh        # Ручная генерация ключей (для справки)
```

---

## Архитектура стека

```
[клиент]
    │
    ├─ 443/TCP ──→ [xray: VLESS Reality]
    │               └─ маскировка под www.microsoft.com
    │
    └─ 8443/TCP ─→ [xray: VLESS xHTTP+TLS]  ← только при наличии домена
                    └─ TLS-сертификат от Let's Encrypt

[certbot] ─ автообновление сертификата каждые 12ч
[nginx]   ─ отдаёт ACME challenge на порту 80
```

Docker-профили:
- `docker compose up -d` — только `xray` (без домена)
- `docker compose --profile tls up -d` — `xray` + `certbot` + `nginx` (с доменом)

---

## Секреты и безопасность

- Секреты xray (UUID, ключи) хранятся на сервере в `STACK_PATH/.xray-secrets` (chmod 600)
- При повторном деплое секреты **не перегенерируются**
- Файл `.env` добавлен в `.gitignore` и не попадает в репозиторий
- Аутентификация SSH — по системному публичному ключу (без необходимости указывать SSH_PASSWORD)

---

## Ручные операции

### Проверить конфиг xray

```bash
ssh root@your-server "docker exec xray xray run -test -config /etc/xray/config.json"
```

### Выпустить сертификат вручную

```bash
ssh root@your-server "cd ~/xray-server && \
  docker compose --profile tls run --rm --entrypoint certbot certbot \
  certonly --webroot -w /var/www/certbot \
  -d your-domain.com \
  --email your@email.com \
  --agree-tos --no-eff-email --non-interactive"
```

### Посмотреть список сертификатов

```bash
ssh root@your-server "cd ~/xray-server && \
  docker compose --profile tls run --rm certbot certificates"
```
