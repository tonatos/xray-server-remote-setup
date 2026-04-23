"""
Fabric-задачи для деплоя xray-сервера.

Использование:
  fab deploy               — полный деплой (ключи, сертификаты, запуск стека)
  fab add-client --name=X  — добавить клиента и получить ссылки
  fab list-clients         — список клиентов с vless-ссылками
  fab status               — статус контейнеров
  fab logs [--lines=N]     — логи xray
  fab restart              — перезапуск xray

Конфигурация через .env (см. .env.example).
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import time
import urllib.parse
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from fabric import Connection, task

load_dotenv()

# ---------------------------------------------------------------------------
# Конфигурация из переменных окружения
# ---------------------------------------------------------------------------

SSH_HOST: str = os.environ.get("SSH_HOST", "")
SSH_USER: str = os.environ.get("SSH_USER", "root")
SSH_PASSWORD: str = os.environ.get("SSH_PASSWORD", "")
STACK_PATH: str = os.environ.get("STACK_PATH", "~/xray-server")
DOMAIN: str = os.environ.get("DOMAIN", "")
CERTBOT_EMAIL: str = os.environ.get("CERTBOT_EMAIL", "")

# True если DOMAIN явно присутствует в окружении (в т.ч. пустая строка).
# False если ключ не задан вообще — тогда домен унаследуем с сервера.
_DOMAIN_EXPLICITLY_SET: bool = "DOMAIN" in os.environ

LOCAL_DIR = Path(__file__).parent

# ---------------------------------------------------------------------------
# Утилиты подключения и загрузки файлов
# ---------------------------------------------------------------------------


def _conn() -> Connection:
    if not SSH_HOST:
        raise SystemExit(
            "SSH_HOST не задан. Укажи в .env или передай как переменную окружения."
        )
    connect_kwargs: dict = {}
    if SSH_PASSWORD:
        connect_kwargs["password"] = SSH_PASSWORD
    return Connection(host=SSH_HOST, user=SSH_USER, connect_kwargs=connect_kwargs)


def _upload_text(c: Connection, content: str, remote_path: str) -> None:
    """Загружает строковое содержимое в файл на удалённом сервере."""
    expanded = _expand_remote_path(c, remote_path)
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".tmp", delete=False, encoding="utf-8"
    ) as f:
        f.write(content)
        tmp = f.name
    try:
        c.put(tmp, remote=expanded)
    finally:
        os.unlink(tmp)


def _stack_project_name() -> str:
    """Имя проекта docker-compose (basename пути стека)."""
    return STACK_PATH.rstrip("/").split("/")[-1]


_remote_home_cache: dict[str, str] = {}


def _remote_home(c: Connection) -> str:
    """Кешированный домашний каталог удалённого пользователя."""
    key = f"{c.user}@{c.host}"
    if key not in _remote_home_cache:
        _remote_home_cache[key] = c.run("echo $HOME", hide=True).stdout.strip()
    return _remote_home_cache[key]


def _expand_remote_path(c: Connection, path: str) -> str:
    """Раскрывает ~ в пути (SFTP не понимает тильду, в отличие от shell)."""
    if path.startswith("~"):
        return path.replace("~", _remote_home(c), 1)
    return path


# ---------------------------------------------------------------------------
# Управление секретами xray
# ---------------------------------------------------------------------------

_SECRETS_FILE = ".xray-secrets"
_REQUIRED_SECRET_KEYS = ("XRAY_UUID", "XRAY_PRIVATE_KEY", "XRAY_PUBLIC_KEY", "XRAY_SHORT_ID")


def _parse_env_text(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            result[k.strip()] = v.strip()
    return result


def _load_secrets(c: Connection) -> Optional[dict[str, str]]:
    """Загружает секреты xray из файла .xray-secrets на сервере."""
    result = c.run(f"cat {STACK_PATH}/{_SECRETS_FILE}", warn=True, hide=True)
    if not result.ok:
        return None
    secrets = _parse_env_text(result.stdout)
    if all(secrets.get(k) for k in _REQUIRED_SECRET_KEYS):
        return secrets
    return None


def _save_secrets(c: Connection, secrets: dict[str, str]) -> None:
    content = "\n".join(f"{k}={v}" for k, v in secrets.items()) + "\n"
    _upload_text(c, content, f"{STACK_PATH}/{_SECRETS_FILE}")
    c.run(f"chmod 600 {STACK_PATH}/{_SECRETS_FILE}")


def _generate_secrets(c: Connection) -> dict[str, str]:
    """Генерирует UUID, x25519 keypair и short_id через xray в Docker."""
    print("    Генерация UUID...")
    uuid_out = c.run(
        "docker run --rm --entrypoint xray ghcr.io/xtls/xray-core:latest uuid",
        hide=True,
    ).stdout
    uuid_m = re.search(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        uuid_out,
        re.I,
    )
    if not uuid_m:
        raise RuntimeError(f"Не удалось извлечь UUID из: {uuid_out!r}")
    uuid = uuid_m.group(0)

    print("    Генерация x25519 keypair (Reality)...")
    kp_out = c.run(
        "docker run --rm --entrypoint xray ghcr.io/xtls/xray-core:latest x25519",
        hide=True,
    ).stdout
    priv_m = re.search(r"Private key:\s*(\S+)", kp_out)
    pub_m = re.search(r"Public key:\s*(\S+)", kp_out)
    if not priv_m or not pub_m:
        raise RuntimeError(f"Не удалось распарсить keypair: {kp_out!r}")

    print("    Генерация short_id...")
    short_id = c.run("openssl rand -hex 8", hide=True).stdout.strip()

    return {
        "XRAY_UUID": uuid,
        "XRAY_PRIVATE_KEY": priv_m.group(1),
        "XRAY_PUBLIC_KEY": pub_m.group(1),
        "XRAY_SHORT_ID": short_id,
    }


def _derive_public_key(c: Connection, private_key: str) -> str:
    """Вычисляет публичный ключ из приватного через xray x25519 -i.

    Xray выводит: "Password (PublicKey): <key>" или "Public key: <key>".
    """
    out = c.run(
        f"docker run --rm --entrypoint xray ghcr.io/xtls/xray-core:latest x25519 -i {private_key}",
        hide=True,
        warn=True,
    ).stdout
    m = re.search(r"(?:Public key|Password \(PublicKey\)):\s*(\S+)", out)
    return m.group(1) if m else ""


def _extract_secrets_from_config(
    c: Connection, config: dict
) -> Optional[dict[str, str]]:
    """Извлекает секреты из уже заполненного config.json на сервере."""
    try:
        reality = next(
            ib for ib in config["inbounds"] if ib.get("tag") == "vless-reality"
        )
        uuid = reality["settings"]["clients"][0]["id"]
        private_key = reality["streamSettings"]["realitySettings"]["privateKey"]
        short_id = reality["streamSettings"]["realitySettings"]["shortIds"][0]
    except (KeyError, StopIteration, IndexError):
        return None

    print("    Вычисляем публичный ключ из приватного...")
    public_key = _derive_public_key(c, private_key)

    return {
        "XRAY_UUID": uuid,
        "XRAY_PRIVATE_KEY": private_key,
        "XRAY_PUBLIC_KEY": public_key,
        "XRAY_SHORT_ID": short_id,
    }


def _get_or_create_secrets(c: Connection) -> dict[str, str]:
    """Возвращает существующие секреты или генерирует новые."""
    secrets = _load_secrets(c)
    if secrets:
        print("  Секреты найдены на сервере, пропускаем генерацию.")
        return secrets

    # Попытка извлечь из уже существующего конфига на сервере
    cfg_result = c.run(f"cat {STACK_PATH}/config.json", warn=True, hide=True)
    if cfg_result.ok and "YOUR_UUID" not in cfg_result.stdout:
        print("  Извлекаем секреты из существующего config.json на сервере...")
        try:
            cfg = json.loads(cfg_result.stdout)
            secrets = _extract_secrets_from_config(c, cfg)
            if secrets:
                _save_secrets(c, secrets)
                return secrets
        except json.JSONDecodeError:
            pass

    print("  Генерируем новые секреты xray...")
    secrets = _generate_secrets(c)
    _save_secrets(c, secrets)
    return secrets


# ---------------------------------------------------------------------------
# Конфигурация xray
# ---------------------------------------------------------------------------


def _get_server_config(c: Connection) -> Optional[dict]:
    """Читает текущий config.json с сервера (если он уже заполнен)."""
    result = c.run(f"cat {STACK_PATH}/config.json", warn=True, hide=True)
    if result.ok and "YOUR_UUID" not in result.stdout:
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            pass
    return None


def _get_server_clients(server_config: dict) -> dict[str, list]:
    """Возвращает словарь inbound_tag → список клиентов из серверного конфига."""
    return {
        ib["tag"]: ib["settings"]["clients"]
        for ib in server_config.get("inbounds", [])
        if "settings" in ib and "clients" in ib.get("settings", {})
    }


def _get_server_domain(server_config: dict) -> str:
    """Извлекает домен из TLS-инбаунда серверного конфига."""
    for ib in server_config.get("inbounds", []):
        if ib.get("tag") == "vless-xhttp-tls":
            try:
                cert = ib["streamSettings"]["tlsSettings"]["certificates"][0]
                m = re.search(r"/live/([^/]+)/fullchain\.pem", cert["certificateFile"])
                if m:
                    return m.group(1)
            except (KeyError, IndexError):
                pass
    return ""


def _build_config(
    secrets: dict[str, str],
    domain: str,
    server_clients: Optional[dict[str, list]] = None,
) -> dict:
    """
    Собирает конфиг xray из шаблона (config.json):
    - подставляет секреты и домен
    - удаляет TLS-инбаунд если домен не задан
    - сохраняет клиентов с сервера (чтобы не перетирать при повторном деплое)
    """
    text = (LOCAL_DIR / "config.json").read_text(encoding="utf-8")
    text = text.replace("YOUR_UUID", secrets["XRAY_UUID"])
    text = text.replace("YOUR_PRIVATE_KEY", secrets["XRAY_PRIVATE_KEY"])
    text = text.replace("YOUR_SHORT_ID", secrets["XRAY_SHORT_ID"])
    if domain:
        text = text.replace("YOUR_DOMAIN", domain)

    config = json.loads(text)

    if not domain:
        config["inbounds"] = [
            ib for ib in config["inbounds"] if ib.get("tag") != "vless-xhttp-tls"
        ]

    # Восстанавливаем клиентов с сервера, если их больше чем в шаблоне
    if server_clients:
        for inbound in config["inbounds"]:
            tag = inbound.get("tag")
            if tag in server_clients and len(server_clients[tag]) > len(
                inbound["settings"]["clients"]
            ):
                inbound["settings"]["clients"] = server_clients[tag]

    return config


# ---------------------------------------------------------------------------
# Загрузка файлов на сервер
# ---------------------------------------------------------------------------


def _upload_files(c: Connection, config: dict, domain: str) -> None:
    c.run(f"mkdir -p {STACK_PATH}")

    _upload_text(c, json.dumps(config, ensure_ascii=False, indent=2), f"{STACK_PATH}/config.json")
    print("  ✓ config.json")

    c.put(
        str(LOCAL_DIR / "docker-compose.yml"),
        remote=_expand_remote_path(c, f"{STACK_PATH}/docker-compose.yml"),
    )
    print("  ✓ docker-compose.yml")

    if domain:
        nginx_conf = (LOCAL_DIR / "nginx-acme.conf").read_text(encoding="utf-8")
        nginx_conf = nginx_conf.replace("YOUR_DOMAIN", domain)
        _upload_text(c, nginx_conf, f"{STACK_PATH}/nginx-acme.conf")
        print("  ✓ nginx-acme.conf")


# ---------------------------------------------------------------------------
# Docker
# ---------------------------------------------------------------------------


def _ensure_docker(c: Connection) -> None:
    result = c.run("docker --version", warn=True, hide=True)
    if result.ok:
        print(f"  Docker найден: {result.stdout.strip()}")
        return
    print("  Docker не найден, устанавливаем...")
    c.run("curl -fsSL https://get.docker.com | sh")
    print("  ✓ Docker установлен.")


def _cert_exists(c: Connection, domain: str) -> bool:
    """Проверяет наличие сертификата в Docker-томе letsencrypt."""
    proj = _stack_project_name()
    vol_data = f"/var/lib/docker/volumes/{proj}_letsencrypt/_data"
    result = c.run(
        f"test -f {vol_data}/live/{domain}/fullchain.pem", warn=True, hide=True
    )
    return result.ok


def _setup_certbot(c: Connection, domain: str, email: str) -> None:
    """Запускает xray-acme-proxy и получает сертификат через certbot."""
    print(f"  Запускаем xray-acme-proxy...")
    c.run(f"cd {STACK_PATH} && docker compose --profile tls up -d xray-acme-proxy")
    time.sleep(4)

    print(f"  Запрашиваем сертификат для {domain}...")
    c.run(
        f"cd {STACK_PATH} && docker compose --profile tls run --rm "
        f"--entrypoint certbot certbot "
        f"certonly --webroot -w /var/www/certbot "
        f"-d {domain} "
        f"--email {email} "
        f"--agree-tos --no-eff-email --non-interactive"
    )
    print("  ✓ Сертификат получен.")


def _start_stack(c: Connection, domain: str) -> None:
    profile_arg = "--profile tls" if domain else ""
    # up -d запускает отсутствующие контейнеры, но не перезапускает уже запущенные.
    # Xray читает конфиг при старте, поэтому рестарт необходим после изменения config.json.
    c.run(f"cd {STACK_PATH} && docker compose {profile_arg} up -d")
    c.run(f"cd {STACK_PATH} && docker compose restart xray")


# ---------------------------------------------------------------------------
# Генерация vless-ссылок
# ---------------------------------------------------------------------------


def _vless_reality_link(
    uuid: str, host: str, public_key: str, short_id: str, name: str
) -> str:
    params = urllib.parse.urlencode(
        {
            "encryption": "none",
            "flow": "xtls-rprx-vision",
            "security": "reality",
            "sni": "www.microsoft.com",
            "fp": "chrome",
            "pbk": public_key,
            "sid": short_id,
            "type": "tcp",
        }
    )
    tag = urllib.parse.quote(f"{name}-Reality")
    return f"vless://{uuid}@{host}:443?{params}#{tag}"


def _vless_xhttp_link(uuid: str, host: str, domain: str, name: str) -> str:
    params = urllib.parse.urlencode(
        {
            "encryption": "none",
            "security": "tls",
            "sni": domain,
            "type": "xhttp",
            "path": "/xhttp",
        }
    )
    tag = urllib.parse.quote(f"{name}-xHTTP-TLS")
    return f"vless://{uuid}@{host}:8443?{params}#{tag}"


def _print_client_links(
    name: str,
    uuid: str,
    secrets: dict[str, str],
    host: str,
    domain: str,
) -> None:
    pub = secrets.get("XRAY_PUBLIC_KEY", "")
    sid = secrets.get("XRAY_SHORT_ID", "")

    if pub and sid:
        link = _vless_reality_link(uuid, host, pub, sid, name)
        print(f"  VLESS Reality:\n  {link}\n")

    if domain:
        link = _vless_xhttp_link(uuid, host, domain, name)
        print(f"  VLESS xHTTP+TLS:\n  {link}\n")


# ---------------------------------------------------------------------------
# Fabric-задачи
# ---------------------------------------------------------------------------


@task
def deploy(ctx):
    """Полный деплой xray-сервера.

    1. Проверяет/устанавливает Docker
    2. Генерирует секреты xray (UUID, ключи Reality) — только если не существуют
    3. Собирает и загружает config.json + docker-compose.yml
    4. Получает TLS-сертификат (если задан DOMAIN) — только если не существует
    5. Запускает docker-compose стек
    """
    c = _conn()
    print(f"\n[deploy] {SSH_USER}@{SSH_HOST}  стек: {STACK_PATH}\n")

    c.run(f"mkdir -p {STACK_PATH}")

    print("[1/5] Проверяем Docker...")
    _ensure_docker(c)

    print("[2/5] Секреты xray...")
    secrets = _get_or_create_secrets(c)

    print("[3/5] Сборка и загрузка файлов...")
    server_cfg = _get_server_config(c)
    server_clients = _get_server_clients(server_cfg) if server_cfg else None
    # Если DOMAIN явно задан в окружении (даже пустой строкой) — используем его.
    # Иначе наследуем домен из уже развёрнутого конфига на сервере.
    if _DOMAIN_EXPLICITLY_SET:
        effective_domain = DOMAIN
    else:
        effective_domain = _get_server_domain(server_cfg) if server_cfg else ""
    config = _build_config(secrets, effective_domain, server_clients)
    _upload_files(c, config, effective_domain)

    if effective_domain:
        print(f"[4/5] TLS-сертификат для {effective_domain}...")
        if _cert_exists(c, effective_domain):
            print("  Сертификат уже существует, пропускаем.")
        else:
            if not CERTBOT_EMAIL:
                raise SystemExit(
                    "CERTBOT_EMAIL не задан в .env — обязателен для получения сертификата."
                )
            _setup_certbot(c, effective_domain, CERTBOT_EMAIL)
    else:
        print("[4/5] DOMAIN не задан — пропускаем certbot.")

    print("[5/5] Запуск стека...")
    _start_stack(c, effective_domain)

    print(f"\n✓ Деплой завершён!\n")
    print("=== Параметры Reality ===")
    print(f"  Хост:       {SSH_HOST}")
    if effective_domain:
        print(f"  Домен:      {effective_domain}")
    print(f"  Public key: {secrets.get('XRAY_PUBLIC_KEY', 'н/д')}")
    print(f"  Short ID:   {secrets.get('XRAY_SHORT_ID', 'н/д')}")
    print()


@task
def add_client(ctx, name, level=0):
    """Добавляет нового клиента в xray и печатает vless-ссылки.

    Параметры:
      --name    имя клиента (обязательно)
      --level   уровень политики, default=0 (влияет на таймауты и статистику,
                см. секцию policy в config.json)

    Использование:
      fab add-client --name=alice
      fab add-client --name=alice --level=1
    """
    c = _conn()

    secrets = _load_secrets(c)
    if not secrets:
        raise SystemExit("Секреты не найдены на сервере. Сначала выполни: fab deploy")

    cfg_result = c.run(f"cat {STACK_PATH}/config.json", hide=True)
    config = json.loads(cfg_result.stdout)

    # Проверяем, нет ли уже клиента с таким именем
    reality_ib = next(
        (ib for ib in config["inbounds"] if ib.get("tag") == "vless-reality"), None
    )
    if reality_ib:
        existing = [
            c for c in reality_ib["settings"]["clients"]
            if c.get("email", "").split("@")[0] == name
        ]
        if existing:
            raise SystemExit(
                f"Клиент '{name}' уже существует (UUID: {existing[0]['id']}). "
                f"Используй другое имя или запусти: fab list-clients"
            )

    # Генерируем UUID для нового клиента
    uuid_out = c.run(
        "docker run --rm --entrypoint xray ghcr.io/xtls/xray-core:latest uuid",
        hide=True,
    ).stdout
    uuid_m = re.search(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        uuid_out,
        re.I,
    )
    if not uuid_m:
        raise RuntimeError("Не удалось сгенерировать UUID для клиента.")
    client_uuid = uuid_m.group(0)
    client_level = int(level)

    for inbound in config["inbounds"]:
        tag = inbound.get("tag", "")
        clients: list = inbound["settings"]["clients"]
        if tag == "vless-reality":
            clients.append(
                {
                    "id": client_uuid,
                    "flow": "xtls-rprx-vision",
                    "email": f"{name}@reality",
                    "level": client_level,
                }
            )
        elif tag == "vless-xhttp-tls":
            clients.append(
                {
                    "id": client_uuid,
                    "email": f"{name}@xhttp-tls",
                    "level": client_level,
                }
            )

    _upload_text(
        c,
        json.dumps(config, ensure_ascii=False, indent=2),
        f"{STACK_PATH}/config.json",
    )
    c.run(f"cd {STACK_PATH} && docker compose restart xray")

    effective_domain = DOMAIN or _get_server_domain(config)
    print(f"\n✓ Клиент '{name}' добавлен  (UUID: {client_uuid}, level: {client_level})\n")
    _print_client_links(name, client_uuid, secrets, SSH_HOST, effective_domain)


@task
def list_clients(ctx):
    """Выводит список всех клиентов с vless-ссылками для подключения."""
    c = _conn()

    secrets = _load_secrets(c)
    if not secrets:
        raise SystemExit("Секреты не найдены на сервере. Сначала выполни: fab deploy")

    cfg_result = c.run(f"cat {STACK_PATH}/config.json", hide=True)
    config = json.loads(cfg_result.stdout)

    reality_inbound = next(
        (ib for ib in config["inbounds"] if ib.get("tag") == "vless-reality"),
        None,
    )
    if not reality_inbound:
        print("vless-reality инбаунд не найден в конфиге сервера.")
        return

    effective_domain = DOMAIN or _get_server_domain(config)
    clients = reality_inbound["settings"]["clients"]
    policy_levels = config.get("policy", {}).get("levels", {})

    print(f"\nКлиентов: {len(clients)}\n")
    for client in clients:
        email = client.get("email", client["id"])
        name = email.split("@")[0]
        lv = client.get("level", 0)
        lv_info = ""
        if str(lv) in policy_levels:
            p = policy_levels[str(lv)]
            parts = []
            if "connIdle" in p:
                parts.append(f"idle={p['connIdle']}s")
            if "bufferSize" in p:
                parts.append(f"buf={p['bufferSize']}KB")
            lv_info = f"  policy[{lv}]: {', '.join(parts)}" if parts else f"  level={lv}"
        else:
            lv_info = f"  level={lv}"
        print(f"── {name}  ({client['id']}){lv_info}")
        _print_client_links(name, client["id"], secrets, SSH_HOST, effective_domain)


@task
def status(ctx):
    """Показывает статус контейнеров на сервере."""
    c = _conn()
    c.run(f"cd {STACK_PATH} && docker compose ps")


@task
def logs(ctx, lines=50):
    """Показывает последние логи xray-контейнера.

    Использование:
      fab logs
      fab logs --lines=100
    """
    c = _conn()
    c.run(f"cd {STACK_PATH} && docker compose logs --tail={lines} xray")


@task
def restart(ctx):
    """Перезапускает xray-контейнер."""
    c = _conn()
    c.run(f"cd {STACK_PATH} && docker compose restart xray")
    print("✓ xray перезапущен.")
