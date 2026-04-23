"""
Fabric-задачи для деплоя xray-сервера.

Использование:
  fab deploy                          — деплой на все серверы
  fab deploy --host=IP                — деплой на конкретный сервер
  fab add-client --name=X             — добавить клиента на все серверы
  fab add-client --name=X --host=IP   — добавить клиента на конкретный сервер
  fab list-clients [--host=IP]        — список клиентов с vless-ссылками
  fab status [--host=IP]              — статус контейнеров
  fab logs [--host=IP] [--lines=N]    — логи xray
  fab restart [--host=IP]             — перезапуск xray

При нескольких серверах list-clients / status / logs / restart
требуют явного --host=IP.

Конфигурация через .env (см. .env.example).
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import time
import urllib.parse
import uuid as _uuid_mod
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from fabric import Connection, task

load_dotenv()

# ---------------------------------------------------------------------------
# Глобальные настройки
# ---------------------------------------------------------------------------

_STACK_PATH_DEFAULT: str = os.environ.get("STACK_PATH", "~/xray-server")
CERTBOT_EMAIL: str = os.environ.get("CERTBOT_EMAIL", "")

LOCAL_DIR = Path(__file__).parent


# ---------------------------------------------------------------------------
# Модель сервера
# ---------------------------------------------------------------------------


@dataclass
class ServerConfig:
    """Конфигурация одного сервера."""

    host: str
    user: str = "root"
    password: str = ""
    domain: Optional[str] = None  # None = унаследовать домен с сервера
    stack_path: str = ""          # пусто = _STACK_PATH_DEFAULT

    @property
    def effective_stack_path(self) -> str:
        return self.stack_path or _STACK_PATH_DEFAULT

    def label(self) -> str:
        domain_part = f"  domain={self.domain}" if self.domain else ""
        return f"{self.user}@{self.host}{domain_part}"


# ---------------------------------------------------------------------------
# Загрузка и выбор серверов
# ---------------------------------------------------------------------------


def _load_servers() -> list[ServerConfig]:
    """Загружает список серверов из переменной SERVERS (JSON-массив)."""
    raw = os.environ.get("SERVERS", "").strip()
    if not raw:
        raise SystemExit(
            "Переменная SERVERS не задана.\n"
            "Заполни .env (см. .env.example)."
        )
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise SystemExit(f"SERVERS: неверный JSON — {e}")
    if not isinstance(data, list) or not data:
        raise SystemExit("SERVERS должен быть непустым JSON-массивом: [{...}, ...]")
    servers: list[ServerConfig] = []
    for i, s in enumerate(data):
        if "host" not in s:
            raise SystemExit(f"SERVERS[{i}]: обязательное поле 'host' отсутствует")
        servers.append(
            ServerConfig(
                host=s["host"],
                user=s.get("user", "root"),
                password=s.get("password", ""),
                domain=s.get("domain"),  # None если ключ отсутствует
                stack_path=s.get("stack_path", ""),
            )
        )
    return servers


def _get_servers(host: Optional[str] = None) -> list[ServerConfig]:
    """Возвращает все серверы или конкретный по host."""
    servers = _load_servers()
    if host:
        matched = [s for s in servers if s.host == host]
        if not matched:
            available = ", ".join(s.host for s in servers)
            raise SystemExit(f"Сервер '{host}' не найден. Доступные: {available}")
        return matched
    return servers


def _get_single_server(host: Optional[str] = None) -> ServerConfig:
    """Возвращает один сервер. При нескольких серверах требует явного --host."""
    servers = _load_servers()
    if host:
        matched = [s for s in servers if s.host == host]
        if not matched:
            available = ", ".join(s.host for s in servers)
            raise SystemExit(f"Сервер '{host}' не найден. Доступные: {available}")
        return matched[0]
    if len(servers) == 1:
        return servers[0]
    options = "\n  ".join(f"--host={s.host}" for s in servers)
    raise SystemExit(
        f"Несколько серверов ({len(servers)}). Укажи конкретный:\n  {options}"
    )


# ---------------------------------------------------------------------------
# Соединение и утилиты
# ---------------------------------------------------------------------------


def _conn(server: ServerConfig) -> Connection:
    connect_kwargs: dict = {}
    if server.password:
        connect_kwargs["password"] = server.password
    return Connection(
        host=server.host,
        user=server.user,
        connect_kwargs=connect_kwargs,
    )


def _upload_text(c: Connection, content: str, remote_path: str) -> None:
    """Загружает строку в файл на удалённом сервере (обрабатывает ~ в пути)."""
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


_remote_home_cache: dict[str, str] = {}


def _remote_home(c: Connection) -> str:
    """Кешированный домашний каталог удалённого пользователя."""
    key = f"{c.user}@{c.host}"
    if key not in _remote_home_cache:
        _remote_home_cache[key] = c.run("echo $HOME", hide=True).stdout.strip()
    return _remote_home_cache[key]


def _expand_remote_path(c: Connection, path: str) -> str:
    """Раскрывает ~ в пути (SFTP не понимает тильду)."""
    if path.startswith("~"):
        return path.replace("~", _remote_home(c), 1)
    return path


def _stack_project_name(stack_path: str) -> str:
    """Имя проекта docker-compose (basename пути стека)."""
    return stack_path.rstrip("/").split("/")[-1]


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


def _load_secrets(c: Connection, stack_path: str) -> Optional[dict[str, str]]:
    result = c.run(f"cat {stack_path}/{_SECRETS_FILE}", warn=True, hide=True)
    if not result.ok:
        return None
    secrets = _parse_env_text(result.stdout)
    if all(secrets.get(k) for k in _REQUIRED_SECRET_KEYS):
        return secrets
    return None


def _save_secrets(c: Connection, stack_path: str, secrets: dict[str, str]) -> None:
    content = "\n".join(f"{k}={v}" for k, v in secrets.items()) + "\n"
    _upload_text(c, content, f"{stack_path}/{_SECRETS_FILE}")
    c.run(f"chmod 600 {stack_path}/{_SECRETS_FILE}")


def _generate_secrets(c: Connection) -> dict[str, str]:
    """Генерирует UUID, x25519 keypair и short_id через xray в Docker."""
    print("    Генерация UUID...")
    uuid = str(_uuid_mod.uuid4())

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
    """Вычисляет публичный ключ из приватного через xray x25519 -i."""
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


def _get_or_create_secrets(c: Connection, stack_path: str) -> dict[str, str]:
    """Возвращает существующие секреты или генерирует новые."""
    secrets = _load_secrets(c, stack_path)
    if secrets:
        print("  Секреты найдены на сервере, пропускаем генерацию.")
        return secrets

    cfg_result = c.run(f"cat {stack_path}/config.json", warn=True, hide=True)
    if cfg_result.ok and "YOUR_UUID" not in cfg_result.stdout:
        print("  Извлекаем секреты из существующего config.json на сервере...")
        try:
            cfg = json.loads(cfg_result.stdout)
            secrets = _extract_secrets_from_config(c, cfg)
            if secrets:
                _save_secrets(c, stack_path, secrets)
                return secrets
        except json.JSONDecodeError:
            pass

    print("  Генерируем новые секреты xray...")
    secrets = _generate_secrets(c)
    _save_secrets(c, stack_path, secrets)
    return secrets


# ---------------------------------------------------------------------------
# Конфигурация xray
# ---------------------------------------------------------------------------


def _get_server_config(c: Connection, stack_path: str) -> Optional[dict]:
    """Читает текущий config.json с сервера (если он заполнен)."""
    result = c.run(f"cat {stack_path}/config.json", warn=True, hide=True)
    if result.ok and "YOUR_UUID" not in result.stdout:
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            pass
    return None


def _get_server_clients(server_config: dict) -> dict[str, list]:
    """Возвращает inbound_tag → список клиентов из серверного конфига."""
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
    """Собирает конфиг xray из шаблона: подставляет секреты, домен, сохраняет клиентов."""
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

    # Восстанавливаем клиентов с сервера (чтобы не потерять при re-deploy)
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


def _upload_files(c: Connection, config: dict, domain: str, stack_path: str) -> None:
    c.run(f"mkdir -p {stack_path}")

    _upload_text(
        c, json.dumps(config, ensure_ascii=False, indent=2), f"{stack_path}/config.json"
    )
    print("  ✓ config.json")

    c.put(
        str(LOCAL_DIR / "docker-compose.yml"),
        remote=_expand_remote_path(c, f"{stack_path}/docker-compose.yml"),
    )
    print("  ✓ docker-compose.yml")

    if domain:
        nginx_conf = (LOCAL_DIR / "nginx-acme.conf").read_text(encoding="utf-8")
        nginx_conf = nginx_conf.replace("YOUR_DOMAIN", domain)
        _upload_text(c, nginx_conf, f"{stack_path}/nginx-acme.conf")
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


def _cert_exists(c: Connection, domain: str, stack_path: str) -> bool:
    """Проверяет наличие сертификата в Docker-томе letsencrypt."""
    proj = _stack_project_name(stack_path)
    vol_data = f"/var/lib/docker/volumes/{proj}_letsencrypt/_data"
    result = c.run(
        f"test -f {vol_data}/live/{domain}/fullchain.pem", warn=True, hide=True
    )
    return result.ok


def _setup_certbot(c: Connection, domain: str, email: str, stack_path: str) -> None:
    """Получает Let's Encrypt сертификат через certbot."""
    print(f"  Запускаем xray-acme-proxy...")
    c.run(f"cd {stack_path} && docker compose --profile tls up -d xray-acme-proxy")
    time.sleep(4)

    print(f"  Запрашиваем сертификат для {domain}...")
    c.run(
        f"cd {stack_path} && docker compose --profile tls run --rm "
        f"--entrypoint certbot certbot "
        f"certonly --webroot -w /var/www/certbot "
        f"-d {domain} "
        f"--email {email} "
        f"--agree-tos --no-eff-email --non-interactive"
    )
    print("  ✓ Сертификат получен.")


def _start_stack(c: Connection, domain: str, stack_path: str) -> None:
    profile_arg = "--profile tls" if domain else ""
    c.run(f"cd {stack_path} && docker compose {profile_arg} up -d")
    c.run(f"cd {stack_path} && docker compose restart xray")


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
# Операции над одним сервером (внутренние)
# ---------------------------------------------------------------------------


def _deploy_server(server: ServerConfig) -> None:
    """Полный деплой на один сервер."""
    c = _conn(server)
    sp = server.effective_stack_path

    c.run(f"mkdir -p {sp}")

    print("[1/5] Проверяем Docker...")
    _ensure_docker(c)

    print("[2/5] Секреты xray...")
    secrets = _get_or_create_secrets(c, sp)

    print("[3/5] Сборка и загрузка файлов...")
    server_cfg = _get_server_config(c, sp)
    server_clients = _get_server_clients(server_cfg) if server_cfg else None

    # Effective domain: явный из конфига сервера, или унаследованный с уже задеплоенного
    if server.domain is not None:
        effective_domain = server.domain
    else:
        effective_domain = _get_server_domain(server_cfg) if server_cfg else ""

    config = _build_config(secrets, effective_domain, server_clients)
    _upload_files(c, config, effective_domain, sp)

    if effective_domain:
        print(f"[4/5] TLS-сертификат для {effective_domain}...")
        if _cert_exists(c, effective_domain, sp):
            print("  Сертификат уже существует, пропускаем.")
        else:
            if not CERTBOT_EMAIL:
                raise SystemExit("CERTBOT_EMAIL не задан в .env")
            _setup_certbot(c, effective_domain, CERTBOT_EMAIL, sp)
    else:
        print("[4/5] DOMAIN не задан — пропускаем certbot.")

    print("[5/5] Запуск стека...")
    _start_stack(c, effective_domain, sp)

    print(f"\n✓ Деплой завершён!")
    print("=== Параметры Reality ===")
    if effective_domain:
        print(f"  Домен:      {effective_domain}")
    print(f"  Public key: {secrets.get('XRAY_PUBLIC_KEY', 'н/д')}")
    print(f"  Short ID:   {secrets.get('XRAY_SHORT_ID', 'н/д')}")


def _add_client_to_server(
    server: ServerConfig, name: str, level: int, client_uuid: str
) -> None:
    """Добавляет клиента с заданным UUID на один сервер."""
    c = _conn(server)
    sp = server.effective_stack_path

    secrets = _load_secrets(c, sp)
    if not secrets:
        raise SystemExit(
            f"[{server.host}] Секреты не найдены. Сначала: fab deploy"
        )

    cfg_result = c.run(f"cat {sp}/config.json", hide=True)
    config = json.loads(cfg_result.stdout)

    # Проверка дублей
    reality_ib = next(
        (ib for ib in config["inbounds"] if ib.get("tag") == "vless-reality"), None
    )
    if reality_ib:
        existing = [
            cl
            for cl in reality_ib["settings"]["clients"]
            if cl.get("email", "").split("@")[0] == name
        ]
        if existing:
            raise SystemExit(
                f"[{server.host}] Клиент '{name}' уже существует "
                f"(UUID: {existing[0]['id']})"
            )

    for inbound in config["inbounds"]:
        tag = inbound.get("tag", "")
        if tag == "vless-reality":
            inbound["settings"]["clients"].append(
                {
                    "id": client_uuid,
                    "flow": "xtls-rprx-vision",
                    "email": f"{name}@reality",
                    "level": level,
                }
            )
        elif tag == "vless-xhttp-tls":
            inbound["settings"]["clients"].append(
                {
                    "id": client_uuid,
                    "email": f"{name}@xhttp-tls",
                    "level": level,
                }
            )

    _upload_text(
        c,
        json.dumps(config, ensure_ascii=False, indent=2),
        f"{sp}/config.json",
    )
    c.run(f"cd {sp} && docker compose restart xray")

    effective_domain = (
        server.domain if server.domain is not None else _get_server_domain(config)
    )
    print(
        f"  ✓ [{server.host}] Клиент '{name}' добавлен "
        f"(UUID: {client_uuid}, level: {level})"
    )
    _print_client_links(name, client_uuid, secrets, server.host, effective_domain or "")


# ---------------------------------------------------------------------------
# Fabric задачи
# ---------------------------------------------------------------------------


@task
def deploy(ctx, host=None):
    """Полный деплой xray-сервера.

    По умолчанию деплоит на все серверы из SERVERS последовательно.
    Идемпотентен: не перегенерирует ключи и не перевыпускает сертификаты.

    Использование:
      fab deploy
      fab deploy --host=1.2.3.4
    """
    servers = _get_servers(host)
    for i, server in enumerate(servers, 1):
        sep = "=" * 60
        print(f"\n{sep}")
        print(f"[{i}/{len(servers)}] {server.label()}")
        print(sep)
        _deploy_server(server)


@task
def add_client(ctx, name, level=0, host=None):
    """Добавляет нового клиента на все серверы (или конкретный).

    UUID генерируется один раз и одинаков на всех серверах —
    достаточно поменять host в ссылке для подключения к другому серверу.

    Параметры:
      --name    имя клиента (обязательно)
      --level   уровень политики, default=0
      --host    конкретный сервер (по умолчанию — все)

    Использование:
      fab add-client --name=alice
      fab add-client --name=alice --host=1.2.3.4
      fab add-client --name=alice --level=1
    """
    servers = _get_servers(host)
    # UUID генерируется один раз для всех серверов
    client_uuid = str(_uuid_mod.uuid4())
    client_level = int(level)

    print(f"\nДобавляем клиента '{name}' (UUID: {client_uuid}) на {len(servers)} сервер(а)...\n")
    for server in servers:
        _add_client_to_server(server, name, client_level, client_uuid)


@task
def list_clients(ctx, host=None):
    """Выводит список клиентов с vless-ссылками.

    При нескольких серверах требует --host.

    Использование:
      fab list-clients
      fab list-clients --host=1.2.3.4
    """
    server = _get_single_server(host)
    c = _conn(server)
    sp = server.effective_stack_path

    secrets = _load_secrets(c, sp)
    if not secrets:
        raise SystemExit(f"Секреты не найдены на {server.host}. Сначала: fab deploy")

    cfg_result = c.run(f"cat {sp}/config.json", hide=True)
    config = json.loads(cfg_result.stdout)

    reality_inbound = next(
        (ib for ib in config["inbounds"] if ib.get("tag") == "vless-reality"), None
    )
    if not reality_inbound:
        print(f"[{server.host}] vless-reality инбаунд не найден.")
        return

    effective_domain = (
        server.domain if server.domain is not None else _get_server_domain(config)
    )
    clients = reality_inbound["settings"]["clients"]
    policy_levels = config.get("policy", {}).get("levels", {})

    print(f"\n[{server.host}] Клиентов: {len(clients)}\n")
    for client in clients:
        email = client.get("email", client["id"])
        name = email.split("@")[0]
        lv = client.get("level", 0)
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
        _print_client_links(name, client["id"], secrets, server.host, effective_domain or "")


@task
def status(ctx, host=None):
    """Показывает статус контейнеров.

    При нескольких серверах требует --host.

    Использование:
      fab status
      fab status --host=1.2.3.4
    """
    server = _get_single_server(host)
    c = _conn(server)
    c.run(f"cd {server.effective_stack_path} && docker compose ps")


@task
def logs(ctx, host=None, lines=50):
    """Показывает последние логи xray-контейнера.

    При нескольких серверах требует --host.

    Использование:
      fab logs
      fab logs --host=1.2.3.4
      fab logs --lines=200
    """
    server = _get_single_server(host)
    c = _conn(server)
    c.run(
        f"cd {server.effective_stack_path} && docker compose logs --tail={lines} xray"
    )


@task
def restart(ctx, host=None):
    """Перезапускает xray-контейнер.

    При нескольких серверах требует --host.

    Использование:
      fab restart
      fab restart --host=1.2.3.4
    """
    server = _get_single_server(host)
    c = _conn(server)
    c.run(f"cd {server.effective_stack_path} && docker compose restart xray")
    print(f"✓ [{server.host}] xray перезапущен.")
