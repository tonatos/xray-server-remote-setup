# 1. Подними только acme-proxy:
```
docker compose up -d xray-acme-proxy
```

# 2. Выпусти сертификат:
```sh
docker compose run --rm --entrypoint certbot certbot \
  certonly \
  --webroot -w /var/www/certbot \
  -d test-sni-over-wildcard.ru \
  --email tonatossn@gmail.com \
  --agree-tos \
  --no-eff-email \
  --non-interactive

docker compose run --rm --entrypoint sh certbot -c \
  "ls -la /etc/letsencrypt/live/test-sni-over-wildcard.ru/"
```

# 3. Выпустить ключи и сгенерировать ключи
```
chmod +x init-keys.sh && ./init-keys.sh
```

# 4. Запусти всё:
```
# Проверить конфиг
docker exec xray xray run -test -config /etc/xray/config.json

# Запустить
docker compose up -d
```
