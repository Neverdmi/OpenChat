# OpenChat

Анонимный текстовый мессенджер на публичной инфраструктуре.

- Спецификация: [SPEC.md](SPEC.md)
- Статус: P5 начат — интерактивный CLI; P4 почти готов (ждёт деплоя публичного релея)
- Тесты: 90

## Что уже работает

**Крипто (`oc-core`)**
- Ed25519/X25519 идентичности, self-certifying `PeerID`, safety number
- Гибридный X3DH: `X25519 + ML-KEM-768`
- Double Ratchet: forward secrecy, post-compromise security, out-of-order доставка
- Sealed sender: релей не видит отправителя
- Фиксированные бакеты паддинга 256/1024/4096/16384
- Ротация адресов-«ящиков» раз в сутки (32 слота)
- Сериализация identity, prekeys и ratchet-состояния для перезапуска

**Транспорт (`oc-transport`)**
- Трейт `Carrier` — взаимозаменяемые носители
- WebSocket-клиент релея (TLS через rustls + ring)
- Пул релеев: случайный fan-out, fallback, health-check
- Мультиплексированная подписка на сотни ящиков в одном соединении

**Релей (`oc-relay`)**
- Store-and-forward без аккаунтов и access-log
- Лимиты TTL / размера / количества событий на ящик
- HTTP `POST /publish` + WebSocket `/ws` (subscribe, publish, ping)
- Лимит 4096 ящиков на соединение
- Статический musl-бинарник ~1.7 MB

**Клиент (`oc-client`)**
- Шифрованное состояние: Argon2id + XChaCha20-Poly1305, файл `0600`
- Invite-ссылки `openchat://v1/...` с подписанным prekey bundle
- X3DH handshake через sealed handshake-mailbox
- TOFU-пиннинг identity-ключей
- Дедупликация сообщений (4096 `msg_id`)
- Состояние и сессии переживают перезапуск

**CLI (`oc-cli`, бинарник `oc`)**
- `init`, `invite`, `add`, `send`, `chat`, `listen`, `contacts`, `flush`, `outbox`, `rotate`, `relays`
- `chat [PEER]` — интерактивный чат: приём и отправка в одном процессе,
  команды `/help`, `/peer <prefix>`, `/quit`. История открытым текстом
  не хранится — сообщения печатаются при получении.

## Сборка и тесты

```bash
cargo test
cargo clippy --all-targets
cargo build --release
cargo build --release --target x86_64-unknown-linux-musl
```

## Быстрый старт (два терминала)

Запустить локальный релей:

```bash
cargo run -p oc-relay -- --listen 127.0.0.1:8080
```

Создать два клиента:

```bash
export OPENCHAT_PASSPHRASE='alice-passphrase'
./target/debug/oc --home /tmp/alice init --relay http://127.0.0.1:8080

export OPENCHAT_PASSPHRASE='bob-passphrase'
./target/debug/oc --home /tmp/bob init --relay http://127.0.0.1:8080
```

Боб показывает invite, Алиса добавляет его:

```bash
INVITE=$(OPENCHAT_PASSPHRASE='bob-passphrase' ./target/debug/oc --home /tmp/bob invite)

OPENCHAT_PASSPHRASE='alice-passphrase' ./target/debug/oc --home /tmp/alice add "$INVITE"
```

Боб принимает рукопожатие, затем Алиса отправляет текст:

```bash
OPENCHAT_PASSPHRASE='bob-passphrase' ./target/debug/oc --home /tmp/bob listen --once --idle 1

BOB_ID=$(echo "$INVITE" | cut -d/ -f4)
OPENCHAT_PASSPHRASE='alice-passphrase' ./target/debug/oc --home /tmp/alice send "$BOB_ID" "привет"

OPENCHAT_PASSPHRASE='bob-passphrase' ./target/debug/oc --home /tmp/bob listen --once --idle 1
```

Ответ:

```bash
ALICE_ID=$(OPENCHAT_PASSPHRASE='bob-passphrase' ./target/debug/oc --home /tmp/bob contacts | awk '{print $1}' | head -1)
OPENCHAT_PASSPHRASE='bob-passphrase' ./target/debug/oc --home /tmp/bob send "$ALICE_ID" "привет обратно"
OPENCHAT_PASSPHRASE='alice-passphrase' ./target/debug/oc --home /tmp/alice listen --once --idle 1
```

Без `--once` команда `listen` работает постоянно.

Интерактивный режим (приём + отправка в одном окне):

```bash
OPENCHAT_PASSPHRASE='alice-passphrase' ./target/debug/oc --home /tmp/alice chat "$BOB_ID"
```

Внутри: текст — отправить, `/peer <prefix>` — сменить собеседника,
`/help` — справка, `/quit` — выход.

## Запуск релея

```bash
cargo run -p oc-relay -- --listen 0.0.0.0:8080
# или готовый бинарник:
./target/x86_64-unknown-linux-musl/release/oc-relay --listen 0.0.0.0:8080
```

Проверка:

```bash
curl http://127.0.0.1:8080/health
```

## Структура

```
crates/oc-core       крипто, X3DH, sealed sender, кадры, ящики, ratchet
crates/oc-wire       общие типы протокола релея (JSON)
crates/oc-transport  Carrier, WebSocket-клиент, пул релеев
crates/oc-relay      self-hosted релей + бинарник
crates/oc-client     состояние, invite, сессии, текст, TOFU
crates/oc-cli        CLI `oc`
relays/default.json  встроенный список релеев (пока пуст)
```

Рабочее имя проекта временное; префикс протокола — `openchat/`.
