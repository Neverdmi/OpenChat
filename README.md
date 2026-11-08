# OpenChat

Анонимный текстовый мессенджер на публичной инфраструктуре.

- Спецификация: [SPEC.md](SPEC.md)
- Статус: P5 — CLI и TUI готовы (GUI удалён); P4 почти готов (ждёт деплоя публичного релея)
- Тесты: 97 (+15 в oc-tui)

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

## Сборка

Одна программа — `oc-tui` (TUI) с CLI-режимом внутри (`--cli`).
Собирается одной командой с указанием таргета:

```bash
# glibc (Debian/Ubuntu/Fedora и т.д.; нужен gcc для ring):
cargo build --release -p oc-tui --target x86_64-unknown-linux-gnu

# musl, статический бинарник (Alpine и любые хосты; работает и на glibc):
cargo build --release -p oc-tui --target x86_64-unknown-linux-musl

# хостовый таргет по умолчанию:
cargo build --release -p oc-tui
```

musl-бинарник статический (static-pie): один файл, который запускается
и на musl-, и на glibc-системах — самый простой вариант для раздачи
друзьям. Бинарники: `target/<target>/release/oc-tui`.

Для Windows (exe с тем же TUI-интерфейсом) — на Windows-машине:

```powershell
cargo build --release -p oc-tui --target x86_64-pc-windows-msvc
# бинарник: target\x86_64-pc-windows-msvc\release\oc-tui.exe
```

На Linux musl-хосте windows-таргет не собирается (нужен MSVC-линкер);
musl-бинарник под Windows не работает — для Windows нужен именно
windows-таргет на Windows или с mingw-кроссом.

Тесты и проверки:

```bash
cargo test
cargo clippy --all-targets
cargo test -p oc-tui
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

## TUI (`oc-tui`) — одна программа со всем

```bash
./target/release/oc-tui            # терминальный интерфейс (ratatui)
./target/release/oc-tui --cli chat <peer>   # тот же CLI, без смены бинарника
```

Первый запуск: на экране входа нажми **F2** (режим Create), введи каталог
состояния, пароль — или **F3**, чтобы сгенерировать сильный
(`word-word-word-word-1234`; запиши его, восстановить нельзя), повтори
пароль, Enter. Дальше всё внутри:

- контакты слева (Tab, ↑↓), переписка по центру, ввод снизу;
- `/invite` — полная ссылка-приглашение отдельной панелью (**C** — скопировать
  в буфер через OSC 52, Esc — закрыть; вручную выделять длинный текст
  не нужно);
- `/add <invite>` (или вставить `openchat://…`) — добавить контакт;
- `/settings` — меню настроек: Tor-режим (`off`/`fallback`/`always`,
  нужен установленный `tor`), fanout, invite при старте;
- `/contacts`, `/flush`, `/help`, `/quit`; `Ctrl+C` — выход.

Tor-режим: `always` гонит весь трафик через Tor SOCKS5 и падает
закрыто (без прямого соединения), если Tor недоступен; `fallback`
пробует напрямую и только при ошибке идёт через Tor.

GUI-версия (egui) удалена: TUI оказался удобнее, в одной программе
остаются только TUI и CLI.

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
crates/oc-cli        CLI `oc` (библиотека + бинарник)
crates/oc-tui        терминал `oc-tui` (ratatui; `--cli` → CLI)
relays/default.json  встроенный список релеев (пока пуст)
```

Рабочее имя проекта временное; префикс протокола — `openchat/`.
