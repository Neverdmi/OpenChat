# OpenChat

Анонимный текстовый мессенджер на публичной инфраструктуре.

- Спецификация: [SPEC.md](SPEC.md)
- Статус: P2 завершён — ядро + транспорт + самохостируемый релей
- Тесты: 41

## Что уже работает

**Крипто (`oc-core`)**
- Ed25519/X25519 идентичности, self-certifying `PeerID`, safety number
- Гибридный X3DH: `X25519 + ML-KEM-768`
- Double Ratchet: forward secrecy, post-compromise security, out-of-order доставка
- Sealed sender: релей не видит отправителя
- Фиксированные бакеты паддинга 256/1024/4096/16384
- Ротация адресов-«ящиков» раз в сутки (32 слота)

**Транспорт (`oc-transport`)**
- Трейт `Carrier` — взаимозаменяемые носители
- WebSocket-клиент релея (TLS через rustls + ring)
- Пул релеев: случайный fan-out, fallback при подписке, health-check
- Разбор встроенного списка релеев `relays/default.json`

**Релей (`oc-relay`)**
- Store-and-forward без аккаунтов и access-log
- Лимиты TTL / размера / количества событий на ящик
- HTTP `POST /publish` + WebSocket `/ws` (подписка, публикация, ping)
- Статический musl-бинарник ~1.7 MB

## Сборка и тесты

```bash
cargo test
cargo build --release
cargo build --release --target x86_64-unknown-linux-musl
```

## Запуск релея

```bash
cargo run -p oc-relay -- --listen 127.0.0.1:8080
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
relays/default.json  встроенный список релеев (пока пуст)
```

Рабочее имя проекта временное; префикс протокола — `openchat/`.
