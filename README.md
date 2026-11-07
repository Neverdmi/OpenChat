# OpenChat

Анонимный текстовый мессенджер на публичной инфраструктуре.

- Спецификация: [SPEC.md](SPEC.md)
- Статус: P1 завершён — ядро протокола (`oc-core`), 25 тестов

## Что уже работает

- Ed25519/X25519 идентичности, self-certifying `PeerID`, safety number
- Гибридный X3DH: `X25519 + ML-KEM-768`
- Double Ratchet: forward secrecy, post-compromise security, out-of-order доставка
- Sealed sender: релей не видит отправителя
- Фиксированные бакеты паддинга 256/1024/4096/16384
- Ротация адресов-«ящиков» раз в сутки (32 слота)

## Сборка и тесты

```bash
cargo test
cargo build --release
cargo build --release --target x86_64-unknown-linux-musl
```

## Структура

```
crates/oc-core   крипто, X3DH, sealed sender, кадры, ящики, ratchet
```

Рабочее имя проекта временное; префикс протокола — `openchat/`.
