# Agent instructions

Read [`.memory`](.memory) and [`SPEC.md`](SPEC.md) before doing anything.

- After each completed step: update `.memory`, run `cargo test` and
  `cargo clippy --all-targets`, commit and push to `origin main` yourself.
- Never commit secrets, `target/`, `.env`, logs, or `~/.git-credentials`.
- Keep the protocol and `SPEC.md` in sync.
