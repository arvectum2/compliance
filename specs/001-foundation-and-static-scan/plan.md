# Implementation Plan — 001
2026-11-05 | Spec Kit 1.2.4

## Архитектура
- src/arvectum_compliance/core: независимые dataclass-модели, HTMLParser и rule registry; только стандартная библиотека.
- src/arvectum_compliance/adapters: статический HTTP через интерфейс Data Platform AcquisitionEngine, дополнительный RestrictedTransport для domain/redirect caps.
- src/arvectum_compliance/cli.py: команды scan-html, scan-url с явным --authorized.
- JSON v1: report {schema_version, source_url, inspected_pages, findings, signals, limitations}; finding содержит versioned rule evidence.
- pyproject.toml: устанавливаемый Python-пакет, CLI entry point; Data Platform как обязательная зависимость интеграционного режима.
- CI: ruff + pytest + CLI fixture smoke, без интернет-запросов.

## Reuse-гейт
Data Platform SDK/engine применяются через public импорт, не копировать internal файлы; для независимого ядра тесты не требуют запущенный Data Platform. Поддержку браузерных сценариев выделить в самостоятельный следующий feature 002.

## Security
HTTP без выполнения JS и POST; URL должен быть HTTP(S), публичным, без credentials, проверка origin на redirect; в production добавить egress firewall/DNS pinning до включения недоверенных multi-tenant доменов.


## Implementation evidence
- Core: src/arvectum_compliance/core/{html,models,scan}.py
- Data Platform: adapters/data_platform.py (public AcquisitionEngine/Request).
- Contract: CLI scan-html and scan-url, JSON schema_version 1.0.
- Tests: tests/test_core.py, tests/test_cli.py, tests/test_adapter.py.
- Fixture acceptance: local arvectum-site/public/contact.html gives one
  form, one consent control, policy links, zero review findings.
- Real GET smoke: https://arvectum.com/ via bounded read-only scan.
- No browser cookies/HAR or automatic legal findings; retained as 002.

### Acceptance verified
- Build: uv build (sdist + wheel) PASS.
- Lint and tests: Ruff PASS, 17/17 Feature 001 tests PASS.
- GitHub Actions: Compliance CI run 41989962869 PASS.
- GitVerse mirror: run 41989962924 PASS; main SHA aligned.
- Mac mini LaunchAgent: active and clean fast-forward.
