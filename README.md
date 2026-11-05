# Arvectum Compliance

Переиспользуемое ядро технической проверки сайтов: формы, видимые ссылки
на документы и структурированные находки. **Не является юридическим
заключением** о соответствии 152-ФЗ. Публичный SaaS ещё не запущен.

## Текущий статус

- AC-00: Spec Kit 1.2.4, разделение core/Data Platform, скрипты CI, политика
  границ безопасности и двухсторонний проектный реестр — реализованы.
- AC-01: работающий **офлайн статический** анализ HTML и ограниченный
  одноадресный HTTP GET — реализованы, браузерный анализ cookies ещё не готов.
- Feature 002: изолированный Docker Chromium worker проверен на тестовых
  страницах (baseline/reject/accept). Выходы очищаются от значений cookies
  и URL-параметров. Реальное браузерное сканирование сайтов не разрешено
  до production egress/firewall и подтверждения владения доменом.
- AC-02+: юридические пакеты правил, SaaS, мониторинг и PR-исправления — впереди.

## Быстрый старт

```bash
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -e '.[dev]'
.venv/bin/ruff check src tests
.venv/bin/pytest -q
.venv/bin/arvectum-compliance scan-html tests/fixtures/review.html --url https://example.com
```

Сеть и внешние ключи для офлайн-режима не нужны. Для разрешённого
одноадресного HTTP-сканирования установить `'.[data-platform]'` и вызвать
`scan-url https://owned.example --authorized`. Это **не** production
multi-tenant worker: до публичного запуска требуется сетевой sandbox.
Формы не отправляются, JS не выполняется, редиректы запрещены.

## Использование как библиотеки

```python
from arvectum_compliance import scan_html
report = scan_html("https://example.com/contact", "<form><input type='email'></form>")
print(report.to_dict())
```

## Документы

- [Текущий roadmap](docs/ROADMAP.md)
- [Архитектура, интерфейсы и reuse](docs/ARCHITECTURE.md)
- [Feature 001 / Spec Kit](specs/001-foundation-and-static-scan/spec.md)
- [Feature 002 / browser next](specs/002-browser-consent-observation/spec.md)
- [Синхронизация](docs/SYNC.md)
- [ADR](docs/adr/0001-core-and-data-platform.md)

## Репозитории

GitHub — https://github.com/arvectum2/compliance (канонический)
GitVerse — https://gitverse.ru/arvectum/compliance (зеркало)
Mac mini — `/Volumes/ArvectumSSD/Arvectum/repos/compliance`


## Проверка браузерного worker (только тестовые страницы)
```sh
npm ci --prefix browser-worker --ignore-scripts --no-audit
docker pull mcr.microsoft.com/playwright@sha256:2f05f8a734509a7b3f26a912639488ee08f58a7b292d14d62271bcff9038768f
scripts/run-browser-fixture.sh consent.html
COMPLIANCE_DOCKER_E2E=1 .venv/bin/pytest -q tests/test_browser_docker.py
```

Официальный образ закреплён по мультиархитектурному digest;
`--network none` и остальные ограничения см. [security](docs/BROWSER_SECURITY.md).
Для live браузерных проверок публичных сайтов ещё требуется B001c.

## Feature 003 — verified offline gateway prototype

Готовы DNS TXT proof (включая SQLite), HMAC-права на точный домен и задание,
бюджеты запросов/байтов, закрепление публичного IP и отдельный Chromium
без сетевого доступа с двунаправленным IPC через stdin/stdout.

Проверка только на синтетических HTML-страницах:
```bash
COMPLIANCE_DOCKER_E2E=1 .venv/bin/pytest -q   tests/test_browser_docker.py tests/test_bridge_docker.py
```

Продуктовый live-browser API НЕ запущен. **Обязательный блокер: EG-003**
(промышленная изоляция egress-шлюза и отрицательные тесты firewall).
Подробнее: [security](docs/FEATURE003_SECURITY.md), [Spec Kit](specs/003-verified-egress-gateway/spec.md).
