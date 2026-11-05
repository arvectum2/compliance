# Arvectum Compliance

Переиспользуемое ядро технической проверки сайтов: формы, видимые ссылки
на документы и структурированные находки. **Не является юридическим
заключением** о соответствии 152-ФЗ. Публичный SaaS ещё не запущен.

## Текущий статус

- AC-00: Spec Kit 1.2.4, разделение core/Data Platform, скрипты CI, политика
  границ безопасности и двухсторонний проектный реестр — реализованы.
- AC-01: работающий **офлайн статический** анализ HTML и ограниченный
  одноадресный HTTP GET — реализованы, браузерный анализ cookies ещё не готов.
- Feature 002: безопасный офлайн-контракт для агрегированных браузерных свидетельств реализован; worker ещё не запущен.
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
