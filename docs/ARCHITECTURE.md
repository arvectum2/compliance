# Arvectum Compliance: границы продукта и библиотек

## Canonical consumers
- **arvectum_compliance.core** — независимая от SaaS, сетевой инфраструктуры
  и конкретного хостинга библиотека. Вход — HTML+source_url, выход —
  версионированный ScanReport. Используется CLI, backend, CI, другие продукты.
- **arvectum_compliance.adapters** — сетевой слой и мост с Data Platform.
  Реальный HTTP mode является локальным ограниченным режимом, НЕ публичным
  multi-tenant сканером до сетевой изоляции.
- **Arvectum Data Platform** — повторно используемые acquisition/extraction,
  модели, SDK, evidence, индексирование, биллинг. Не копировать её реализацию.
- **compliance service (будущий)** — идентификация арендаторов, разрешения
  на домен, задачи/отчёты и мониторинг.
- **compliance SaaS (будущий)** — коммерческий UI, выставление счетов.
  Не должен содержать правил и сканирующего кода.

## Найденные источники переиспользования (ревизия 2026-11-05)
| Repository | Готовый компонент | Стратегия |
| --- | --- | --- |
| arvectum2/data-platform | AcquisitionEngine/Request, HTTP+Playwright renderer | import+adapter; browser hardened separately |
| arvectum2/data-platform | CrawlPolicy, URLDiscoveryCrawler, search, usage, billing | подключать при ограниченном многостраничном сканировании и SaaS |
| arvectum2/arvectum-site | реальные формы/политики/cookie-consent | test fixtures / own-site pilot, не брать PHP в библиотеку |
| arvectum2/tender-agent | review decisions, event logs | заимствовать API patterns, не импортировать доменную модель |
| arvectum2/creative-test-agent | DOCX/PDF export patterns | оценить адаптер отчётов, без прямой зависимости |
| arvectum2/musbread | Playwright E2E, axe checks | использовать test patterns с разрешением Заказчика |
| arvectum2/deal | consumer of Data Platform | возможный будущий клиент, не нужен для текущего MVP |

## Контракты
- Python: `scan_html(url, html) -> ScanReport`; `to_dict()` возвращает schema_version 1.0.
- CLI: `scan-html FILE --url URL`; `scan-url URL --authorized` (ограниченный GET).
- Находка: rule_id/version, status=review, severity, title, explanation, evidence URL/XPath.
- Core rules не отправляют формы, не загружают ссылки, не вызывают LLM.
- Нельзя на основании отсутствия checkbox утверждать отсутствие законного
  основания обработки: только сигнал для проверки.

## Среды
- Локальный офлайн: запускается без Data Platform.
- Интеграционный: Data Platform Python Engine через дополнительный набор
  зависимостей. Нет необходимости запускать сервис и вводить секреты.
- Производственный SaaS: новая изолированная сеть для сканирования, egress deny
  RFC1918/localhost/link-local/metadata, DNS pinning, 0 доверенных редиректов
  и субресурсов, авторизация владения, quota и rate caps. До реализации — NO-GO.

## Версионирование и тесты
Правила и evidence не изменяются задним числом. Изменение семантики rule_id
требует повышения rule_version и нового теста/фактологического источника.
В CI полностью сетенезависимый suite. Интеграцию с Data Platform
дополнительно проверяем в Mac mini workspace, не импортируем её внутренние файлы.
