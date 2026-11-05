# План Feature 002

1. Отдельный контейнер/неймспейс worker с egress policy.
2. Сетевые trace fixtures и доказательная модель; модуль не влияет на core 001.
3. Сценарии baseline, отклонение, согласие с conservative UI recognition.
4. Интеграция Data Platform только для acquisition/indexing; browser interception
   выполняется через специализированный read-only adapter.
5. Негативные security tests и QA на собственных тестовых доменах.

Gate: не включать публичный SaaS до проверенного сетевого sandbox.

B002 evidence DTO и сравнение фаз реализованы как офлайн-контракт в src/arvectum_compliance/core/browser_evidence.py; браузерный сбор и сетевой sandbox **не** реализованы.


## Acceptance progress (2026-11-05)
- B001a: Docker image pinned to the official multi-arch digest.
  Worker executes Chromium as unprivileged user in Linux --network none,
  with read-only filesystem, cap-drop, no-new-privileges and resource bounds.
- B001b: pinned_http.py validates all DNS answers and connects to approved
  public IP without a second DNS lookup, preserving TLS SNI/hostname checks.
  HTTP redirects are never followed. Not yet network-firewall protected.
- B003/B004: real Chromium Docker tests validate three independent contexts
  and network-deny fixtures; pytest asserts no cookie values/PII in JSON.
- B001c/B005: no live browser target support until gateway isolation,
  verified domain ownership, quotas and end-to-end attack fixtures pass.
