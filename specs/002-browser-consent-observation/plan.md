# План Feature 002

1. Отдельный контейнер/неймспейс worker с egress policy.
2. Сетевые trace fixtures и доказательная модель; модуль не влияет на core 001.
3. Сценарии baseline, отклонение, согласие с conservative UI recognition.
4. Интеграция Data Platform только для acquisition/indexing; browser interception
   выполняется через специализированный read-only adapter.
5. Негативные security tests и QA на собственных тестовых доменах.

Gate: не включать публичный SaaS до проверенного сетевого sandbox.
