# Синхронизация GitHub — GitVerse — Mac mini

GitHub: https://github.com/arvectum2/compliance — источник истины, ветка main.
GitVerse: https://gitverse.ru/arvectum/compliance — одностороннее зеркало.
Mac mini: /Volumes/ArvectumSSD/Arvectum/repos/compliance — локальный checkout.

## GitHub -> GitVerse

Workflow .github/workflows/mirror-to-gitverse.yml синхронизирует все обычные
ветки и теги при push, вручную и по ежедневному расписанию.
Токен читается только из GitHub Actions secret GITVERSE_TOKEN.
Параметры --force --prune применяются ТОЛЬКО к зеркалу: собственные
коммиты в GitVerse запрещены, иначе они будут потеряны.

## GitHub -> Mac mini

LaunchAgent com.arvectum.compliance-sync запускает установленную копию
scripts/sync-local.sh при входе и каждые 300 секунд.
Допускается только fetch + merge --ff-only на чистой ветке main.
При локальных изменениях, активной другой ветке или отключённом SSD
изменения не перезаписываются. Локальные коммиты отправлять в GitHub.

## Проверка

    cd /Volumes/ArvectumSSD/Arvectum/repos/compliance
    git status -sb
    git rev-parse HEAD
    git ls-remote origin refs/heads/main
    git ls-remote gitverse refs/heads/main
    gh run list -R arvectum2/compliance --workflow mirror-to-gitverse.yml --limit 3
    launchctl list | grep com.arvectum.compliance-sync

Обновление установленного задания после изменения сценария или plist
требует их повторной установки в домашний каталог пользователя.
