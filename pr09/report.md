<!--
SPDX-FileCopyrightText: 2024 slayny23 <park243@mail.ru>
SPDX-License-Identifier: MIT
-->

Вот команда — вставь её целиком в терминал, она создаст готовый report.md со всеми собранными данными:
bashcat > ~/xto/pr09/report.md << 'REPORT'
# ПР №9. Следы вредоносного ПО в Linux

## 1. Что было посажено

| Механизм | Место | Команда/файл |
|----------|-------|-------------|
| Cron | crontab пользователя ssl | /tmp/.hidden_malware/backdoor.sh (@reboot и */5 * * * *) |
| Systemd | ~/.config/systemd/user/ | system-helper.service |
| Shell profile | ~/.bashrc (строка 116) | /tmp/.hidden_malware/backdoor.sh & |
| Процесс | /tmp/.hidden_malware/ | listener.sh -> nc слушает порт 4444 |

## 2. Что нашли — процессы

Команда: ps aux | grep '/tmp'

Результат:
ssl   20250  /bin/bash /tmp/.hidden_malware/backdoor.sh   (запущен systemd, 19:01)

ssl   20256  /bin/bash /tmp/.hidden_malware/listener.sh   (запущен вручную, 19:02)

ssl   20347  /bin/bash /tmp/.hidden_malware/backdoor.sh   (запущен cron, 19:05)

ssl   20498  /bin/bash /tmp/.hidden_malware/backdoor.sh   (запущен cron, 19:10)

ssl   20628  /bin/bash /tmp/.hidden_malware/backdoor.sh   (запущен cron, 19:15)

Что подозрительно: путь запуска из скрытой папки /tmp/.hidden_malware (начинается с точки), несколько одновременно работающих копий одного и того же скрипта. Это прямое следствие того, что сразу три механизма автозапуска (systemd с Restart=always, cron каждые 5 минут, и потенциально bashrc при каждом новом терминале) работают одновременно и независимо — даже если убить один процесс, через 5 минут cron запустит новый, а systemd перезапустит свой почти сразу.

## 3. Что нашли — сетевые соединения

Команда: ss -tulnp
Подозрительный порт: 4444 на 0.0.0.0 (все интерфейсы, не только localhost)
Процесс: nc, PID 20257

Команда: sudo lsof -i :4444
Результат:
COMMAND   PID USER FD   TYPE DEVICE SIZE/OFF NODE NAME

nc      20257  ssl  3u  IPv4 1324777     0t0  TCP *:4444 (LISTEN)

Как lsof связывает порт с процессом: ss показывает, что порт держит процесс с PID 20257, но не даёт деталей о самом процессе. lsof -i :4444 подтверждает то же самое и дополнительно через lsof -p 20257 видно, что это исполняемый файл /usr/bin/nc.openbsd, его открытые файлы и сокеты, а также что stderr (FD 2w) перенаправлен в /dev/null — типичный приём, чтобы не оставлять следов об ошибках в логах.

Важное наблюдение: сам скрипт listener.sh (PID 20256, bash-обёртка) не является держателем порта — порт держит его дочерний процесс nc (PID 20257). Это типичная схема "launcher + реальный воркер", усложняющая обнаружение по первому же PID.

## 4. Что нашли — автозапуск

### Cron

Вывод crontab -l:
@reboot /tmp/.hidden_malware/backdoor.sh &

*/5 * * * * /tmp/.hidden_malware/backdoor.sh &

Что подозрительно: путь в /tmp/ + скрытая папка, запуск при каждой загрузке (@reboot) и дополнительно каждые 5 минут — избыточность для гарантированного выживания.

Проверка системного /etc/crontab, /etc/cron.d/ и /var/spool/cron/crontabs/* — посторонних записей не найдено, всё стандартное (anacron, e2scrub_all). Подозрительные записи есть только в crontab пользователя ssl.

### Systemd

Вывод systemctl --user list-unit-files --state=enabled (фрагмент):
system-helper.service    enabled enabled
Среди легитимных десктопных сервисов (pipewire, wireplumber, tracker-*, gcr-ssh-agent и т.п.) единственный сервис без понятного происхождения.

Важное наблюдение: системная проверка systemctl list-unit-files --state=enabled (без --user) НЕ показывает этот сервис вообще — он виден только через флаг --user. Это и есть причина, по которой ~/.config/systemd/user/ — удобное и опасное место: не требует root/sudo и не попадает в обычный системный аудит.

Содержимое unit-файла:
[Unit]

Description=System Helper Service

After=default.target
[Service]

ExecStart=/tmp/.hidden_malware/backdoor.sh

Restart=always

RestartSec=10
[Install]

WantedBy=default.target

Что подозрительно: обобщённое название Description, ExecStart указывает на /tmp/, Restart=always обеспечивает автоматическое выживание процесса.

### ~/.bashrc

Строка которую нашли:
system update helper
/tmp/.hidden_malware/backdoor.sh &

Где находится (номер строки): строка 116 файла /home/ssl/.bashrc (найдено через grep -n).

## 5. Итоговая таблица следов

| Место | Инструмент обнаружения | Что нашли |
|-------|----------------------|-----------|
| Процессы | ps aux / grep '/tmp' | 4 копии backdoor.sh + listener.sh из /tmp/.hidden_malware |
| Порт 4444 | ss -tulnp | nc, PID 20257, слушает на 0.0.0.0 |
| Файлы процесса | sudo lsof -p 20257 | /usr/bin/nc.openbsd, сокет TCP *:4444, stderr -> /dev/null |
| Cron | crontab -l | @reboot и */5 * * * * записи на backdoor.sh |
| Systemd | systemctl --user list-unit-files | system-helper.service, ExecStart в /tmp/ |
| Bashrc | grep -n / tail | строка 116, запуск backdoor.sh при каждом терминале |

## 6. Связь с нормативкой

Какие меры ФСТЭК №17 реализует эта проверка:
- АНЗ.2 — обнаружение вредоносного кода: поиск подозрительных мест автозапуска (cron, systemd, bashrc)
- АУД.4 — анализ безопасности: анализ процессов (ps aux) и связи процесс-файл-сеть (lsof)
- ЗИС.17 — управление сетевыми соединениями: проверка слушающих портов через ss, выявление нелегитимного listener на порту 4444

## Выводы

В ходе практической работы был посажен учебный безвредный скрипт, имитирующий поведение вредоносного ПО, в четыре независимых места: cron (двумя записями), systemd user-сервис и ~/.bashrc. Все следы были успешно обнаружены стандартными инструментами Linux: ps, ss, lsof, crontab, systemctl, grep.

Самым неочевидным местом оказался пользовательский systemd-сервис в ~/.config/systemd/user/ — он не требует root для создания и не отображается в стандартной системной проверке systemctl list-unit-files без флага --user, что делает его удобным местом для скрытого автозапуска вредоноса, полученного через скомпрометированный аккаунт обычного пользователя без повышения привилегий.

Также показательным оказался разрыв между process-launcher (bash-скрипт) и реальным держателем сетевого соединения (дочерний процесс nc) — при поверхностной проверке легко принять PID launcher'а за источник сетевой активности, хотя реальная сеть открыта дочерним процессом с другим PID.
## 7. Финальная проверка после зачистки

Команда: /tmp/check-system.sh 2>/dev/null

Сравнение с первым запуском диагностического скрипта:

| Раздел | До зачистки | После зачистки |
|---|---|---|
| Cron | 2 записи @reboot и */5 на backdoor.sh | пусто |
| Systemd enabled (user) | 11 сервисов, включая system-helper.service | 10 сервисов, вредоносного нет |
| Bashrc | строка /tmp/.hidden_malware/backdoor.sh & | пусто |
| Процессы из /tmp | 5 процессов (4 копии backdoor.sh + listener.sh) | 0 (только сам check-system.sh) |
| Порт 4444 | LISTEN, nc PID 20257 | отсутствует |
| Удалённые открытые файлы | только pipewire | только pipewire (без изменений) |

Отдельно пришлось убить процесс nc (PID 20257), который держал порт 4444 -
pkill -f "listener.sh" не нашёл его, так как реальным держателем порта был
дочерний процесс nc, а не сам bash-скрипт listener.sh. Это ещё раз
подтверждает наблюдение из раздела 3: при зачистке важно убивать не
launcher, а конечный процесс, который реально держит ресурс (порт, файл).
