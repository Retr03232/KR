# Паттерн защиты документов от злоупотребления доверием облачному провайдеру

Реализация для курсовой работы: пять самостоятельных HTTPS-сервисов, WebDAV-адаптер для защищённой папки Nextcloud, контейнерные и кластерные конфигурации. Защищается содержимое документов при копировании облачного хранилища и обращении за открытым текстом только с облачными служебными реквизитами.


## Состав

| Сервис | Функция | Данные |
|---|---|---|
| order-api | WebDAV и передача запросов | Только временные буферы в памяти |
| identity-policy | Личные учётные записи, изолированные пространства файлов, режим чтения | Соль и хеши паролей, признаки прав |
| security-crypto | Проверка сервиса и пользователя, AES-GCM, версии, повтор операций | Ключи, nonce, доверенный реестр, подготовленный шифротекст |
| cloud-storage | Получение и сохранение неизменяемых зашифрованных объектов | Случайные идентификаторы и шифротекст |
| audit | Подтверждение записи решений перед выдачей содержимого | Субъект, действие, результат, идентификатор объекта |

Nextcloud, его база, TLS-терминация, временные файлы и четыре доверенных сервиса находятся у потребителя. Только cloud-storage и его том относятся к поставщику. На одном компьютере это функциональная модель, а не реальная защита от администратора данного компьютера.

## Быстрая проверка без Docker

Нужен Python 3.12. Команды выполняются из корня проекта:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
python -m pytest -q --junitxml=reports/tests.xml
python scripts/check_manifests.py
python scripts/run_local.py
```

В Linux вместо активации PowerShell: `source .venv/bin/activate`.
Локальный WebDAV: `https://localhost:18441/dav/`. Персональные пароли: `.runtime-local/users.json`; доверенный сертификат: `.runtime-local/ca.pem`. Не отключать проверку TLS. Ctrl+C останавливает только запущенные скриптом процессы. Файлы сохраняются. Локальный запуск не запускает Nextcloud.

## Docker Compose и Nextcloud

Нужен работающий Docker Engine с Compose. В Windows — Docker Desktop с Linux-контейнерами либо отдельная Linux-ВМ. Каталог `.runtime` создаётся один раз; bootstrap отказывается заменять существующие секреты.

```powershell
python scripts/bootstrap.py
docker compose build
docker compose -f compose.yaml -f compose.nextcloud.yaml --profile nextcloud --profile monitoring up -d
docker compose -f compose.yaml -f compose.nextcloud.yaml --profile nextcloud ps
docker compose -f compose.yaml -f compose.nextcloud.yaml exec -u www-data nextcloud php occ status
```

Nextcloud доступен по `https://localhost:8443`; администратор `admin`, пароль в `.runtime/nextcloud.env`. Браузеру нужен доверенный CA `.runtime/ca.pem`. Импорт сертификата в хранилище ОС выполняется пользователем осознанно, автоматически скрипты его не устанавливают. Прямой WebDAV для диагностики: `https://localhost:8444/dav/`.

После готовности Nextcloud выполнить автоматическую настройку и проверку:

```powershell
python scripts/setup_nextcloud.py
python scripts/verify_nextcloud.py
```

`setup_nextcloud.py` создаёт демонстрационные учётные записи alice и bob и папку `Protected`, подключённую по WebDAV к `https://order-api:8443/dav/`. Реквизиты входа в Nextcloud находятся в `.runtime/nextcloud-users.json`; отдельные реквизиты хранилища — в `.runtime/users.json`. Скрипт сохраняет для каждого пользователя его собственное подключение. Он отключает общий доступ к папке и предпросмотры, включает доступ Nextcloud к частному адресу контейнера. На существующей рабочей инсталляции эти настройки требуют отдельного согласования; здесь настраивается выделенный стенд.

Сертификат лабораторного CA добавляется в Nextcloud командой occ и в системное хранилище сертификатов его контейнера через `deploy/nextcloud-entrypoint.sh`. Это необходимо для разных HTTP-клиентов Nextcloud, в том числе загрузки через Guzzle. Проверка TLS остаётся включённой. Хранилище доверия Windows скрипты не меняют.

`verify_nextcloud.py` создаёт небольшой тестовый файл в Protected и оставляет его для демонстрации. Скрипт проверяет SHA-256 после скачивания, изоляцию alice/bob, отказ анонимному запросу, шифротекст в облачной базе, отказ с облачным токеном и пять целей Prometheus. Результат сохраняется в `reports/nextcloud-smoke.json`. Учётные записи проверяются без переноса cookie между пользователями.


Запуск Prometheus:

```powershell
docker compose -f compose.yaml -f compose.nextcloud.yaml --profile monitoring up -d
```

Адрес `http://localhost:9090` привязан только к loopback. Отдельная сеть monitoring-ui обеспечивает публикацию порта; внутренняя monitoring соединяет все пять сервисов. Поэтому Compose не обеспечивает направленную фильтрацию всех межсервисных соединений: допуск к API проверяется служебными токенами и пользовательской аутентификацией. Направленные сетевые ограничения описаны в Kubernetes NetworkPolicy и пока не проверены на кластере. Счётчики: `pattern_requests_total`, `pattern_decisions_total`, `pattern_audit_events_total`; гистограмма `pattern_request_seconds`. Время HTTP-обработчика не заменяет измерение получения полного файла клиентом.

## Kubernetes

`deploy/kubernetes.yaml` содержит пять Deployment и Service, отдельные PVC, пространства `pattern-consumer` и `pattern-provider`, запрет сетевого обмена по умолчанию и разрешённые связи. Нужны StorageClass по умолчанию, CNI с поддержкой NetworkPolicy и доступный узлам образ. Файл не включает Nextcloud и Prometheus: их размещают отдельно в потребительском пространстве с метками `app: nextcloud` и `app: prometheus` либо используют согласованный внешний маршрут.

```powershell
python scripts/bootstrap.py
docker build -t YOUR_REGISTRY/course-pattern:0.1.0 .
docker push YOUR_REGISTRY/course-pattern:0.1.0
python scripts/deploy_kubernetes.py --context YOUR_CONTEXT --image YOUR_REGISTRY/course-pattern:0.1.0
kubectl --context YOUR_CONTEXT -n pattern-consumer get pods,svc,pvc,networkpolicy
kubectl --context YOUR_CONTEXT -n pattern-provider get pods,svc,pvc,networkpolicy
kubectl --context YOUR_CONTEXT -n pattern-consumer port-forward service/order-api 8444:8443
```

Второй вызов bootstrap не нужен, если конфигурация уже создана для Compose. Вместо примеров YOUR_REGISTRY/YOUR_CONTEXT указываются собственные значения; это не реальные адреса. Скрипт применяет изменения только к явно указанному контексту. Значения Secret передаются через stdin, а не через аргументы команд и не хранятся в Git. Перезапуск после изменения Secret необходимо выполнить явно: конфигурация читается сервисом при старте.

Один кластер с двумя namespace не защищает ключи от cluster-admin. Для реального разделения нужны независимые инфраструктуры потребителя и поставщика, отдельные администраторы, сертификаты на реальные DNS-имена, ограниченный TLS-маршрут к cloud-storage. Приложенный кластерный вариант предназначен для функциональной демонстрации. Изменение числа реплик недопустимо без переработки локальной SQLite и блокировок WebDAV.

## GitHub и GitLab

Репозитории пользователем пока не созданы, удалённая публикация не выполнялась. В проекте есть `.github/workflows/ci.yml` и `.gitlab-ci.yml`; облачные CI-проверки не запускались.

После создания двух пустых репозиториев и настройки авторизации Git:

```powershell
git init -b main
git add .
git diff --cached --stat
git commit -m "Implement five-service document protection prototype"
git remote add github https://github.com/YOUR_ACCOUNT/YOUR_REPOSITORY.git
git remote add gitlab https://gitlab.com/YOUR_ACCOUNT/YOUR_REPOSITORY.git
git push -u github main
git push gitlab main
```

Если локальный репозиторий уже инициализирован, повторять `git init` не требуется. Имя и email автора коммита задаются самим пользователем. Пароли, токены, `.runtime*`, журналы тестов с локальными конфигурациями и базы данных исключены из Git. В CI публикуется только JUnit-отчёт, а не временные каталоги с секретами.

## Границы реализации

- Аутентификация стенда — персональные пароли по TLS и независимая проверка identity-policy. OIDC пока не реализован; согласованная версия глав 1–2 описывает персональную проверку по TLS.
- Доступ к документам ограничен личным пространством пользователя; групповые ACL, делегирование и совместное редактирование не реализованы.
- Полный файл обрабатывается в памяти. Предел 10 МиБ — выбранное ограничение прототипа. Шифрование потоков и больших файлов потребует отдельного формата.
- AES-GCM: отдельный случайный ключ 256 бит и nonce 96 бит на версию; тег 128 бит. Повтор с тем же `request_id` использует сохранённый шифротекст. В WebDAV этот идентификатор задаётся заголовком `Idempotency-Key`; без него новая загрузка создаёт новую версию.
- Журнал `authorized` фиксирует разрешение перед возвратом содержимого, а не факт его получения пользователем. Проверки stat/list не создают событий выдачи. Отказы, отсечённые order-api, пока отражаются в HTTP-метриках, а не в audit. Полноту аудита всех отказов нельзя заявлять.
- Удаление скрывает файл в реестре, но не стирает старые шифрованные объекты и ключи. Сборка мусора и политика хранения требуют отдельной разработки.
- Не заявлены отказоустойчивость, защита от DoS, шифрование метаданных, ротация секретов, HSM или полная промышленная готовность. Секреты на диске доверенного узла защищаются его средствами; Windows chmod не заменяет настройку NTFS ACL.
- Резервировать реестр, ключи и аудит нужно согласованно и вне полномочий провайдера. Без резервной копии ключей документы после утраты доверенного тома не восстановить.

## Документация




Блок-схемы и текст главы находятся в `docs/`. Дополнительные первичные источники и проверенные свойства перечислены в `docs/sources.md`. Конкретные численные параметры стенда объяснены в `docs/parameters.md`; они не выдаются за измеренные показатели или нормативные требования.
