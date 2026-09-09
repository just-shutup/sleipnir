<div align="center">

# Sleipnir

**Сетевой и веб-сканер уязвимостей на C++20**

Port scanning · Fingerprinting · CVE matching · TLS audit · Lua-плагины · HTML/JSON-отчёты

`C++20` · `Asio` · `OpenSSL` · `Lua 5.4` · `Linux-first`

</div>

---

Sleipnir — один бинарник, закрывающий конвейер аудита: от разведки портов до итогового отчёта для заказчика. Движок построен на Asio (пул воркеров, жёсткие таймауты, корректная остановка по Ctrl+C), базы знаний — декларативные JSON-файлы, пополняемые без перекомпиляции. Все проверки по умолчанию неинвазивны.

## Быстрый старт

### Вариант 1 — готовый бинарник

Скачайте архив последнего релиза со страницы [Releases](https://github.com/sleipnir-scanner/sleipnir/releases) (сборка Linux x86_64, публикуется GitHub Actions при выходе тега):

```bash
tar xzf sleipnir-*-linux-x86_64.tar.gz
cd sleipnir-*/
./sleipnir --version
```

В архиве лежит бинарник вместе с каталогами `data/` и `plugins/` — сканер находит их автоматически рядом с собой или вверх по дереву каталогов, поэтому запускать можно из любого места.

### Вариант 2 — сборка из исходников

Нужны CMake ≥ 3.20, компилятор с C++20 и заголовки OpenSSL (`libssl-dev`). Всё остальное вендорено в `third_party/`.

```bash
git clone https://github.com/sleipnir-scanner/sleipnir.git
cd sleipnir
cmake -B build -DBUILD_TESTS=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
ctest --test-dir build --output-on-failure   # юнит-тесты (doctest)
```

Бинарник: `build/apps/sleipnir/sleipnir`.

### Первый скан

```bash
# Интерактивная оболочка (по умолчанию на терминале)
./sleipnir
sleipnir> scan 192.168.1.0/24 -p 22,80,443 --report report.html
sleipnir> set          # текущие настройки
sleipnir> exit

# One-shot из командной строки
./sleipnir scan 192.168.1.10 -p 1-1024 --report report.json

# Сканирование только своих лабораторных сервисов (мок-лаба в комплекте)
python3 tools/mocklab/mock_services.py &
./sleipnir scan 127.0.0.1 -p 2101,2102,2201,2375,2501,2502,2503,6380,8080,8081,8082,8443
```

### Указание каталога плагинов

Сканер загружает все `.lua`-файлы из каталога `plugins/` (рядом с бинарником / в CWD / выше по дереву). Свой каталог:

```bash
./sleipnir --plugins ~/my-plugins --list-plugins     # проверка загрузки
./sleipnir scan 10.0.0.5 -p 21,25 --plugins ~/my-plugins
./sleipnir scan 10.0.0.5 -p 80 --no-plugins          # отключить движок
```

Аналогично `--data DIR` подменяет каталог баз (`service_probes.json`, `cve_map.json`) — так можно вести свою, более актуальную базу CVE. Шаблон плагина — в разделе [Lua API](#lua-api-плагинов).

---

## Правовой статус и правила использования

Sleipnir — инструмент аудита, разработанный в учебных целях для лабораторных и учебных стендов. Он выполняет активные сетевые запросы, поэтому его применение регулируется следующими правилами.

**Разрешённое применение.** Сканирование систем, которыми вы владеете или на которые получили **явное документированное разрешение** владельца: собственные стенды, виртуальные машины, учебные полигоны, целевые системы в рамках договора о тестировании на проникновение (rules of engagement фиксируют цели, окна и интенсивность).

**Запрещённое применение.** Любое сканирование, включая разведку, без разрешения владельца. В РФ несанкционированный доступ к компьютерной информации образует состав преступления (ст. 272 УК РФ); смежные действия — ст. 273 и 274 УК РФ. Аналогичные нормы есть в большинстве юрисдикций (CFAA в США, Computer Misuse Act в Великобритании). IP-адрес оператора фиксируется в логах целевых систем.

**Ограниченная агрессивность.** Проверки по умолчанию неинвазивны: TCP-подключения, чтение баннеров, HTTP GET/OPTIONS/TRACE, TLS-хэндшейки. Модуль проверки устойчивости (`--fuzz`) отправляет заведомо некорректные данные и способен вызвать отказ сервиса — он **выключен по умолчанию** и предназначен только для стендов, восстановление которых оператор контролирует. Режим `--safe` гарантирует неинвазивное поведение.

**Отказ от гарантий.** ПО распространяется «как есть». Отсутствие находок не означает отсутствие уязвимостей: сигнатурный подход покрывает только известные проблемы, и корректность зависит от актуальности базы CVE. Выводы сканера — входные данные для проверки человеком, а не заключение об уровне безопасности.

**Обращение с результатами.** Отчёты содержат сведения, применимые для атаки. Храните и передавайте их с уровнем защиты, соответствующим чувствительности исследованных систем, и используйте по назначению — для устранения найденных недостатков.

---

## Возможности

<table>
<tr><th>Модуль</th><th>Что делает</th></tr>
<tr><td><b>Разведка</b></td><td>IP-литералы, CIDR (<code>10.0.0.0/24</code>), DNS-имена, URL-ввод; порты <code>top100</code>, списки и диапазоны; пул из 32 воркеров, все операции с таймаутами</td></tr>
<tr><td><b>Fingerprinting</b></td><td>Декларативная таблица проб в духе nmap: NULL-проба + активные пробы (HTTP, Redis, PostgreSQL, MongoDB, IRC) и бинарные протоколы (MySQL, VNC, telnet); 12+ типов сервисов, извлечение продукта и версии</td></tr>
<tr><td><b>CVE-матчинг</b></td><td>Локальная база: <b>31 продукт, 95 записей</b> (OpenSSH, vsftpd, Apache, nginx, OpenSSL, MySQL, PostgreSQL, Redis, Tomcat, PHP, WordPress, Jenkins, Grafana, Elasticsearch, CouchDB, Webmin, Exchange…), constraint-язык версий (<code>&lt;9.8p1</code>, <code>&gt;=1.0 &lt;2.0</code>); стек технологий собирается из <code>Server</code> и <code>X-Powered-By</code></td></tr>
<tr><td><b>TLS-аудит</b></td><td>Хэндшейк на TLS-портах с SNI; сертификат: срок (+окно 14 дней), самоподписанность, доверие цепочке, соответствие имени; активный детект TLS 1.0/1.1/SSL 3.0</td></tr>
<tr><td><b>HTTP-аудит</b></td><td>Раскрытие версии в <code>Server</code> и <code>X-Powered-By</code>, directory listing, security-заголовки (CSP, XCTO, XFO), пермиссивная CORS, cookie без Secure/HttpOnly/SameSite, чувствительные пути (<code>/.git</code>, <code>/.env</code>, <code>/.aws/credentials</code>, <code>/phpinfo.php</code>…), методы TRACE/OPTIONS</td></tr>
<tr><td><b>Web-app probes</b></td><td>Контентные проверки приложений: GraphQL introspection, Spring Boot actuator, OpenAPI/Swagger-документация, <code>package.json</code> в web-root, ограниченный SQLi-детект по ошибкам драйверов БД (строгие маркеры, без ложных срабатываний на 500-страницах)</td></tr>
<tr><td><b>Lua-плагины</b></td><td>Хуки <code>on_port_open</code>/<code>on_service</code>/<code>on_http_response</code>; API: TCP, HTTP, HTTPS, TLS-инспекция; каждый плагин — отдельный <code>lua_State</code> без <code>io</code>/<code>os.execute</code>/<code>require</code>. В комплекте 10 проверок: неавторизованный Redis, открытый Docker API, SMTP VRFY, CORS-рефлексия, пользователи WordPress, security.txt, анонимный FTP, открытый relay, directory listing, админ-панели</td></tr>
<tr><td><b>Robustness</b></td><td>Проверка устойчивости к некорректному вводу: детерминированный ограниченный корпус payload'ов, темповый контроль, верификация отказа переподключением; opt-in (<code>-f</code>)</td></tr>
<tr><td><b>Отчётность</b></td><td>Цветная консоль, машиночитаемый JSON, самодостаточный HTML с распределением по критичности; <code>--fail-on SEVERITY</code> — код возврата 3 для CI/CD</td></tr>
<tr><td><b>Оболочка</b></td><td>REPL с историей и персистентными настройками сессии; Ctrl+C прерывает скан, не выходя из оболочки</td></tr>
</table>

---

## Использование

```
sleipnir [OPTIONS] [SUBCOMMAND]
  -i, --interactive  Интерактивная оболочка (по умолчанию на TTY)
  --plugins DIR      Каталог плагинов
  --list-plugins     Загрузить плагины, показать статус и выйти
  -V, --version      Версия

sleipnir scan <targets...> [OPTIONS]
  -p, --ports SPEC       Порты: 'top100', список или диапазоны (по умолчанию top100)
  -t, --threads N        Число воркеров (по умолчанию 32)
      --timeout MS       Таймаут операции, мс (по умолчанию 2500)
      --no-plugins       Отключить Lua-движок
      --data DIR         Каталог данных: probes, CVE db (по умолчанию 'data')
  --no-tls               Отключить TLS-аудит
  --tls-ports SPEC       Порты для TLS-хэндшейка (по умолчанию 443,465,636,993,995,8443,…)
  --safe                 Неинвазивный режим (переопределяет -f)
  --delay MS             Пауза между заданиями на воркере
  --user-agent STR       HTTP User-Agent
  -f, --fuzz             Включить модуль проверки устойчивости
      --fuzz-max-len N   Максимальный размер payload (по умолчанию 8192)
      --fuzz-delay MS    Пауза между payload'ами, мс (по умолчанию 20)
      --report FILE      Отчёт: .html/.htm -> HTML, иначе JSON
      --fail-on SEV      Код 3 при находках уровня SEV и выше (low|medium|high|critical)
  -v, --verbose          Подробный вывод
```

Коды возврата: `0` — завершено (находки ниже порога), `1` — ошибка выполнения, `2` — ошибка использования, `3` — сработал `--fail-on`.

```bash
# Подсеть, HTML-отчёт для отчётности
sleipnir scan 192.168.1.0/24 -p 22,80,443,3306 --report report.html

# TLS-аудит веб-сервера по имени (SNI, проверка сертификата)
sleipnir scan intranet.example.test -p 443,8443

# CI/CD: сборка падает при находках уровня medium и выше
sleipnir scan 127.0.0.1 -p 80,443 --fail-on medium
```

Скан прерывается `Ctrl+C` с печатью частичных результатов; в оболочке скан можно перезапустить сразу.

---

## Методология

Каждая находка имеет проверяемое обоснование (`evidence`) и источник (`source`: `cve-db`, `builtin`, `tls`, `plugin:<name>`, `fuzz`).

- **Пассивные и неинвазивные проверки** (по умолчанию): чтение баннеров, активные пробы протоколов, HTTP GET/OPTIONS/TRACE, TLS-хэндшейки.
- **Подтверждение находок**: exposed-пути требуют кода 200 и контрольного маркера в теле; CVE-матч — точной версии из баннера/заголовка; устаревший TLS — успешно завершённого хэндшейка, зафиксированного на этой версии.
- **Контроль ложных срабатываний**: в мок-лабе порт 2502 эмулирует корректно настроенный SMTP и не должен давать находок — негативный тест прогоняется при каждой регрессии.
- **Критичность** наследует CVSS из CVE-базы; конфигурационные недостатки градируются по стандартной практике (exposed credentials — high, directory listing — medium, security-заголовки — low).
- **Модуль устойчивости** детерминирован (фиксированное зерно ГПСЧ), ограничен (`--fuzz-max-len`), темп контролируется (`--fuzz-delay`); отказ сервиса фиксируется только после неудачного переподключения.

---

## Архитектура

```
apps/sleipnir/main.cpp        CLI (CLI11), REPL, сигналы, авто-поиск data/plugins
libs/sleipnir/
  src/targets.cpp             Расширение таргетов и портов, DNS-резолв
  src/netio.cpp               TcpClient: async-Asio под блокирующим API, таймауты
  src/tls_client.cpp          TlsClient: asio::ssl + извлечение сертификата (OpenSSL)
  src/tls_checks.cpp          Аудит сертификата и legacy-протоколов TLS
  src/probes.cpp              ProbeDb: таблица проб + regex-fingerprinting
  src/http_client.hpp         HTTP/1.1 клиент (шаблон поверх TCP/TLS), chunked-декодер
  src/checks.cpp/.hpp         Встроенные проверки веб-мисконфигураций
  src/cve_db.cpp              Загрузка и матчинг CVE-базы (constraint-язык версий)
  src/plugins.cpp             Lua-хост: песочница, хуки, API плагинов
  src/fuzz.cpp                Payload-корпус и верификация отказов сервиса
  src/engine.cpp              ScanEngine: очередь задач + пул воркеров, пайплайн
  src/report.cpp              Консольный, JSON и HTML отчёты
data/                         service_probes.json · cve_map.json
plugins/                      Примеры Lua-плагинов
tools/mocklab/                Мок-лаборатория уязвимых сервисов
tests/                        Юнит-тесты (doctest)
.github/workflows/release.yml  Сборка и публикация релиза
```

Пайплайн одного job'а: **connect → probes (fingerprint) → CVE matching → TLS-аудит (TLS-порты) → `on_port_open` → HTTP-проверки + `on_http_response` → `on_service` → robustness (opt-in)**.

Каждый воркер владеет своим `io_context` и транспортами; разрыв соединения во время проб (peer EOF) детектируется и вызывает переподключение — fingerprinting устойчив к сервисам, отвечающим фатальной ошибкой и закрывающим соединение. `ScanEngine::request_stop()` атомарно останавливает воркеры и модуль устойчивости; флаг сбрасывается перед каждым запуском.

TLS-слой включается для портов из `--tls-ports`, когда plaintext-пробы не идентифицировали сервис: хэндшейк (с SNI для имён), извлечение сертификата, его проверка, затем полный HTTP-пайплайн поверх TLS.

### Lua API плагинов

```lua
-- plugins/my_check.lua
function on_http_response(ctx)
    if ctx.http_status == 200 and ctx.http_body:find("SECRET") then
        sleipnir.add_finding{
            title = "Secret leaked on front page",
            severity = "high",
            description = "The word SECRET appears in the response body.",
            evidence = ctx.http_body:sub(1, 100),
        }
    end
end
```

`ctx` = `{host, port, service, product, version, banner, http_status, http_headers, http_body}`.

| Функция | Описание |
|---|---|
| `sleipnir.tcp_connect(host, port)` | TCP-соединение → `conn` (`:send`, `:read(wait_ms)`, `:close`) |
| `sleipnir.http_get(host, port, path)` | HTTP GET → `{status, headers, body}` |
| `sleipnir.https_get(host, port, path)` | То же поверх TLS |
| `sleipnir.tls_info(host, port)` | `{protocol, cipher, subject, issuer, not_before, not_after, self_signed, chain_trusted, hostname_match}` |
| `sleipnir.add_finding{...}` | Находка: `title`, `severity`, `description`, `evidence`, `port`/`cve` (опц.) |
| `sleipnir.log(msg...)` | Строка в лог сканера |

Это ограничение окружения, а не криптографическая песочница: плагин исполняется с привилегиями процесса — запускайте только плагины, которые прочитали и поняли.

### Форматы отчётов

```json
{
  "meta":     { "tool": "sleipnir", "version": "...", "elapsed_seconds": ..., "config": {...} },
  "stats":    { "hosts": ..., "open_ports": ..., "findings": ... },
  "targets":  [ { "host", "port", "service", "product", "version", "banner", "http", "tls" } ],
  "findings": [ { "host", "port", "severity", "title", "cve", "source", "description", "evidence" } ]
}
```

HTML-отчёт — самодостаточный документ с inline-CSS: сводка по критичности, таблица находок с обоснованием, эндпоинты с TLS-деталями.

---

## Мок-лаборатория

Двенадцать слушателей на `127.0.0.1` (stdlib Python + системный `openssl`), воспроизводящих типовые уязвимые конфигурации:

```bash
python3 tools/mocklab/mock_services.py
sleipnir scan 127.0.0.1 -p 2101,2102,2201,2375,2501,2502,2503,6380,8080,8081,8443 -f --report report.html
```

| Порт | Сервис | Что эмулирует | Ожидаемый результат |
|---|---|---|---|
| 2101 | FTP | vsftpd 2.3.4 | CVE-2011-2523 (critical) |
| 2102 | FTP | vsftpd 3.0.2, анонимный вход | CVE-2015-1419 + плагин |
| 2201 | SSH | OpenSSH 7.2p2 | CVE-2024-6387, CVE-2023-38408 и др. |
| 2375 | Docker API | Engine API без TLS/auth | плагин docker_api_unauth (critical) |
| 2501 | SMTP | Postfix, открытый relay + VRFY | плагины smtp_openrelay, smtp_vrfy |
| 2502 | SMTP | Postfix, relay закрыт, VRFY отключён | ничего — **негативный тест** |
| 2503 | echo | отказ от payload > 1024 байт | robustness → critical |
| 6380 | Redis | Redis 6.0.16 без аутентификации | CVE-2022-0543 + плагин (critical) |
| 8080 | HTTP | Apache 2.4.49, dir listing, `/.git`, `/.env` | CVE-2021-41773 + builtin |
| 8081 | WordPress | WP 5.8.1 / PHP 7.2.24 / nginx 1.18.0, REST-пользователи, CORS-рефлексия | CVE nginx + PHP + WordPress + 3 плагина |
| 8082 | SPA | GraphQL introspection, Spring actuator, OpenAPI, `package.json`, SQL-ошибка в поиске | web-app probes: SQLi (high), actuator (high), GraphQL (medium) |
| 8443 | HTTPS | то же поверх TLS, самоподписанный сертификат (CN=mock.lab, 1 день) | CVE + TLS-находки |

---

## Sleipnir рядом с классикой

Честная позиция: Sleipnir не заменяет nmap и Metasploit и не претендует на их место. Это самостоятельный сканер аудита с конвейером «разведка → оценка → отчёт».

| | **nmap** | **Sleipnir** |
|---|---|---|
| Скан портов | SYN/UDP/ACK-сканы, тысячи хостов в секунды | TCP connect-скан, пул воркеров — медленнее, но без raw-сокетов и привилегий root |
| Fingerprinting | ~1200 проб, детект ОС | 7 проб, 12+ сервисов — расширяемы декларативно, в JSON |
| Скриптование | NSE (~600 скриптов) | Lua-плагины с TLS-инспекцией в API |
| Отчёты | XML/grepable | JSON + самодостаточный HTML |
| Декодирование TLS/сертификатов | нет (это делает sslscan/тестssl) | встроено |
| Код | ~150k строк | ~3.5k строк, читается за вечер |

| | **Metasploit** | **Sleipnir** |
|---|---|---|
| Назначение | эксплуатация уязвимостей | обнаружение (по design без эксплойтов) |
| Категория | фреймворк пентеста | сканер аудита — сосед Nessus/OpenVAS в миниатюре |
| Безопасность применения | payload'ы меняют состояние цели | проверки по умолчанию read-only, `--safe` как политика |

**Где Sleipnir хорош:** быстрый аудит своих лабораторных стендов и учебных полигонов, интеграция в CI/CD (`--fail-on`), основа для экспериментов — весь код помещается в голове, а базы знаний расширяются правкой JSON.

---

## Расширение и ограничения

- **Новые сервисы/сигнатуры** — проба и regex-правила в `data/service_probes.json` (без перекомпиляции; специфичные правила — раньше общих).
- **Новые CVE** — записи в `data/cve_map.json`: ключ — алиас баннера, `aliases` — написания, `vulns` — `{cve, affected, cvss, summary}`.
- **Новые проверки** — Lua-плагин; то, что должно быть быстрым и компилируемым, — в `checks.hpp`.

Известные рамки: сигнатурный детект (версию, скрытую в баннере, не матчит), без аутентификации в приложениях, TCP only, SMB/RPC не пробируются. Дорожная карта: master/worker-раздача целей по сети, TLS-аудит всех портов, экспорт SARIF, diff между запусками.

## Проект

Sleipnir v0.5.0 — это самостоятельный проект по информационной безопасности: асинхронный сетевой движок на Asio, интеграция Lua (sol2), декларативные базы знаний с языком ограничений версий, TLS-инспекция на OpenSSL и методика самотестирования на воспроизводимом полигоне с негативными тестами.
