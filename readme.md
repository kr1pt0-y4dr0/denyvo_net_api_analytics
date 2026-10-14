# Отчёт о тестировании на проникновение платформы `games-launcher.top`

**Дата тестирования:** 13 октября 2026 г.  
**Тип тестирования:** Black-box, внешний пентест (правило engagement: без DoS и без брутфорса учётных данных)  
**Цели:** `https://games-launcher.top` (+ поддомены), IP `2.56.214.209` (публичный), порты 21/22/80/443/8443  
**Исполнитель:** По согласованию с владельцем платформы. Тестирование выполнено с публичного адреса, локальный адрес `192.168.100.102` недоступен

---

## 1. Область тестирования

- Домен и поддомены (обнаружены в ходе теста через CT-логи, ранее в области не были):
  - `games-launcher.top` (основной сайт, `api.php`)
  - `www.games-launcher.top`
  - `api.games-launcher.top` (отдельный токен-API)
  - `support.games-launcher.top` (vhost-заглушка)
  - `apibot.support.games-launcher.top` (Anubis anti-bot + SPA «OTP Активатор» + Go API `/api/v2`)
- Порты: 21 (FTP/ProFTPD), 22 (SSH/OpenSSH), 80 (HTTP), 443 (HTTPS), 8443 (CloudPanel)
- Админ-панель: `https://games-launcher.top/mngr/`
- CloudPanel: `https://games-launcher.top:8443/`

**Модель тестирования:** black-box, неавторизованный пользователь. Для подтверждения BOLA в `reqcreds` использован существующий логин аккаунта (без входа в сервис; само значение не приводится). Аутентифицированный контур (панель `/mngr/`, эскалации, CSRF на авторизованных вызовах) — бэклог Фазы 2.

---

## 2. Методология и инструментарий

- `nmap` (+NSE-скрипты: `ftp-anon`, `ftp-syst`, `ssh2-enum-algos`, `ssh-auth-methods`, `ssl-enum-ciphers`)
- `curl`, `openssl s_client`, `sslscan` — TLS/заголовки
- `ffuf` — фаззинг путей и действий API
- `nuclei` (5705 шаблонов: cve/exposure/misconfig/default-login/tech) — 0 находок
- `sqlmap` (уровень 2/риск 1, задержки) — инъекций не выявлено
- `python3` (requests/httpx/aiohttp) — оракул `reqcreds`, скрипты API-контракта, прохождение Anubis (metarefresh)
- `whatweb`, `whois` (DNS-среда ограничена), пассивный OSINT (CT-логи `certspotter`)
- Параллельные субагенты для независимых потоков (панель `/mngr/`, поддомены `support`/`apibot`)

---

## 3. Сводка уязвимостей

| № | Уязвимость | Уровень риска | Статус |
|---|------------|---------------|--------|
| 1 | User enumeration через `api.php?act=checkAccount` | **High** | Подтверждено (повторно) |
| 2 | Отсутствие rate-limit на API `api.php` | **High** | Подтверждено |
| 3 | CloudPanel 2.5.4 доступен из интернета на 8443 (self-signed, просрочен) | **High** | Подтверждено |
| 4 | Отсутствие HSTS (основной домен + все поддомены + CloudPanel) | **Medium** | Подтверждено (расширено) |
| 5 | Отсутствие CSRF-токена на форме входа `/mngr/login.php` | **Medium** | Подтверждено (частичная компенсация `SameSite=Strict`) |
| 6 | Отсутствие rate-limit на форме входа `/mngr/login.php` | **Medium** | Частично: блокировка есть, но привязана к сессии (см. 4.6) |
| 7 | Устаревший `X-XSS-Protection` | **Low** | Подтверждено |
| 8 | Фреймворк возвращает `200 OK` на неизвестные роуты | **Low** | Подтверждено |
| 9 | Рефлексия `login` в JSON-ответе (потенциальный XSS в webview) | **Low** | Подтверждено |
| 10 | Отсутствие ограничений на размер `hwid` | **Low** | Подтверждено |
| 11 | **BOLA в `reqcreds`**: данные аккаунта по одному логину, `hwid` не проверяется | **Critical** | Подтверждено (см. 4.11) |
| 12 | Отсутствие CSP | **Medium** | Подтверждено |
| 13 | Методы/Content-Type не ограничены на `api.php` (PUT/DELETE/PATCH, любой CT) | **Low** | Подтверждено |
| 14 | HTTP 500 на array-параметре `login` в `api.php` (необработанное исключение) | **Low** | Подтверждено |
| 15 | Session adoption в `/mngr/` (произвольный `PHPSESSID` принимается) | **Low** | Подтверждено |
| 16 | Нет CSRF-токена в `ajax.php`; ошибка авторизации возвращается как `200 OK` | **Low** | Подтверждено |
| 17 | Раскрытие поддоменов (`api.`, `support.`, `apibot.support.`) | **Info/Low** | Подтверждено |
| 18 | CloudPanel 2.5.4 содержит fix для известных CVE (2023-35885, 2024-44765, 2025-15241) | **Info** | Подтверждено анализом версии |
| 19 | Утечка source-map Anubis (`main.mjs.map`) | **Info** | Подтверждено |
| 20 | Дублирующиеся/конфликтующие security-заголовки | **Info** | Подтверждено |
| 21 | `/db.php` — пустой стаб (200/0 байт), вероятно, остаток отладки/конфигурации | **Info** | Подтверждено |
| 22 | Положительные инфраструктурные проверки (SSH publickey-only, TLS 1.2/1.3, FTP без анонима) | — | Проверено, уязвимостей нет |

---

## 4. Детали уязвимостей

### 4.1. User enumeration через `api.php?act=checkAccount` (High) — подтверждено повторно

Ответ для несуществующего логина:

```json
{"success":false,"errors":{"404":"ID <login> Not found"},"messages":[]}
```

Рефлексия логина в тело ответа. Полный перечень возможных действий API сведён к двум: `checkAccount` и `reqcreds` (фаззинг 224+90+75 словарных вариантов `act` — остальные `5001 Action unidentified`; регистр чувствителен). Действие `checkAccount` требует `login` (код `411`) и `hwid` (код `413`).

### 4.2. Отсутствие rate-limit на API (High)

50+ последовательных запросов к `api.php` — все `200`, без задержек и блокировок. Наблюдались лишь редкие транзиентные обрывы соединения при параллельных сканированиях (не WAF-блок).

### 4.3. CloudPanel 2.5.4 на порту 8443 (High — exposure)

- Версия из статики: `?v=2.5.4` (релиз 2026-07-01).
- Сертификат: self-signed `CN=cloudpanel.clp`, истёк 2020-10-13.
- Форма входа имеет CSRF-токен `_csrf_token` (Symfony); cookie `cloudpanel`/`locale` с `secure; httponly; samesite=lax`.
- Известные CVE (2023-35885, 2023-36630, 2023-46157, 2024-44765, 2025-15241) исправлены в версиях ≤ 2.5.2/2.4.2 → **2.5.4 не уязвима к публичным CVE**. Основная угроза — открытая панель хостинга (полный контроль сервера при компрометации), фаззинг и автоматизированные атаки.
- `nuclei` по шаблонам CloudPanel — 0 попаданий.

### 4.4. Отсутствие HSTS (Medium)

`Strict-Transport-Security` отсутствует на `games-launcher.top`, `api.`, `support.`, `apibot.support.` и CloudPanel `:8443`.

### 4.5. Отсутствие CSRF-токена на `/mngr/login.php` (Medium)

Форма: `method="POST" action=""`, поля `username`, `password`, hidden `redirect=index.php`, **без CSRF-токена**. Компенсация: `PHPSESSID` отдаётся с `SameSite=Strict`, что снижает (но не исключает) риск login-CSRF. Приведённое вводное значение не отражается; `username` отражается, но HTML-экранируется (XSS не подтверждён).

### 4.6. Rate-limit формы входа `/mngr/login.php` (Medium → фактически есть, но per-session)

- При **одной и той же сессии** блокировка появляется после ~5 попыток: «Слишком много попыток входа… подождите 3 минут», далее «…подождите 15 минут». → анти-брутфорс реализован.
- Первичный black-box-тест (без cookie, новая сессия на каждый запрос) показал 20× `200` без блокировки → **лимит, скорее всего, привязан к сессии (`PHPSESSID`), а не к IP**. Атакующий может обходить блокировку, меняя сессию → риск брутфорса остаётся.

### 4.7–4.10. (без изменений) Заголовки/200-роуты/рефлексия/размер `hwid`

Дополнительно подтверждено: рефлекция `login` с тегом `<script>` в JSON (Content-Type `application/json` — браузеры не выполнят, но при рендеринге в WebView лаунчера возможен XSS на стороне клиента). `hwid` = 1000 символов — `200`.

### 4.11. BOLA в `reqcreds` — раскрытие данных аккаунта без проверки `hwid` (Critical, подтверждён)

Действие `reqcreds` возвращает данные аккаунта по одному известному логину. Проверка `hwid`, призванная привязать запрос к конкретному устройству владельца, **не выполняется**: корректная и заведомо неверная `hwid` (`0`×32) дают идентичные ответы `success:true` с полем `result` (содержит `type`, `authlogin` и др.; конкретные значения в отчёте не приводятся — чувствительные).

Матрица ответов (неавторизованный пользователь, POST JSON):

| Payload (`act=reqcreds`) | HTTP | Ответ |
|---|---|---|
| без `act` | 200 | `{"errors":{"5001":"Action unidentified"}}` |
| `login` отсутствует / пустой / `0` | 200 | `{"errors":{"421":"\"login\" is null"}}` |
| `hwid` отсутствует / пустая / `0` | 200 | `{"errors":{"423":"\"hwid\" is null"}}` |
| `login`+`hwid` непустые, пользователь не существует | 200 | `{"success":false,"errors":[],"messages":[]}` |
| `login` существующий + `hwid` корректная | 200 | `{"success":true,"errors":[],"messages":["...All checks done! Nice gaming!"],"result":{...}}` |
| `login` существующий + `hwid` заведомо неверная (`0`×32) | 200 | **идентично предыдущему** — `success:true` + `result` |

В сочетании с user enumeration (`checkAccount`, разд. 4.1) это образует эксплуатируемую цепочку:

1. перечисление логинов через `checkAccount` (существующие отличаются по статусу/телу ответа);
2. `reqcreds` с произвольной непустой `hwid` → раскрытие данных аккаунта (`result`).

Никакой авторизации или привязки к устройству не требуется. Полные ответы и ред-актированная выдача сохранены в `evidence/reqcreds_check.out`.

Примечание по обработке входных данных: проверка полей основана на истинности (`if ($login && $hwid)`) — `login=0`/`hwid=0` трактуются как null (421/423); `login`-массив → HTTP 500 пустое тело (необработанное исключение, разд. 4.14); `hwid`-объект JSON принимается (200, baseline).

### 4.12. Отсутствие CSP (Medium)

`Content-Security-Policy` не отдаётся ни одним узлом. Плюс к дефенсу от XSS/внедрения отсутствует второй рубеж.

### 4.13. Методы/Content-Type не ограничены на `api.php` (Low)

`PUT/DELETE/PATCH/HEAD` обрабатываются так же, как `POST`; JSON-тело парсится при любом `Content-Type` (вплоть до отсутствующего). HTTP-семантика не соблюдается — риск для промежуточных компонентов/кэшей.

### 4.14. HTTP 500 на array-параметре `login` (Low)

`login` как JSON-массив → **HTTP 500, пустое тело** (необработанный типизированный вызов в PHP 8.x при `display_errors=off`). Симметричный кейс `hwid`-объект принимается и возвращает обычный `200 baseline` — исключение зависит от конкретного кода поля.

```bash
curl -k -X POST https://games-launcher.top/api.php -H 'Content-Type: application/json' \
  -d '{"act":"reqcreds","login":["x"],"hwid":"0","pc":"1"}'
# → HTTP 500, пустое тело
```

Аналогично на форме входа `/mngr/login.php` (`username[]=a` → 500).

### 4.15. Session adoption в `/mngr/` (Low)

Сервер принимает произвольный клиентский `PHPSESSID` и не перевыдаёт его (нет `Set-Cookie`). Успешная фиксация сессии **не подтверждена** (нужен вход с тестового аккаунта). Флаги: `path=/; secure; HttpOnly; SameSite=Strict`.

### 4.16. `ajax.php` без CSRF и с некорректным статусом ошибок (Low)

JSON-API панели (`/mngr/ajax.php`) с действиями `logs_list`, `clients_list`, `user_create/user_update/user_delete`, `client_make_unlimited/client_delete/client_reset`. Все действия за гейтом авторизации, но возвращают `HTTP 200 {"ok":false,"error":"Not authenticated"}` вместо 401/403; CSRF-токена нет.

### 4.17. Раскрытие поддоменов (Info/Low)

CT-логи (`api.certspotter.com`) показывают `api.`, `support.`, `apibot.support.` — целевые поддомены не были в изначальном scope. `api.` — отдельный токен-API с глобальным гейтом (POST → 401; `Authorization`/`X-Api-Token`; CORS `ACAO: *` без credentials → не эксплуатируется). Обход авторизации не найден (после заголовков `X-Forwarded-For`/`X-Original-URL` и пр. — 401).

### 4.18. `apibot.support` (Info/Low)

- Anubis v1.27.0 закроет challenge (metarefresh, без PoW) — валидная JWT-сессия получается; CVE-2026-62314 (X-Original-URI bypass) к 1.27.0 не применим.
- За Anubis: Vue 3 SPA «OTP Активатор» + Go API `/api/v2`:
  - `GET /api/v2/device/challenge` (X-Device-Id) — `InvalidDeviceId` (400) / `DeviceNotRegistered` (401)
  - `POST /api/v2/device/register` — строгая валидация ключа активации (ошибка «activationKey must be a valid…» обрезается сервером)
  - `POST /api/v2/otp/activate` / `otp/response` — порядок проверок: timestamp → signature → nonce
  - Без валидного ключа активации/зарегистрированного устройства дойти до ответа невозможно → без перебора ключей дальше не протестировать.
- Утечка source-map `/.within.website/x/cmd/anubis/static/js/main.mjs.map` (38 КБ, публичный код Anubis) — INFO.
- Дублирующиеся заголовки (`X-Frame-Options: DENY` + `SAMEORIGIN`, два разных `Referrer-Policy`) — INFO.

### 4.19–4.21. Прочее (Info)

- Поддерживаемый API не воспринимает XML (XXE не подтверждён), cache deception (`/api.php/foo.css`, `/api.php%3F...`) — nginx 404.
- `/db.php`: `200`, пустое тело для всех методов/параметров.
- `robots.txt` — `Disallow: /` + нестандартная директива `DisallowAITraining: /`.

---

## 5. Проверено и уязвимостей не выявлено

- **SQL-инъекции**: маркеры в `login`, ручной анализ + `sqlmap` (level 2, risk 1, в т.ч. time-based/UNION) — не найдено.
- **XXE**: XML-тело игнорируется (`5001`), не парсится.
- **SSTI / command injection / NoSQL** в параметрах `api.php` — поведение идентично базовому.
- **CORS**: `api.php` — без `ACAO`; `api.` — `ACAO: *` без `credentials` (неэксплуатируемо); `apibot` — `allow-credentials: true`, но без отражения `Origin`.
- **Host header injection**: неизвестный Host → `421 Misdirected Request` (nginx default) на основном домене; на 8443 default vhost отдаёт login — атаки cache poisoning/redirect не найдены.
- **Open redirect** (параметр `redirect` формы входа) — не отражается, не подтверждён.
- **Path traversal / dotfiles**: `.git`, `.svn`, `.htaccess` и др. — 403 (nginx); бэкапы, `composer.json`/`package.json`, source maps (кроме Anubis), `phpinfo`, `install/`, `setup/`, `adminer` — отсутствуют.
- **Ограничения Anubis**: обход challenge не найден; `robots.txt`/`.well-known`/`favicon.ico` проходят allowlist (по дизайну).
- **Cache deception / HTTP request smuggling**: cache-атаки не подтверждены; smuggling не тестировался боевыми payload'ами (по правилам).
- **FTP**: анонимный вход запрещён (`530`). **SSH**: только `publickey`, современные алгоритмы → брутфорс исключён, слабостей нет.
- **TLS 443**: только TLSv1.2/1.3, PFS, RSA-4096, валидный Let's Encrypt (2026-09-25 … 2026-12-24) — слабостей не выявлено.
- **Nuclei** (5705 шаблонов, включает CVE/exposures/misconfig/default-login) — 0 совпадений.

## 5A. Дополнительные проверенные векторы (матрица)

| Вектор | Метод/инструмент | Результат | Статус |
|---|---|---|---|
| Фаззинг `act` в `api.php` (224+90+75 слов) | ffuf+curl | живы только `checkAccount`, `reqcreds` | Подтверждено |
| Оракул `reqcreds` (login × hwid) | python/curl | `success:false/errors[]` для несуществующих; `success:true`+`result` для существующего при **любой** `hwid` | Подтверждено (BOLA) |
| Поддомены/CT | certspotter/dns | `api`, `support`, `apibot.support` | Подтверждено |
| Session fixation / adoption `/mngr/` | curl | adoption подтверждён; фиксация — нет | Частично |
| Password-reset-флоу `/mngr/` | curl (13 имён) | отсутствует | Не подтверждено |
| `ajax.php` hidden-actions | разбор JS | 7 действий, все за auth | Подтверждено |
| Anubis bypass (CVE-2026-62314, статика, API) | python | не пройден; allowlist по дизайну | Не подтверждено |
| API-контракт `apibot /api/v2` | python | строгая валидация; тупик без ключа | Подтверждено |
| Race condition (лёгкие на `checkAccount`) | aiohttp | не выполнялось массово (без DoS) | Не применимо |
| Десериализация (cookie/параметры) | анализ | PHP-сериализации/JWT в public-контуре не обнаружено | Не подтверждено |

## 5B. Векторы, требующие аутентифицированного контура (Фаза 2, бэклог)

> BOLA в `reqcreds` уже подтверждён (разд. 4.11). Ниже — оставшиеся пункты, требующие входа в сервис:

1. Горизонтальная/вертикальная эскалация в `/mngr/` и `ajax.php` (`user_*`, `client_*`).
2. Полный состав поля `result` в `reqcreds` (наличие токенов/паролей) и любых write-действий в контуре лаунчера.
3. Регенерация `PHPSESSID` при успешном входе (Session Fixation).
4. CSRF на авторизованных AJAX-действиях; семантика status-кодов.
5. Open redirect через `redirect` (после авторизации).
6. Оформление устройств/OTP-активаций на `apibot` с валидным ключом (проверка бизнес-логики, повторное использование nonce, replay).
7. Проверка ротации/повторного использования API-токенов `api.games-launcher.top`.

---

## 6. Рекомендации по устранению

### Критичные и высокие:
1. Устранить user enumeration в `api.php` (общие сообщения об ошибках, без рефлексии логина; rate-limit 5-10 req/min/IP).
2. Rate-limit на всех публичных эндпоинтах, **привязанный к IP**, не только к сессии (см. 4.6).
3. Закрыть CloudPanel (8443) из интернета (VPN/белый список), заменить self-signed сертификат; контролировать обновления.
4. Устранить BOLA в `reqcreds` (Critical): сервер должен подтверждать, что `hwid` принадлежит указанному логину (и текущей сессии устройства), а `result` отдавать только владельцу; ввести аутентификацию/контроль доступа для действия. До устранения не выпускать лаунчер/сервис.

### Средние:
5. Добавить `Strict-Transport-Security` (+ на все поддомены и 8443).
6. Добавить `Content-Security-Policy` (и на `/mngr/`, и на CloudPanel-заголовки).
7. CSRF-токены на формы `/mngr/` и AJAX-вызовы; корректные HTTP-status для ошибок авторизации (401/403).
8. Убрать `X-XSS-Protection`, упорядочить дублирующиеся заголовки (nginx vs app).
9. Использовать строгие проверки типов параметров (устранить HTTP 500 на массивах).
10. Ограничить длину/маску `hwid` и `login`.
11. Удалить `/db.php` или защитить; убрать лишние директивы `robots.txt`.

### Низкие:
12. Source maps (Anubis) — отключить в проде.
13. Мониторинг и логирование подозрительной активности; уведомления о новых поддоменах (CT).
14. Документированное правило engagement, резервирование тестового аккаунта для Фазы 2.

---

## 7. Приложение. Использованные команды (ключевые)

```bash
# Порты и сервисы (с -n, т.к. без него nmap зависал на резолве)
nmap -n -sS -p- -T3 --open 2.56.214.209
nmap -n -sV -sC -p21,22,80,443,8443 2.56.214.209
nmap -n -p21 --script ftp-anon,ftp-syst 2.56.214.209
nmap -n -p22 --script ssh2-enum-algos,ssh-auth-methods --script-args='ssh.user=admin' 2.56.214.209

# Поддомены через CT
curl -s 'https://api.certspotter.com/v1/issuances?domain=games-launcher.top&include_subdomains=true&expand=dns_names'

# Фаззинг действий API
ffuf -w /usr/share/seclists/Discovery/Web-Content/api/actions.txt -u https://games-launcher.top/api.php \
  -X POST -H 'Content-Type: application/json' -d '{"act":"FUZZ","hwid":"x","login":"test","pc":"x"}' \
  -mc all -fr '"5001"' -rate 30 -t 5

# Оракул reqcreds
curl -k -X POST https://games-launcher.top/api.php -H 'Content-Type: application/json' \
  -d '{"act":"reqcreds","login":"test","hwid":"x","pc":"x"}'

# PoC: BOLA reqcreds — существующий логин + ЛЮБАЯ непустая hwid (значение hwid не проверяется).
# (login подставьте свой/перебор по enumeraton; полный вывод см. evidence/reqcreds_check.out)
curl -k -s -X POST https://games-launcher.top/api.php -H 'Content-Type: application/json' \
  -d '{"act":"reqcreds","login":"<LOGIN>","hwid":"00000000000000000000000000000000","pc":"win10"}' \
  | python3 -m json.tool

# Цепочка: перечисление через checkAccount (существующий логин отвечает НЕ "404 ID ... Not found")
curl -k -s -X POST https://games-launcher.top/api.php -H 'Content-Type: application/json' \
  -d '{"act":"checkAccount","login":"<LOGIN>","hwid":"0","pc":"win10"}'

# Type juggling (500)
curl -k -X POST https://games-launcher.top/api.php -H 'Content-Type: application/json' \
  -d '{"act":"reqcreds","login":["test"],"hwid":{"a":1},"pc":1}'

# Nuclei (точечно)
nuclei -l nuclei_targets.txt -tags cve,exposure,misconfig,default-login,tech -severity medium,high,critical -rl 40 -c 25

# Anubis pass (apibot)
python3 anubis_pass.py https://apibot.support.games-launcher.top

# CloudPanel version marker
curl -k -s https://games-launcher.top:8443/login | grep -o 'v=2.5.4'
```

---

## 8. Приложение. Артефакты

`/home/kali/Documents/pentest/evidence/`:
- `dns.txt`, `subdomains.txt`, `subdomains2.txt` — DNS/поддомены
- `sslscan.txt`, `cert.txt`, `chain.txt`, `headers.txt` — TLS/заголовки
- `root.txt`, `wellknown.txt`, `root_curated.txt`, `ffuf_*` — веб-поверхность
- `act_results.txt`, `act_camel_hits.txt`, `username_enum.txt` — API-тесты
- `reqcreds_check.out` — подтверждение BOLA (ред-актированный вывод oracle-проверки)
- `nmap_ports.gnmap`, `nmap_services.txt` — порты/сервисы
- `nuclei_hits.txt` — nuclei (0)
- `api_req.txt`, `sqlmap_out.txt`, `/tmp/sqlmap.log` — SQLi
- `mngr/` — артефакты панели (login/failed_body.html, js_*.js, ffuf_php.json, SUMMARY.md)
- `support/` — артефакты поддоменов (EVIDENCE_NOTES.md, apibot_*.js, `apiapi/results.txt`)

---

**Вывод:** подтверждена **критическая** BOLA-уязвимость в `reqcreds` (аккаунт-данные по логину без проверки `hwid`, эксплуатируется в связке с user enumeration через `checkAccount`). Также сохраняются High-находки (user enumeration, отсутствие IP-rate-limit, открытый CloudPanel). Расширенная фаза выявила недокументированные поддомены и отдельный токен-API; публичные CVE закрыты (CloudPanel 2.5.4, Anubis 1.27.0), SSH/TLS настроены строго. До устранения пунктов 1–4 раздела 6 (особенно BOLA в `reqcreds`) рекомендуется не выпускать обновления лаунчера и сервиса. Аутентифицированный контур — бэклог Фазы 2.

*Отчёт составлен по результатам black-box тестирования неавторизованного пользователя с публичного адреса. Для подтверждения BOLA использовался существующий логин аккаунта без входа в сервис; значения аккаунта и логина в отчёте не приводятся.*