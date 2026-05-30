# kamienclave — Технический дизайн-документ

Версия: 0.3 (draft)
Статус: клиент и сервер реализованы; сервер вынесен в приватный репозиторий kamienclave-backend
Дата: 2026-06-01

---

## 1. Назначение

`kamienclave` — CLI-утилита (бинарь `enclave` / `enclave-vm`), которая по предъявлении валидной лицензии получает с
сервера актуальный защищённый payload, исполняет его исключительно в
оперативной памяти встроенным runtime'ом и по завершении сессии стирает
рабочие буферы. Локально исходная логика payload не сохраняется ни в каком
виде. Каждый запуск = повторный поход к серверу. Поставляемый клиенту
артефакт (в т.ч. Docker-образ) — это **инертный загрузчик**: без живой
валидной лицензии он не содержит и не может получить ценную логику.

Программный комплекс состоит из:

1. **kamienclave-client** — настоящий репозиторий. CLI-бинарь, который
   распространяется лицензированным пользователям.
2. **kamienclave-backend** — приватный отдельный репозиторий. HTTP-сервис,
   хранящий лицензии, публичные ключи клиентов и репозиторий собранных
   `index.js` payload'ов. Документируется отдельно.
3. **kamienclave-proto** — общий минимальный модуль с DTO и константами
   протокола, подключаемый обоими репозиториями как зависимость.

Существует две независимые сборки клиента:

| Сборка     | Назначение                                                                 | Видимость |
| ---------- | -------------------------------------------------------------------------- | --------- |
| `public`   | Демонстрация, awareness, выдача артефактов для маркетинга/документации     | open      |
| `backend`  | Боевая утилита с полным набором hardening-механик и анти-аналитикой        | closed    |

`public`-сборка использует упрощённый payload-канал (например, заглушку
сервера или public-only payload'ы) и **не** содержит чувствительной
backend-логики. Реализуется в отдельном репозитории, повторно использует
`kamienclave-proto`.

### 1.1. Цель защиты и принцип

Базовый принцип, из которого исходит весь дизайн:

> Код, исполняемый на машине клиента, **невозможно** сделать неизвлекаемым.
> Клиент — root в своём Docker-контейнере и на хосте: он может gdb-ить
> процесс, читать `/proc/<pid>/mem`, патчить бинарь. Docker — формат
> поставки, а **не** граница безопасности.

Поэтому цель kamienclave — **не секретность, а экономика**:

1. **Поднять стоимость извлечения** на порядки выше стоимости честной
   лицензии (тонкий загрузчик + серверная доставка + bytecode-payload +
   обфускация → извлечение требует квалифицированного RE в реальном времени,
   а не `unzip` образа).
2. **Сделать утечку трассируемой** — per-license watermarking (§8.4.1), чтобы
   утёкшую копию можно было привязать к лицензии и отозвать/преследовать.
3. **Сохранить контроль** — kill-switch, ротация payload, телеметрия на
   стороне сервера (часть защиты, не зависящая от client-side харденинга).

Анти-отладка и анти-дамп (§8.1–8.2) — это **speed bumps**: они отсекают
casual-копирование и замедляют автоматизированный дамп, но не считаются
несущей защитой и не должны создавать ложного ощущения секретности.

---

## 2. Глоссарий

- **License key** — публично известный лицензиару идентификатор + случайная часть, выдаваемая клиенту при покупке.
- **Client signing key** — приватный Ed25519-ключ клиента, которым клиент подписывает запросы. Хранится зашифрованно внутри бинаря, выданного сервером.
- **Server public verification key** — публичный Ed25519-ключ сервера, вшитый в каждый бинарь enclave для валидации ответов.
- **Session ECDH keypair** — эфемерная пара X25519, создаваемая клиентом на каждый запрос. Используется для гибридного шифрования payload.
- **Payload** — обфусцированный `index.js`, возвращаемый сервером.
- **In-memory runtime** — встроенный JS-интерпретатор (`goja`), исполняющий payload в адресном пространстве процесса enclave.

---

## 3. Высокоуровневая архитектура

```
                         +-----------------------------+
                         |        kamienclave-backend       |
                         |  (private repo)             |
                         |  - license DB               |
                         |  - clients pubkeys          |
                         |  - signed payload registry  |
                         +--------------+--------------+
                                        ^
                                        | HTTPS (TLS1.3)
                                        | + app-level AEAD
                                        | + request signatures
                                        v
                  +--------------------------------------------+
                  |              enclave / enclave-vm          |
                  |   (this repo, backend or public build)     |
                  |                                            |
                  |  +-------------+   +--------------------+  |
                  |  | license     |   | transport layer    |  |
                  |  | embedded    |   | (HTTP+ECDH+AEAD)   |  |
                  |  | priv key    |   +---------+----------+  |
                  |  +------+------+             |             |
                  |         |                    v             |
                  |  +------v---------+   +------+----------+  |
                  |  | request signer |   | response opener |  |
                  |  | (Ed25519)      |   | (AEAD verify)   |  |
                  |  +------+---------+   +------+----------+  |
                  |         |                    |             |
                  |         +--------+-----------+             |
                  |                  v                         |
                  |        +---------+-----------+             |
                  |        |   in-memory JS VM   |             |
                  |        |   (goja, ES5.1+)    |             |
                  |        +---------+-----------+             |
                  |                  |                         |
                  |        +---------v-----------+             |
                  |        |   hardening layer   |             |
                  |        | anti-debug/anti-dump|             |
                  |        | secure-zero/mlock   |             |
                  |        +---------------------+             |
                  +--------------------------------------------+
```

---

## 4. Компоненты клиента

### 4.1 Структура исходников

```
app/
  cmd/
    enclave/                  клиентский CLI (enclave / enclave-vm)
    enclave-server/           серверный CLI (см. §14)
    stamp/                    build-тул: дописывает integrity-трейлер (§8.3)
  internal/
    cliargs/                  парсинг аргументов и подкоманд
    config/                   таблица констант сборки (URL сервера, public keys)
    license/                  чтение вшитого приватного ключа, расшифровка passphrase'ом
    proto/                    DTO протокола + canonical (JCS), zero internal deps → готов к выносу
    protosign/                подписные обёртки над proto (Ed25519); держит зависимость вне proto
    crypto/
      sign/                   Ed25519 подпись/верификация
      kex/                    X25519 ECDH + HKDF-SHA256
      aead/                   AES-256-GCM обёртка
      zeroize/                безопасное стирание чувствительных байтов
    transport/                HTTP-клиент, ретраи, pinning сертификата сервера
    runtime/
      bytecode/               mini-VM: ISA, интерпретатор, wire-формат, реф-ассемблер, шифр констант
      bcrun/                  клиентский раннер bytecode (backend-путь): decode+run
      vm/                     goja-обёртка (public JS-путь и host-уровень)
      host/                   host-bridge: goja Install + bytecode HostTable (§7.2.1)
    hardening/
      antidebug/              кросс-платформенные анти-отладочные проверки
      antidump/               PR_SET_DUMPABLE, MADV_DONTDUMP, mlock, RLIMIT_CORE=0
      integrity/              сверка self-bin SHA-256 с вшитым значением
      secrets/                реестр чувствительных буферов для wipe на fatal-пути
      signals/                перехват SIGTERM/SIGINT/… с zeroize-хуками (§8.2)
      panicguard/             recover-обёртка: без stack-trace на backend, re-panic на public
      policy/                 единая точка реакции (backend hard-exit / public warn)
    platform/
      platform_linux.go       build-tag linux
      platform_windows.go     build-tag windows
      platform_darwin.go      build-tag darwin
      platform_stub.go        fallback для не-целевых платформ
  serverkit/                  ⮕ вынесено в приватный репозиторий kamienclave-backend
    jsbc/                     компилятор JS-подмножества → bytecode (на парсере goja)
    watermark/                embed/extract per-license отпечатка (§8.4.1)
    factory/                  сборка per-license payload: compile→watermark→encrypt
  go.mod
  go.sum
```

### 4.2 Жизненный цикл запуска

1. **early-init** (до `main`): через `init()` в `hardening/antidebug` —
   немедленные проверки отладчика. Если найден — `os.Exit(0)` без
   диагностики.
2. **lockdown**: устанавливаются `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`,
   `mlockall(MCL_CURRENT|MCL_FUTURE)` (best-effort, см. §7).
3. **integrity**: сверка SHA-256 собственного бинаря с вшитым на этапе
   серверной сборки значением; mismatch → выход.
4. **license unlock**: расшифровка вшитой приватной секции
   passphrase'ом пользователя (если включена опция per-license
   passphrase) → получение `ClientSigningKey`.
5. **handshake**: построение запроса, его подписание, отправка по HTTPS.
6. **payload receive**: AEAD-расшифровка ответа эфемерным ключом
   сессии.
7. **execute**: запуск payload в `goja` VM с whitelisted host API.
8. **teardown**: явное обнуление buffer'ов с payload и ключами,
   `runtime.GC()`, выход.

### 4.3 Public vs backend сборки

Различия задаются build-tag'ами в `cmd/enclave`:

| Аспект              | `public`                            | `backend`                                |
| ------------------- | ----------------------------------- | ---------------------------------------- |
| Endpoint URL        | demo.enclave.example                | боевой, вшит в `config` приватной сборки |
| Anti-debug          | мягкий warn                         | hard-exit без диагностики                |
| Логи                | человекочитаемые                    | минимальные, без stack trace             |
| Обфускация бинаря   | стандартный `go build`              | `garble` с literal/idents/seed=random    |
| Symbol stripping    | по желанию                          | `-ldflags="-s -w -buildid="`             |
| Integrity check     | off                                 | on                                       |
| Payload-формат      | прямой JS (goja)                    | bytecode mini-VM                         |
| mini-VM в репо      | отсутствует физически               | присутствует (backend-only)              |

В public-репозитории физически отсутствуют файлы `backend`-веток —
исключаем риск утечки через git-историю.

---

## 5. Протокол обмена

### 5.1 Транспорт

- HTTPS, TLS 1.3, проверка цепочки + дополнительный **SPKI pinning**
  публичного ключа сервера (вшитый sha256 SPKI).
- Поверх TLS — собственный AEAD-слой, чтобы компрометация CA в системе
  пользователя не дала прочесть payload и подделать ответ.

### 5.2 Запрос на выдачу payload

```jsonc
// POST /v1/fetch
{
  "v": 1,                        // protocol version
  "product": "enclave",
  "build": "backend",            // "public" | "backend"
  "client_version": "0.1.0",
  "license_id": "LCS-XXXX-...",  // открытый идентификатор лицензии
  "nonce": "<32 random bytes b64>",
  "ts": 1717075200,              // unix
  "eph_pub": "<X25519 client ephemeral pubkey b64>"
}
```

Тело подписывается приватным **Ed25519**-ключом клиента. Подпись
передаётся в заголовке `X-Delator-Sig: <ed25519 b64>` либо как
отдельное поле верхнего уровня. Подписывается каноническая
JSON-сериализация (RFC 8785 JCS) для исключения malleability.

> Против draft 0.1 ECDSA P-256 заменён на Ed25519: детерминированная подпись
> без катастрофического foot-gun переиспользования nonce (главная причина
> утечек ECDSA-ключей), быстрее, проще, согласован с уже используемым X25519.

### 5.3 Защита от replay

- `nonce` — 32 случайных байта, на сервере храним BloomFilter / Redis
  с TTL.
- `ts` — окно валидности ±60 секунд.
- Отказ при любом из условий: invalid sig, used nonce, ts вне окна,
  license revoked/expired.

### 5.4 Ответ сервера

```jsonc
// 200 OK
{
  "v": 1,
  "eph_pub": "<X25519 server ephemeral pubkey b64>",
  "salt": "<16 random bytes b64>",
  "nonce": "<12 random bytes b64>", // GCM nonce
  "ct": "<AEAD ciphertext b64>"     // AES-256-GCM
}
```

`shared = X25519(client_eph_priv, server_eph_pub)` →
`key = HKDF-SHA256(shared, salt, info="kamienclave/v1/payload")` →
`AES-256-GCM` со случайным 96-битным nonce.

> Изменения против draft 0.1: убран `tag_hash` (sha256 от plaintext) — он
> избыточен при наличии GCM-тега и работает как confirmation-oracle для
> угадываемого payload. Nonce сделан случайным вместо `0`: ключ и так
> одноразовый, но фиксированный nonce — хрупкий инвариант, катастрофически
> ломающийся при любом будущем переиспользовании ключа.

Ответ дополнительно подписывается серверным **Ed25519** — заголовок
`X-Delator-Server-Sig`. Клиент верифицирует подпись вшитым
публичным ключом сервера.

### 5.5 Ошибки

Сервер отдаёт минималистичные ошибки — без подсказок атакующему:
`401 invalid request` без указания почему. Подробности — только в
серверных логах.

---

## 6. Криптография

| Назначение                       | Алгоритм                          | Параметры                         |
| -------------------------------- | --------------------------------- | --------------------------------- |
| Подпись запроса клиента          | Ed25519                           | RFC 8032                          |
| Подпись ответа сервера           | Ed25519                           | RFC 8032                          |
| Эфемерный обмен ключами          | ECDH X25519                       | RFC 7748                          |
| Деривация сессионного ключа      | HKDF-SHA256                       | salt от сервера, 32 байта output  |
| Симметричное шифрование payload  | AES-256-GCM                       | случайный 96-бит nonce            |
| Шифрование embed'а приватника    | AES-256-GCM                       | KDF: Argon2id(passphrase, salt)   |
| Канонизация JSON для подписи     | JCS (RFC 8785)                    | —                                 |

Все буферы с чувствительными данными аллоцируются как `[]byte` и явно
обнуляются `crypto/subtle`-style функцией перед освобождением. Где
возможно — `mlock`-ятся.

### 6.1 Хранение приватного ключа клиента

Гибрид из двух выбранных опций:

1. **Per-license server build** — при выдаче лицензии серверная
   фабрика собирает уникальный бинарь enclave-vm. В него на этапе сборки
   `embed`-ом включается зашифрованный блоб с приватником клиента.
2. **Зашифрованный keyfile / passphrase** — embed-блоб зашифрован
   AES-256-GCM, ключ деривируется Argon2id из passphrase, которое
   пользователь вводит при запуске (`--passphrase` или TTY-prompt).
   Опционально KDF дополнительно подмешивает machine-bound материал
   (machine-id, MAC). Включается флагом серверной сборки.

Приватник никогда не лежит на диске в открытом виде, существует в
памяти ровно столько, сколько занимает подпись запроса, и
немедленно zeroize-ится.

---

## 7. Исполнение payload в памяти

### 7.1 Формат payload и runtime

**Ключевое решение против draft 0.1.** Отдавать в `goja` читаемый JS-исходник
строкой — самое слабое место под нашу цель: атакующему достаточно хукнуть
`goja.Compile`/`RunString` (или пропатчить наш же host-bridge) и снять
исходник payload одним куском. Интерпретатор-граница — подарок для извлечения.

Поэтому payload доставляется **не как JS-исходник, а как bytecode нашего
собственного формата**, исполняемый mini-VM:

- Серверный pipeline компилирует исходную логику в кастомный bytecode
  (стек-машина с зашифрованными константами и flattened control-flow).
- Клиент получает только bytecode; читаемого JS/AST в памяти не возникает
  ни на каком этапе. Снять дамп = получить bytecode под недокументированную
  VM, а не исходник.
- Таблица опкодов рандомизируется per-build (см. §8.4), так что дизассемблер
  одной утёкшей сборки не переносится на другую.
- **Граница ответственности (чёрный ящик).** Этот репозиторий содержит
  только *интерпретатор* bytecode и *версионированный ISA-spec* (контракт в
  `kamienclave-proto`: набор опкодов, кодировка операндов, value-модель,
  host-call ABI). Фронтенд компилятора (исходный язык → bytecode) живёт
  целиком на сервере и сюда не попадает: клиент не знает исходного языка
  payload'а. Утечка из клиента даёт максимум VM+ISA, но не компилятор.
  На сервере фронтендом v1 — JS-подмножество (уже есть `index.js`-payload'ы),
  но для клиента это прозрачно.

> Серверный компилятор JS-подмножества (`serverkit/jsbc`, парсер goja → AST →
> bytecode через тот же ISA) вынесен в приватный репозиторий `kamienclave-backend`,
> поэтому правило «фронтенд не в клиенте» соблюдено: оба репозитория зависят
> только от общего ISA-контракта. Опкод-таблица (seed сборки) — общий
> per-build секрет компилятора и интерпретатора, в payload не кладётся.

`github.com/dop251/goja` остаётся в стеке как pure-Go ES-движок для
host-уровня и для public-сборки (там допустим прямой JS):

- pure Go, без CGO → честная кросс-компиляция linux/windows/darwin
- управляемый lifecycle: runtime можно прибить и обнулить heap
- whitelist host-функций — payload видит только то, что мы явно прокинули

> Это переносит mini-VM из «опц. фаза 8» в **несущую** часть защиты: без неё
> дамп памяти тривиально отдаёт исходник, и весь остальной хардинг теряет смысл.
> Альтернатива `rogchap.com/v8go` (V8) — только если понадобится скорость на
> host-уровне; компромисс — тащит CGO и большой V8.

### 7.2 Sandbox / host bridge

payload может вызывать только функции, явно зарегистрированные в
`internal/runtime/host`:

- `http.fetch(url, opts)` — обёртка над собственным HTTP-клиентом с
  whitelist'ом доменов, заданным в payload-конфиге.
- `log(msg)` — в `backend`-сборке — no-op или ring-buffer без вывода.
- `env.get(key)` — только из whitelist'а.
- никакого FS, `eval`-инъекций ниже, никакого require удалённых
  модулей.

bytecode-payload декодируется и исполняется mini-VM напрямую из `[]byte`;
промежуточного читаемого представления не материализуется, а исходный
буфер обнуляется сразу после загрузки в VM.

### 7.2.1 Host-call ABI и whitelist

Механизм и список функций разделены:

- **Механизм расширяемый сразу.** Один generic-опкод `HOSTCALL <id>` +
  реестр функций. Добавление новой host-функции не меняет ISA — это важно,
  чтобы версия загрузчика у клиента не ломалась при росте API.
- **Список — узкий whitelist, deny-by-default.** Каждая зарегистрированная
  функция — это и точка хука для атакующего, и capability извлечённого
  payload'а. Расширяется только под реальную потребность.

Стартовый набор (v1):

| Функция        | Семантика                                                     |
| -------------- | ------------------------------------------------------------- |
| `log(msg)`     | `backend`: no-op / ring-buffer без вывода; `public`: stdout   |
| `env.get(key)` | только из whitelist'а ключей                                  |
| `sleep(ms)`    | bounded задержка                                              |

Под потребность, но **не «на всякий случай»**:

- `http.fetch(url, opts)` — добавляется, только если payload реально ходит
  наружу; за per-payload доменным whitelist'ом, подписанным сервером.
- `crypto.*` — **не закладываем**. Транспортную крипту держит host; если
  payload'у нужен хеш — добавляется узкий `host.sha256`, а не крипто-тулкит.
- FS / `os/exec` / require удалённых модулей — никогда.

### 7.3 Teardown

При завершении сессии (нормальное или через сигнал):

1. Все ref-ы на `goja.Runtime` обнуляются.
2. `runtime.GC()` x2 для скорейшего освобождения.
3. Все известные буферы с payload/ключами проходят через `zeroize`.
4. `mlock`-нутые регионы `munlock`-аются после стирания.
5. Только после этого — `os.Exit`.

---

## 8. Hardening

Все механики ниже — в `backend`-сборке. `public` ограничивается
soft-warn'ами для демонстрационной ценности.

Приоритет по вкладу в защиту (см. §1.1): **несущие** — серверная доставка
bytecode-payload (§7.1) и per-license watermarking (§8.4.1); **speed bumps** —
анти-отладка (§8.1) и анти-дамп (§8.2), которые лишь замедляют, но не
предотвращают извлечение тем, кто root в своём контейнере.

### 8.1 Анти-отладка

| Платформа | Техника                                                                                  |
| --------- | ---------------------------------------------------------------------------------------- |
| Linux     | `ptrace(PTRACE_TRACEME, 0,0,0)` self-attach в `init()`; повторно — проверка `TracerPid` в `/proc/self/status` через jitter-таймер |
| Linux     | Замер времени между двумя `rdtsc`/монотонными часами вокруг "trap-инструкций" — детект singlestep |
| Windows   | `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, чтение `BeingDebugged`/`NtGlobalFlag` из PEB, `NtQueryInformationProcess(ProcessDebugPort/Flags/ObjectHandle)` |
| Darwin    | `sysctl(KERN_PROC, KERN_PROC_PID, pid)` → `P_TRACED` флаг; `ptrace(PT_DENY_ATTACH)` в `init()` |
| Все       | Periodic re-check через `time.AfterFunc` со случайным интервалом                         |

При детектировании — silent `os.Exit(0)`. В `public`-сборке вместо
выхода печатается warning.

### 8.2 Анти-дамп

| Платформа | Техника                                                                  |
| --------- | ------------------------------------------------------------------------ |
| Linux     | `prctl(PR_SET_DUMPABLE, 0)`, `RLIMIT_CORE=0`, `madvise(MADV_DONTDUMP)` для регионов с payload |
| Linux     | `mlock` критических буферов чтобы не свопались                           |
| Windows   | `SetProcessMitigationPolicy(ProcessSignaturePolicy)` (best-effort), `SetErrorMode(SEM_FAILCRITICALERRORS\|SEM_NOGPFAULTERRORBOX)` |
| Darwin    | `setrlimit(RLIMIT_CORE,0)`, `ptrace(PT_DENY_ATTACH)`                     |
| Все       | Обнуление чувствительных байт сразу после использования                  |
| Все       | Перехват SIGSEGV/SIGBUS/SIGABRT → zeroize-then-exit                      |

### 8.3 Целостность

- **Trailer-схема (реализовано).** Post-build тул `cmd/stamp` дописывает в
  хвост бинаря трейлер `magic(8) || sha256(body)`. В рантайме `integrity`
  читает свой файл, отделяет трейлер и пересчитывает SHA-256 по телу — это
  снимает цикличность «хеш файла внутри того же файла» и применяется *после*
  garble (трейлер — сырые байты, не Go-переменная). Хвостовые байты после
  структуры ELF/Mach-O/PE игнорируются загрузчиком, бинарь исполняется.
- Несовпадение → `policy.Violate(ReasonIntegrity)` (backend: silent-exit).
  Не-застэмпленный dev-бинарь → soft-miss, без срабатывания.
- В `backend`-сборке дополнительно может сверяться список ожидаемых
  публичных ключей (по мере появления embed-сторов).

### 8.4 Защита payload от анализа

- Payload **никогда** не пишется на ФС, не передаётся в `os/exec`, не
  попадает в env-переменные, не логируется.
- Расшифрованный bytecode хранится в одном `[]byte`, загружается в mini-VM,
  после чего буфер немедленно zeroize.
- Исходная логика обфусцируется на серверной стороне *до* компиляции в
  bytecode (отдельный pipeline, documented в kamienclave-backend): identifier
  mangling, string encryption, control-flow flattening.
- **Bytecode mini-VM (несущая защита, не опция).** Логика компилируется в
  кастомный bytecode со случайной таблицей опкодов и зашифрованными
  константами; таблица ре-рандомизируется на каждую серверную сборку. Цель —
  чтобы дамп памяти давал bytecode под недокументированную VM, а не исходник.

### 8.4.1 Per-license watermarking (несущая защита)

Извлечение не предотвратить, но утечку можно сделать **трассируемой**:

- Серверная фабрика вшивает в каждый per-license payload уникальный,
  избыточно размазанный отпечаток лицензии (в константах, порядке опкодов,
  «мёртвых» ветках) — так, чтобы его нельзя было вырезать одним diff'ом.
- Утёкшая в паблик копия → по отпечатку определяется лицензия → отзыв +
  юридическое преследование по условиям лицензии.
- Это смещает защиту с «технически невозможной профилактики» на
  **детерренс + атрибуцию**, что для on-prem реально достижимо.

**Реализация v1** (`serverkit/watermark`): N избыточных CRC-защищённых
записей-отпечатков вшиваются как инертные строковые константы пула на
seed-зависимых позициях (`Program.InsertConstants` ремапит индексы
`OpPushConst`, поведение не меняется). Извлечение — majority-vote по
валидным копиям: достаточно одной уцелевшей. Это **cost-raising +
атрибуция**, не предотвращение: формат-осведомлённый атакующий способен
вырезать все копии (принято, см. §1.1). Клиент watermark не трогает —
только переносит (VM игнорирует лишние константы, Encode/Decode их
сохраняют).

### 8.5 Защита бинаря enclave-vm

- Сборка через `garble`: literal-obfuscation, ident-rename, tiny mode,
  random seed на каждую сборку.
- `-trimpath`, `-ldflags="-s -w -buildid="`.
- В Docker-сборке — `CGO_ENABLED=0`, статический бинарь.

### 8.6 Что НЕ защищаем (явные out-of-scope)

- Атакующий с root/Administrator-правами и физическим доступом, имеющий
  возможность модифицировать ядро или загружать LKM/KMD — за пределами
  модели угроз.
- Side-channel атаки на ECDSA через power analysis — за пределами.
- Полная защита от reverse-engineering — недостижимо в принципе;
  цель — кратно поднять стоимость анализа.

---

## 9. Модель угроз (краткая)

| Угроза                                          | Митигатор                                                |
| ----------------------------------------------- | -------------------------------------------------------- |
| Кража лицензионного бинаря и запуск на чужой машине | Per-license ключ + passphrase; machine-bound KDF (опц.) |
| Запуск под gdb/lldb/x64dbg                      | §8.1                                                     |
| Дамп процесса (`/proc/<pid>/mem`, ProcDump)     | §8.2                                                     |
| MITM при выдаче payload                         | TLS + SPKI pinning + AEAD поверх + подпись ответа         |
| Replay предыдущего ответа сервера               | nonce + ts + одноразовый сессионный ключ                  |
| Подделка лицензии                               | Проверка подписи и записи в БД на сервере                |
| Утечка бинаря backend-логики через GitHub       | Физически отдельный приватный репозиторий                |
| Анализ payload в памяти                         | Bytecode mini-VM (§7.1/§8.4) + серверная обфускация       |
| Утечка извлечённой копии в паблик               | Per-license watermarking + отзыв + юр. преследование      |

> **Честная оговорка.** Клиент с root в своём Docker-контейнере (т.е. любой
> легитимный покупатель) способен в итоге извлечь payload: gdb, `/proc/<pid>/mem`,
> патч бинаря. Docker — формат поставки, **не** граница безопасности. Поэтому
> в строках выше «митигатор» означает *повышение стоимости и трассируемость*,
> а не предотвращение. Цель — сделать извлечение дороже честной лицензии и
> привязать утёкшую копию к нарушителю (§1.1).

---

## 10. Зависимости

| Зависимость                              | Назначение                            |
| ---------------------------------------- | ------------------------------------- |
| `github.com/dop251/goja`                 | In-memory JS runtime                  |
| `github.com/dop251/goja_nodejs`          | Минимальный набор node-совместимых модулей по whitelist |
| `golang.org/x/crypto`                    | `argon2`, `hkdf`, `chacha20poly1305` (резерв) |
| `golang.org/x/sys`                       | `unix.Prctl`, `unix.Mlockall`, syscalls per OS |
| `golang.org/x/term`                      | TTY-prompt для passphrase             |
| `github.com/spf13/cobra`                 | CLI subcommands                       |
| `github.com/cyphar/filepath-securejoin`  | На случай host-файловых операций       |
| `mvdan.cc/garble` (build-time)           | Обфускация Go-бинаря при сборке       |

Стандартная библиотека: `crypto/ed25519`, `crypto/ecdh`, `crypto/aes`,
`crypto/cipher`, `crypto/sha256`, `crypto/rand`, `crypto/tls`,
`encoding/json`, `net/http`.

---

## 11. Dev-окружение

Разработка ведётся в Docker-контейнере, описанном в
[docker/Dockerfile](docker/Dockerfile). Контейнер содержит:

- Go toolchain
- `git`, `make`, `ca-certificates`
- `garble` для тестовой сборки backend-варианта
- `golangci-lint`, `staticcheck` для статанализа
- (опц.) `upx` для исследования финального размера бинаря

Запуск:

```bash
docker compose up -d dev-enclave
docker exec -it dev-enclave bash
```

Внутри:

```bash
cd /app
go mod tidy
go build ./cmd/enclave    # обычная сборка
make build-backend         # обфусцированная сборка через garble
```

---

## 12. Этапы реализации

| Этап | Статус | Содержание                                                                          |
| ---- | ------ | ----------------------------------------------------------------------------------- |
| 0    | ✅     | Скаффолд: go.mod, структура каталогов, Dockerfile, заглушка CLI                     |
| 1    | ✅     | Протокол и крипта: Ed25519 подпись, X25519+HKDF+AES-GCM (random nonce), JCS         |
| 2    | ✅     | Transport-слой: HTTPS-клиент, SPKI pinning, обработка ошибок и ретраев              |
| 3    | ✅     | License-слой: расшифровка embed-блоба, passphrase prompt, machine-bound (флагом)    |
| 4    | ✅     | **Bytecode mini-VM**: ISA+интерпретатор+реф-ассемблер, per-build рандомизация опкодов, ChaCha20-шифрование пула констант, компилятор (serverkit, в kamienclave-backend), клиентский `bcrun`, build-tag CLI-интеграция (backend=bytecode), e2e через transport |
| 5    | ✅     | Runtime/host-bridge: whitelist host-API (goja + `HOSTCALL` ABI), lifecycle, teardown, zeroize |
| 6    | ✅     | **Per-license watermarking**: embed/extract + размазывание + majority-vote; фабрика `serverkit/factory` (compile→watermark→encrypt); bytecode-параметры едут в bundle; license DB/выдача реализованы в `internal/server` (§14) |
| 7    | ✅     | Hardening speed bumps: anti-debug/anti-dump per-OS, integrity, **signal-zeroize + panic-guard + secrets-registry** (подключены в Init и run-пути) |
| 8    | ✅     | Build pipeline: `garble`-сборка, версионирование (ldflags), **integrity-стэмпинг (`cmd/stamp` + trailer)**, mock-сервер для интеграц. тестов, `make test` (default+backend) |
| 9    | 🟡     | Подготовка к разнесению: `proto` обеззависимлен (zero internal deps, extraction-ready), bytecode-ISA dep-light (stdlib+chacha20); осталось физическое разнесение репозиториев + public-сборка |

---

## 13. Открытые вопросы

1. Допустимо ли требовать у пользователя passphrase каждый запуск,
   или достаточно machine-bound деривации? (UX vs security)
2. Хотим ли мы поддержку offline-режима с кэшированием подписанного
   payload на TTL? По умолчанию — нет (каждый запуск идёт к серверу).
3. Лимит на конкурентные сессии одной лицензии — серверный вопрос,
   но клиент должен корректно отображать `429 license busy`.
4. **[решено v0.2]** Глубина mini-VM: v1 — стек-машина с per-build
   рандомизацией опкодов, шифрованием констант, обфускацией диспетчера и
   bogus-хендлерами. Native-Go-виртуализация участков per-license — не сейчас;
   ISA версионируется так, чтобы добавить этот слой позже, после замера
   реальной стоимости взлома v1.
5. **Host-bridge surface** зависит от того, что payload реально делает
   (сеть? чтение env? крипто-тяжёлые операции?). v1-набор — `log`/`env.get`/
   `sleep` (§7.2.1); финальный список — после спецификации поведения payload'а.

---

## 14. Серверная часть (`kamienclave-backend`)

Сервер вынесен в отдельный **приватный** репозиторий `kamienclave-backend`
(пакеты `internal/server/`, `internal/serverkit/`, CLI `cmd/enclave-server`),
поэтому компилятор и watermark-фабрика физически не попадают к клиенту (§7.1).
Бэкенд импортирует общий wire-контракт и крипто из публичного клиентского модуля
как обычную зависимость; правило `internal/` держит границу в обе стороны.

### 14.1 Компоненты

```
cmd/enclave-server/          CLI: keygen / serve / license issue|list|revoke|attribute
cmd/enclave-host/            клиент режима B: fetch+run Node-приложения из памяти
internal/server/
  store/                     БД лицензий: JSON (reload-on-mtime) | SQLite (pure-Go), интерфейс DB
  licensing/                 выпуск: генерация ключей+секретов, sealed bundle
  api/                       HTTP /v1/fetch, /v1/blob, /metrics, /healthz; rate-limit
  ratelimit/                 per-IP token-bucket (до крипты)
  metrics/                   Prometheus-счётчики
internal/serverkit/          (см. §7.1, §8.4.1)
  jsbc/                      компилятор JS-подмножества → bytecode (режим A)
  watermark/                 embed/extract отпечатка в bytecode (режим A)
  factory/                   compile → watermark → encrypt (режим A)
  appwatermark/              embed/extract отпечатка в JS-бандл (режим B)
internal/encpkg/             (клиент+сервер) формат .encpkg: AEAD+Ed25519 конверт
internal/apprunner/          (клиент) verify→decrypt→integrity→launch; Linux memfd
```

### 14.0 Два режима доставки

- **режим A (bytecode):** `factory` собирает закрытый bytecode-payload, клиент
  исполняет в mini-VM (`bcrun`). Несущая непрозрачность; узкий язык.
- **режим B (fullapp):** сервер пакует целый ncc-бандл Node-приложения в `.encpkg`
  (`encpkg.Seal` + `appwatermark`), клиент (`enclave-host`/`apprunner`) verify+
  decrypt и запускает Node из памяти (memfd, no-disk). Полная совместимость;
  защита = дистрибуция + атрибуция, **не** неизвлекаемость. Драфт и честная
  модель угроз — [docs/DRAFT-fullapp-delivery.md](docs/DRAFT-fullapp-delivery.md),
  гайд — [docs/USAGE-fullapp.md](docs/USAGE-fullapp.md). Режим выбирается полем
  `Mode` в лицензии/бандле.

### 14.2 Модель лицензии (store)

Запись связывает `license_id` с публичным ключом клиента и per-build секретами:
`opcode_seed`, `const_key` (отдаются и клиенту в bundle), `fingerprint`,
`watermark_seed`, `payload_source`, `status`, `expires_at`, `max_concurrent`.
Приватный ключ подписи клиента сервер **не хранит** — он существует лишь в момент
выпуска, запечатывается в bundle и забывается.

### 14.3 Обработка `/v1/fetch`

1. Распарсить запрос, найти лицензию по `license_id`.
2. Проверить подпись клиента (Ed25519) по canonical-форме (§5.2).
3. Проверить статус (active / не истекла / не отозвана) → `403`.
4. Freshness: версия протокола, окно `ts` ±skew, nonce не повторялся (§5.3) → `401`.
5. Concurrency-лимит лицензии (§13.3) → `429`.
6. Собрать payload фабрикой: compile → watermark(seed=lic) → encrypt(table+key) (§7.1, §8.4).
7. ECDH с эфемерным ключом клиента, AES-256-GCM, подпись ответа (§5.4).
8. Ошибки — минималистичные, детали только в серверный лог (§5.5).

### 14.4 Жизненный цикл и эксплуатация

- **Выпуск:** `license issue` создаёт запись, пишет sealed bundle (`*.lic`) для
  клиента. Bundle несёт signing-key + per-build секреты, защищён Argon2id-passphrase.
- **Ротация логики:** отредактировать `payload_source` (или флаг при перевыпуске) —
  новый payload компилируется на каждый запрос, передистрибуция бинаря не нужна.
- **Kill-switch:** `license revoke` → немедленный `403` на следующем запросе.
  NB (находка live-теста): `serve` и CLI — **разные процессы** поверх одного
  JSON-файла, поэтому store перечитывает файл при изменении mtime — иначе
  running-сервер держал бы устаревшую копию и отзыв молча не срабатывал бы.
  Проверено вживую: revoke → `fetch 403` → приложение не стартует.
- **Подъём с нуля, выпуск, запуск:** см. [docs/SETUP.md](docs/SETUP.md);
  язык payload, host-API и CLI — [docs/USAGE.md](docs/USAGE.md).

### 14.5 Статус и оговорки

Реализовано и протестировано сквозняком (server↔client e2e в
`internal/server/api/`). Готово также: **per-IP rate-limiting** (token-bucket,
`internal/server/ratelimit`, срабатывает до крипты; флаги `--rate`/`--rate-burst`)
и **out-of-band доставка** больших бандлов (одноразовый TTL-токен + `/v1/blob`).
Админ-операции (`issue/list/revoke/attribute`) — локальный CLI поверх JSON-файла,
сетевого admin-API нет → их «auth» = права на файл (`0o600`).

Готово также (по итогам live-тестирования на реальном NestJS-бэкенде):
**SQLite-хранилище** (pure-Go, CGO-free; `--db *.db`), **per-IP rate-limiting**,
**Prometheus-метрики** (`/metrics`), **обфускация-пайплайн поставщика**
(`scripts/build-fullapp-bundle.sh`, оба пресета проверены на реальном бандле).
Для продакшна остаётся: серверная обфускация — как часть пайплайна поставщика;
расширенная телеметрия/аудит; реплики БД при росте.
