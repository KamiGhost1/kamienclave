# kamienclave — режим B: доставка полного приложения (fullapp)

Гайд по доставке и запуску **целого Node.js-приложения** (например NestJS-бэкенда)
в зашифрованном, подписанном, лицензируемом виде. Приложение исполняется в памяти
штатным Node.js; локально его исходник не сохраняется.

Это дополнение к bytecode-режиму ([USAGE.md](USAGE.md)). Базовый дизайн и честная
модель угроз — в [DRAFT-fullapp-delivery.md](DRAFT-fullapp-delivery.md).

> **Что режим B даёт:** защиту в покое и в доставке (на диске только
> зашифрованный подписанный бандл), enforcement (лицензия/expiry/kill-switch),
> атрибуцию утечки (per-license watermark), подлинность (подпись).
> **Чего НЕ даёт:** секретности кода от root — Node обязан видеть исполнимый JS,
> поэтому атакующий с root на машине клиента может снять распакованный код из
> памяти. Режим B — про лицензируемую дистрибуцию и трассируемость, не про
> неизвлекаемость. Для секретного ядра используйте bytecode-режим (USAGE.md).

---

## 0. Подготовка приложения (на стороне поставщика)

Режим B принимает **единый JS-бандл**, собранный через
[`@vercel/ncc`](https://github.com/vercel/ncc):

```bash
# в репозитории приложения
npx nest build                 # ваш обычный билд -> dist/
ncc build dist/main.js -o out  # -> out/index.js  (единый файл)
```

**Обфускация (рекомендуется для режима B).** Код режима B — обычный JS в памяти,
поэтому обфускация *до* сборки поднимает стоимость снятия из дампа. Готовый
пайплайн — [`scripts/build-fullapp-bundle.sh`](../scripts/build-fullapp-bundle.sh)
(ncc → `javascript-obfuscator` → проверки). Обе пресета (`medium`/`high`)
проверены на реальном NestJS-бэкенде: приложение поднимается, DI/reflect-metadata
переживают обфускацию, эндпоинты отвечают. `medium` — баланс (быстро, ~0.8× размер);
`high` — макс. защита (control-flow flattening + self-defending, ~2× размер, ~100с
сборки на 4 МБ). Это cost-raising, не секретность (root всё равно снимет, §2).

Требования к бандлу:
- **Pure-JS.** ncc не инлайнит native-аддоны (`.node`). Если в рантайме есть
  native-зависимости (напр. `bcrypt`) — заменить на чисто-JS аналог (`bcryptjs`),
  иначе бандл перестаёт быть единым и no-disk-запуск ломается.
- **Конфиг через `process.env`.** Env приходит в контейнер; приложение читает
  `process.env`. Не полагайтесь на чтение файлов рядом с бандлом (`__dirname`):
  при no-disk запуске у бандла нет своей папки на диске.
- **Длительные шаги (миграции и т.п.) — вне бандла.** Прогоняйте отдельно.

> env — это данные клиента (адреса БД/Redis, порты), не ваш секрет. Настоящие
> секреты (ключи к внешним API, проприетарные алгоритмы) в env класть нельзя —
> для них bytecode-режим.

---

## 1. Сервер: ключи и сертификат

(как в [SETUP.md](SETUP.md) — общие для обоих режимов)

```bash
enclave-server keygen --priv server.key --pub server.pub
openssl req -x509 -newkey ed25519 -nodes -keyout tls.key -out tls.crt \
  -days 365 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost"
```

---

## 2. Выпуск fullapp-лицензии

```bash
enclave-server license issue \
  --mode fullapp \
  --id LCS-ACME-0001 \
  --server-url https://localhost:8443 \
  --server-pub server.pub \
  --cert tls.crt \
  --app-bundle out/index.js \
  --app-entrypoint index.js \
  --app-node ">=20" \
  --app-env PORT --app-env DATABASE_URL --app-env REDIS_URL \
  --out acme.lic \
  --passphrase "customer-secret" \
  --expires-days 365 \
  --max-concurrent 3
```

Флаги режима B:
- `--mode fullapp` — выбирает режим доставки приложения.
- `--app-bundle` — путь к ncc-бандлу (читается сервером при каждом fetch, можно
  обновлять для ротации без перевыпуска лицензии).
- `--app-entrypoint` — логическое имя точки входа (по умолчанию `index.js`).
- `--app-node` — требуемый диапазон версий Node (информативно, в манифесте).
- `--app-env` (повторяемый) — **имена** env-переменных, которые загрузчик
  пробросит дочернему Node. Значения берутся из окружения клиента.

Результат: `acme.lic` (sealed bundle с ключом расшифровки приложения) — отдаётся
клиенту вместе с бинарём `enclave-host`. `--passphrase` сообщается клиенту вне
канала.

---

## 3. Запуск сервера

```bash
enclave-server serve --addr :8443 --db licenses.json \
  --sign-key server.key --cert tls.crt --key tls.key
```

---

## 4. Клиент: запуск приложения

Клиенту нужны бинарь `enclave-host` и его лицензия `acme.lic`. Запуск (Linux):

```bash
ENCLAVE_PASSPHRASE="customer-secret" \
PORT=8080 DATABASE_URL=postgres://... REDIS_URL=redis://... \
enclave-host run --license-file acme.lic --ca tls.crt
```

Что происходит:
1. распаковка лицензии (passphrase) → ключ расшифровки приложения;
2. fetch зашифрованного `.encpkg` по протоколу (`/v1/fetch`, Ed25519+AEAD+pin);
3. проверка подписи сервера, расшифровка, sha256-integrity бандла;
4. проброс перечисленных в лицензии env-переменных;
5. **запуск Node из RAM** — бандл пишется во временный файл на tmpfs (`/dev/shm`,
   `0600`), запускается `node`, файл анлинкается через ~1.5с (Node работает из
   открытого in-RAM fd), удаляется на выходе. На постоянный диск код не пишется.
   Для бандлов > 64 МБ (дефолт `/dev/shm`) укажите бóльший tmpfs через `--tmpdir`;
6. приложение слушает свой порт как обычно; `Ctrl-C`/`SIGTERM` завершает его.

С реальным (доверенным) TLS-сертификатом `--ca` не нужен.

> **Платформа:** no-disk запуск через `memfd` реализован на **Linux**. На других
> ОС загрузчик вернёт ошибку (см. DRAFT §9 Q6).

### Сборка `enclave-host`

```bash
make build-host    # -> bin/enclave-host (Linux, обфусцированный, со stamp)
```

---

## 5. Управление и атрибуция

```bash
enclave-server license list   --db licenses.json
enclave-server license revoke --db licenses.json --id LCS-ACME-0001   # kill-switch
```

**Атрибуция утечки.** В каждый выданный бандл вшит per-license отпечаток
(инертные JS-комментарии, размазанные по бандлу, с CRC и majority-vote). Если
бандл утёк — определите лицензию:

```bash
enclave-server license attribute --file leaked-index.js
# fingerprint: LCS-ACME-0001
```

Отпечаток выживает частичную чистку/порчу копий. Формат-осведомлённый атакующий
может вырезать все копии — это принято (как и вся client-side защита): watermark
поднимает стоимость и даёт атрибуцию, а не предотвращение.

---

## 6. Чек-лист первого запуска (B0)

При первой интеграции реального приложения проверьте по порядку:

1. **ncc-бандл pure-JS** — рядом с `out/index.js` нет `.node`. Если есть —
   убрать native-зависимость (напр. `bcrypt`→`bcryptjs`).
2. **ncc-warnings** про опциональные пакеты (`@nestjs/microservices`,
   `@nestjs/websockets`) — не фатальны, если не используются.
3. **env подхватывается** — приложение видит `process.env` (перечислите имена в
   `--app-env`).
4. **запуск из памяти** — `enclave-host run` поднимает HTTP, эндпоинт отвечает.
5. **нет чтений по `__dirname`** при старте (шаблоны, статика, миграции по пути) —
   иначе их надо вынести/материализовать (DRAFT §5, §9a).

---

## 7. Ограничения режима B (честно)

- Секретность кода от root не гарантируется (см. рамку вверху).
- Native-аддоны (`.node`) не поддерживаются no-disk-путём (нужен файл на диске).
- no-disk-запуск — только Linux.
- Большие бандлы доставляются out-of-band: `/v1/fetch` отдаёт одноразовый
  TTL-токен (внутри зашифрованного ответа), клиент качает `.encpkg` отдельным
  GET `/v1/blob`. Прозрачно для пользователя; сам blob самозащищён.
- Серверная часть (`internal/server`, `internal/serverkit`) вынесена в приватный
  репозиторий `kamienclave-backend`; этот публичный репозиторий — только клиент.
