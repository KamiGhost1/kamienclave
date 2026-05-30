# kamienclave — пошаговая настройка

Этот гайд проводит через полный путь с нуля: собрать бинарники, поднять
лицензионный сервер, выпустить лицензию и запустить клиента. Команды
предполагают, что вы внутри dev-контейнера (`docker exec -it dev-enclave bash`,
рабочая директория `/app`) либо имеете локальный Go 1.26+.

Все артефакты ниже складываются в рабочую директорию `deploy/` — создайте её:

```bash
mkdir -p deploy && cd deploy
```

---

## 0. Сборка бинарников

```bash
# из /app (клиентский репозиторий)
make build          # -> bin/enclave        (public клиент, goja)
make build-backend  # -> bin/enclave-vm     (backend клиент, bytecode mini-VM)
make build-host     # -> bin/enclave-host   (клиент режима B)

# enclave-server собирается в приватном репозитории kamienclave-backend:
#   make build       # -> bin/enclave-server
```

> `make build-backend` требует `garble` (есть в dev-контейнере). Для боевой
> поставки именно `enclave-vm` отдаётся клиентам — он не содержит читаемого JS-пути.

Скопируйте нужные бинарники в `deploy/` или добавьте `../bin` в PATH.

---

## 1. Серверная часть

### 1.1. Ключ подписи сервера

Сервер подписывает каждый ответ; клиент проверяет подпись вшитым публичным
ключом. Сгенерируйте пару:

```bash
enclave-server keygen --priv server.key --pub server.pub
```

- `server.key` — приватный ключ, **только на сервере**, никогда не покидает его.
- `server.pub` — публичный ключ, попадёт в каждую клиентскую лицензию.

### 1.2. TLS-сертификат

Сервер работает по HTTPS, клиент дополнительно пиннит SPKI сертификата.
Для dev годится самоподписанный:

```bash
openssl req -x509 -newkey ed25519 -nodes \
  -keyout tls.key -out tls.crt -days 365 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost"
```

Для прода используйте реальный сертификат вашего домена. **Важно:** SPKI-пин
вычисляется из *этого* сертификата при выпуске лицензии (шаг 2), поэтому
лицензии надо перевыпускать при ротации TLS-ключа (или пиннить промежуточный CA —
см. TECHNICAL §5.1).

### 1.3. Payload — защищаемая логика

Логика пишется на поддерживаемом подмножестве JS (см. USAGE.md → «Язык payload»).
Пример `payload.js`:

```js
// Возвращает результат, который увидит клиент; может звать host-функции.
var total = 0;
for (var i = 1; i <= 10; i++) { total += i * i; }
log("computed sum of squares 1..10");
total
```

### 1.4. Выпуск лицензии

Одной командой: создаётся запись в БД лицензий, генерируется клиентская пара
ключей и per-build секреты, и пишется **запечатанный бандл** `acme.lic` для клиента.

```bash
enclave-server license issue \
  --db licenses.json \
  --id LCS-ACME-0001 \
  --server-url https://localhost:8443 \
  --server-pub server.pub \
  --cert tls.crt \
  --payload payload.js \
  --out acme.lic \
  --passphrase "customer-secret" \
  --expires-days 365 \
  --max-concurrent 3
```

Что куда:
- `acme.lic` → **отдать клиенту** (вместе с бинарём `enclave-vm`).
- `--passphrase` → сообщить клиенту вне канала; он введёт её при запуске
  (или задаст через `ENCLAVE_PASSPHRASE`). Можно опустить для passphrase-less
  бандла, но это снижает защиту украденного файла.
- `licenses.json` → серверная БД, остаётся на сервере.

### 1.5. Запуск сервера

```bash
enclave-server serve \
  --addr :8443 \
  --db licenses.json \
  --sign-key server.key \
  --cert tls.crt \
  --key tls.key \
  --rate 5 --rate-burst 15   # per-IP rate limit (до проверки крипты)
```

> **Хранилище лицензий.** Путь `--db` выбирает бэкенд по расширению:
> `.json` — простой файл (для малого числа лицензий), `.db`/`.sqlite` —
> SQLite (pure-Go, без CGO; для многих лицензий, конкурентных записей,
> транзакций; отзыв виден running-серверу мгновенно). Команды `license *`
> используют тот же `--db`.

Проверка живости: `curl -k https://localhost:8443/healthz` → `ok`.

---

## 2. Клиентская часть

Клиенту нужны два файла: бинарь `enclave-vm` и его лицензия `acme.lic`.

```bash
# CA нужен только для самоподписанного dev-сертификата
enclave-vm run \
  --license-file acme.lic \
  --ca tls.crt
# подсказка пароля -> вводите "customer-secret"
```

Неинтерактивно (CI/headless):

```bash
ENCLAVE_PASSPHRASE="customer-secret" enclave-vm run --license-file acme.lic --ca tls.crt
```

Ожидаемый вывод:

```
computed sum of squares 1..10
result: 385
```

С реальным (доверенным) TLS-сертификатом флаг `--ca` не нужен.

---

## 3. Управление лицензиями

```bash
enclave-server license list --db licenses.json          # обзор
enclave-server license revoke --db licenses.json --id LCS-ACME-0001  # kill-switch
```

Отозванная лицензия немедленно перестаёт обслуживаться (`403`); клиент не сможет
получить payload. Ротация логики — просто отредактируйте `payload.js` и
перевыпустите/перезапустите сервер: новый payload поедет при следующем запросе.

---

## 4. Боевые рекомендации

- **Не отдавайте `enclave` (public) клиентам** — он исполняет payload как читаемый
  JS. Боевая поставка — только `enclave-vm`.
- **Стэмпуйте бинарь** integrity-трейлером при сборке (Makefile делает это
  автоматически в `build-*`); боевой `enclave-vm` при модификации молча завершится.
- **Серверный приватный ключ и `licenses.json`** — бэкапьте и держите вне доступа.
- **Серверная часть вынесена:** `internal/server` + `internal/serverkit` живут в
  приватном репозитории `kamienclave-backend` — компилятор и watermark-фабрика
  физически не попадают к клиенту (TECHNICAL §7.1, §8.4.1).
- **Per-license passphrase vs machine-binding** — открытый вопрос UX/безопасности
  (TECHNICAL §13); по умолчанию passphrase вводится при каждом запуске.
