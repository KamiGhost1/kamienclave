# kamienclave

`kamienclave` доставляет защищённую бизнес-логику лицензированным пользователям так,
чтобы поднять стоимость её извлечения и сделать любую утечку трассируемой. Логика
компилируется на сервере в обфусцированный bytecode, доставляется по защищённому
каналу только по валидной лицензии и исполняется **исключительно в оперативной
памяти** встроенной mini-VM. Локально исходная логика не сохраняется ни в каком
виде; каждый запуск инициирует новый защищённый запрос к серверу.

> **Честная рамка** (см. [TECHNICAL.md §1.1](TECHNICAL.md)): код, исполняемый на
> машине клиента, невозможно сделать неизвлекаемым. Цель kamienclave — **экономика
> и атрибуция**, а не абсолютная секретность: извлечение делается дороже честной
> лицензии, а утёкшая копия привязывается к лицензии через watermark.

kamienclave поддерживает два режима доставки:
- **режим A (bytecode)** — серверный компилятор переводит JS-подмножество в
  закрытый watermarked bytecode, клиент исполняет его в mini-VM. Сильная
  непрозрачность, узкий язык. Подходит для секретного вычислительного ядра.
- **режим B (fullapp)** — целое Node.js-приложение (например NestJS-бэкенд)
  доставляется зашифрованным/подписанным и запускается в памяти штатным Node.
  Полная совместимость; защита = лицензируемая дистрибуция + атрибуция, не
  неизвлекаемость. См. [docs/USAGE-fullapp.md](docs/USAGE-fullapp.md).

Подробный технический дизайн: [TECHNICAL.md](TECHNICAL.md) ·
[docs/DRAFT-fullapp-delivery.md](docs/DRAFT-fullapp-delivery.md).
Пошаговые инструкции: [docs/SETUP.md](docs/SETUP.md) ·
[docs/USAGE.md](docs/USAGE.md) (режим A) ·
[docs/USAGE-fullapp.md](docs/USAGE-fullapp.md) (режим B).

## Компоненты

| Бинарь          | Назначение                                                                 |
| --------------- | -------------------------------------------------------------------------- |
| `enclave`       | Публичная (open) клиентская сборка — исполняет payload как JS на goja       |
| `enclave-vm`    | Боевая (backend) клиентская сборка — bytecode mini-VM + полный hardening    |
| `enclave-host`  | Клиент режима B: тянет и запускает целое Node-приложение из памяти          |
| `enclave-server`| Лицензионный сервер: endpoint `/v1/fetch`, выдача/отзыв/атрибуция лицензий   |

- **enclave / enclave-vm** — две независимые сборки одного клиента (`app/cmd/enclave`),
  выбираются build-тегом: `enclave-vm` собирается с `-tags backend`.
- **enclave-server** — серверная часть. Вынесена в отдельный **приватный** репозиторий
  `kamienclave-backend` (`internal/server`, `internal/serverkit`, build-factory). Этот
  публичный репозиторий содержит только клиентскую часть; бэкенд зависит от него как от
  библиотеки (общий wire-контракт и крипто). См. TECHNICAL §7.1.

## Структура репозитория

```
.
├── app/                 # Go-модуль github.com/KamiGhost1/kamienclave
│   ├── cmd/
│   │   ├── enclave/        # клиентский CLI (enclave / enclave-vm)
│   │   ├── enclave-host/   # клиент режима B (Node-приложение из памяти)
│   │   └── stamp/          # build-тул: integrity-трейлер
│   ├── crypto/          # sign(Ed25519), kex(X25519), aead, zeroize (public)
│   ├── proto/           # DTO протокола + canonical (JCS)         (public)
│   ├── protosign/       # подпись/верификация DTO                 (public)
│   ├── transport/       # HTTPS-клиент + SPKI pinning + mockserver (public)
│   ├── license/         # sealed bundle (Argon2id) + passphrase   (public)
│   ├── encpkg/          # контейнер .encpkg (AEAD + Ed25519)      (public)
│   ├── runtime/         # bytecode mini-VM, bcrun, goja vm, host-bridge (public)
│   ├── apprunner/       # запуск Node-приложения из tmpfs         (public)
│   └── internal/        # client-private: buildinfo, cliargs, hardening
├── docs/                # SETUP.md, USAGE.md, USAGE-fullapp.md, DRAFT-fullapp-delivery.md
├── docker/              # Dockerfile для разработки
├── docker-compose.yml   # dev-контейнер
├── TECHNICAL.md         # дизайн-документ
├── LICENSE              # Apache License 2.0
└── README.md
```

> Серверная часть (`enclave-server`, build-factory, лицензирование) живёт в
> отдельном приватном репозитории `kamienclave-backend` и здесь отсутствует.
> Публичные пакеты выше (`crypto`, `proto`, `runtime`, …) — общий контракт,
> который бэкенд импортирует как зависимость.

## Быстрый старт (dev-окружение)

```bash
docker compose up -d dev-enclave
docker exec -it dev-enclave bash
# внутри контейнера, в /app:
make build          # enclave (public)
make build-backend  # enclave-vm (обфусцированный, через garble)
make build-host     # enclave-host (режим B)
make test           # тесты в обоих режимах (default + backend)
make ci             # полный гейт: build/vet/test/staticcheck/golangci
```

Дальше — [docs/SETUP.md](docs/SETUP.md): подъём сервера, выпуск лицензии, запуск клиента.

## Статус

Клиент и сервер собраны и протестированы сквозняком (end-to-end: выпуск лицензии →
handshake → зашифрованный watermarked bytecode → mini-VM). См. раздел «Этапы
реализации» в [TECHNICAL.md](TECHNICAL.md).

## License

Licensed under the [Apache License 2.0](LICENSE). © 2026 KamiGhost1.
