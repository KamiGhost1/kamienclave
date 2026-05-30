# syntax=docker/dockerfile:1.7

FROM golang:1.26-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    CGO_ENABLED=0 \
    GOFLAGS="-buildvcs=false" \
    GOTOOLCHAIN=local \
    GOPATH=/go \
    PATH=/go/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# --- System tooling -----------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        wget \
        git \
        make \
        build-essential \
        pkg-config \
        unzip \
        jq \
        less \
        vim-tiny \
        openssh-client \
        gnupg2 \
        procps \
        file \
        binutils \
    && rm -rf /var/lib/apt/lists/*

# --- Go developer tooling -----------------------------------------------------
# garble        — обфускация Go-бинаря для backend-сборки
# golangci-lint — статанализ (v2, ставится через go install под текущий Go)
# staticcheck   — точечный статанализатор
# gopls         — LSP для редакторов
# delve         — отладчик (для разработки самого kamienclave, не для прода)
RUN go install mvdan.cc/garble@latest \
    && go install honnef.co/go/tools/cmd/staticcheck@latest \
    && go install golang.org/x/tools/gopls@latest \
    && go install github.com/go-delve/delve/cmd/dlv@latest \
    && go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest \
    && go clean -cache -modcache -testcache || true

WORKDIR /app

# Прогреем модульный кэш, если go.mod уже существует на момент сборки образа.
# Если файла нет — шаг пропускается, тяжёлый прогрев делается уже внутри
# контейнера через `go mod download`.
COPY app/go.mod* app/go.sum* /app/
RUN if [ -f /app/go.mod ]; then go mod download || true; fi

CMD ["sleep", "infinity"]
