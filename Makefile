.PHONY: help build build-server build-client test test-integration test-race vet fmt clean \
        run-server run-client compose-up compose-down compose-logs

BIN_DIR := bin
SERVER_BIN := $(BIN_DIR)/server
CLIENT_BIN := $(BIN_DIR)/client

LDFLAGS := -s -w

help: ## 显示可用命令
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: build-server build-client ## 构建全部二进制

build-server: ## 构建 server
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(SERVER_BIN) ./cmd/server

build-client: ## 构建 client
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(CLIENT_BIN) ./cmd/client

test: ## 运行单元测试
	go test ./... -count=1

test-race: ## 单元测试 + 竞态检测
	go test ./... -count=1 -race

test-integration: ## 运行集成测试（端到端）
	go test -tags=integration ./tests/... -count=1 -v

vet: ## 静态检查
	go vet ./...

fmt: ## 格式化
	gofmt -l -w .

run-server: ## 本地启动 server（默认 :8080）
	go run ./cmd/server

run-client: ## 本地运行 client（需先启动 server）
	go run ./cmd/client -file testdata/input.json

compose-up: ## 一键启动
	docker compose up --build -d

compose-down: ## 停止并清理
	docker compose down -v

compose-logs: ## 查看 client 输出
	docker compose logs client

clean: ## 清理构建产物
	rm -rf $(BIN_DIR)
