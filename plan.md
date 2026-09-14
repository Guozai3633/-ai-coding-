# Banner 指纹识别系统 — 开发计划

> 配套文档：`需求.md`（做什么）、`架构.md`（怎么设计）、本文档（按什么顺序做）。
> 每个步骤包含：**目标 / 涉及文件 / 关键点 / 验收标准 / 依赖**。
> 优先级：**P0** 必做 → **P1** 生产级必需 → **P2** 加分。

---

## 全局约定

### 实施顺序总览

```
阶段 A 地基          Step 1  项目初始化
                    Step 2  数据模型 + 单测
                    Step 3  配置模块 + 单测
阶段 B 识别内核      Step 4  规则模块（模型/加载/默认规则）+ 单测
                    Step 5  Banner 归一化 + 单测
                    Step 6  识别引擎 + 单测（核心对拍）
阶段 C 服务链路      Step 7  HTTP API 层 + 单测
                    Step 8  server 入口（含 healthcheck 子命令）
                    Step 9  client 逻辑与入口 + 单测
阶段 D 交付验证      Step 10 容器化（Dockerfile × 2 + compose）
                    Step 11 集成测试（端到端）
                    Step 12 文档与交付收尾
```

### 依赖关系

```
1 → 2 → { 3, 4 }
4 → 6 ；5 → 6 ；6 → 7 → 8
2,7 → 9
3,8,9 → 10 → 11 → 12
```

### 测试代码分布

| 类型 | 位置 | 覆盖对象 |
| --- | --- | --- |
| 单元测试 | 与源码同包 `*_test.go` | model / config / rules / normalize / engine / api / client |
| 集成测试 | `tests/integration_test.go`（`//go:build integration`） | client → server → engine 全链路 |
| 容器验收 | `Makefile` 目标 | `docker compose up` 后行为 |

---

## 阶段 A：地基

### Step 1 — 项目初始化

- **优先级**：P0
- **目标**：建立可编译、可测试的 Go 模块骨架与工程配套文件。
- **涉及文件**：
  - `go.mod`、`go.sum`
  - `.gitignore`、`.dockerignore`
  - `Makefile`
  - 目录骨架 `cmd/`、`internal/`、`deploy/`、`testdata/`、`tests/`
- **关键点**：
  - 模块名与仓库路径一致，`go 1.23`
  - 唯一外部依赖：`gopkg.in/yaml.v3`（若拉取受限，改用标准库 `encoding/json` 解析规则，规则结构不变）
  - `.dockerignore` 排除 `.git`、`testdata` 等，避免污染构建上下文
  - `Makefile` 提供 `build / test / test-integration / run-server / run-client / compose-up / compose-down`
- **验收标准**：`go build ./...` 与 `go vet ./...` 通过（空骨架）。
- **依赖**：无

### Step 2 — 数据模型 + 单元测试

- **优先级**：P0
- **目标**：定义对外契约数据结构，锁定输入/输出字段与 JSON 标签。
- **涉及文件（业务）**：`internal/model/model.go`
  - `Record{IP, Port, Banner}`
  - `Result{IP, Port, Protocol, Product, Version, OSHint, Confidence}`
  - 常量 `ProtocolUnknown = "unknown"`
- **涉及文件（测试）**：`internal/model/model_test.go`
- **关键点**：JSON 标签必须严格等于契约（`os_hint`、`confidence` 等）。
- **验收标准**：
  - JSON 序列化/反序列化往返一致
  - 字段名与题目要求逐字一致
- **依赖**：Step 1

### Step 3 — 配置模块 + 单元测试

- **优先级**：P1
- **目标**：统一从环境变量读取运行参数，避免硬编码。
- **涉及文件（业务）**：`internal/config/config.go`
  - `Load() Config`：`PORT`、`FINGERPRINT_RULES`、`LOG_LEVEL`、`SERVER_URL`（client 用）、`REQUEST_TIMEOUT`
  - 提供默认值
- **涉及文件（测试）**：`internal/config/config_test.go`
  - 覆盖：未设置走默认值 / 设置后正确读取 / 非法值回退默认
- **验收标准**：默认值与非法值行为符合预期。
- **依赖**：Step 1

---

## 阶段 B：识别内核

### Step 4 — 规则模块（模型 + 加载 + 默认规则）+ 单元测试

- **优先级**：P0
- **目标**：把指纹规则从代码中解耦，形成可外部覆盖的配置。
- **涉及文件（业务）**：
  - `internal/rules/rule.go`：`Rule` 模型 + `Validate()`（正则可编译、置信度 0~1、ID 唯一）
  - `internal/rules/loader.go`：`Load(path)` —— `go:embed` 内置默认 + 外部文件覆盖 + 按 `Priority` 排序
  - `internal/rules/rules.yaml`：SSH / HTTP(nginx,Apache,Jetty,IIS) / MySQL / Redis / FTP(ProFTPD,vsFTPd,Pure-FTPd) 全部规则
- **涉及文件（测试）**：`internal/rules/loader_test.go`、`internal/rules/rule_test.go`
  - 覆盖：内置规则可加载 / 外部文件覆盖生效 / 外部文件损坏时回退内置 / 非法规则被拒绝 / 优先级排序正确
- **关键点**：
  - 正则必须可编译，避免回溯灾难
  - 端口为**弱提示**，规则中标注但不作为硬门槛
- **验收标准**：加载出的规则集能覆盖 23 条示例中除 unknown 外的全部场景。
- **依赖**：Step 1

### Step 5 — Banner 归一化 + 单元测试

- **优先级**：P0
- **目标**：把原始 banner 转成可安全匹配的形式，处理二进制与转义。
- **涉及文件（业务）**：`internal/engine/normalize.go`
  - 还原字面量 `\r\n`、`\x00`、`\xNN` 转义
  - 非法 UTF-8 / 二进制安全处理（MySQL 握手包）
  - 超长 banner 截断（防正则回溯）
- **涉及文件（测试）**：`internal/engine/normalize_test.go`
  - 覆盖：`\r\n` 还原 / `\x00` 还原 / MySQL 二进制包 / 空串 / 超长截断 / 非法 UTF-8 不 panic
- **验收标准**：所有样例 banner 归一化后不 panic，且关键特征可被正则命中。
- **依赖**：Step 1

### Step 6 — 识别引擎 + 单元测试（核心）

- **优先级**：P0
- **目标**：实现「归一化 → 规则匹配 → 择优 → unknown 兜底」的完整识别流程。
- **涉及文件（业务）**：`internal/engine/engine.go`
  - `New(rules []rules.Rule) *Engine`
  - `Fingerprint(rec model.Record) model.Result`
  - `FingerprintBatch(recs []model.Record) []model.Result`（逐条独立，单条失败不影响整批）
  - 端口一致性微调置信度
- **涉及文件（测试）**：`internal/engine/engine_test.go`
  - **表驱动测试，逐条断言 23 条示例**的 `protocol / product / version / os_hint`
  - 边界：空 banner / 无匹配 / 二进制 banner / 非标端口（8443 的 nginx）
- **验收标准**：
  - 示例中所有非 unknown 条目的协议、产品、版本、OS 线索全部正确
  - unknown 条目返回 `protocol="unknown"` 且 `confidence=0`，**不 panic**
  - `FingerprintBatch` 顺序与输入一致、长度相等
- **依赖**：Step 4、Step 5

---

## 阶段 C：服务链路

### Step 7 — HTTP API 层 + 单元测试

- **优先级**：P0
- **目标**：暴露两个接口并做健壮性兜底。
- **涉及文件（业务）**：
  - `internal/api/router.go`：`ServeMux` 注册 `POST /fingerprint`、`GET /health`
  - `internal/api/handler.go`：请求解析、批量识别、结构化错误、**recover 中间件**、方法/路径不匹配处理
  - `internal/api/dto.go`：错误响应结构
- **涉及文件（测试）**：`internal/api/handler_test.go`（`httptest`）
  - 覆盖：正常批量 200 / 非法 JSON 400 / 空数组 200 / 含 unknown 条目仍 200 / `/health` 200 / 错误方法 405 / panic 被 recover 返回 500 且不崩
- **验收标准**：接口契约与 `架构.md` 第九节一致。
- **依赖**：Step 6

### Step 8 — server 入口

- **优先级**：P0
- **目标**：装配依赖、启动服务、优雅关闭，并提供容器健康探测子命令。
- **涉及文件（业务）**：`cmd/server/main.go`
  - `main()`：`config.Load` → `rules.Load` → `engine.New` → `api.NewServer` → `ListenAndServe`
  - 优雅关闭：`signal.NotifyContext` + `srv.Shutdown`
  - 子命令 `healthcheck`：向自身 `GET /health` 探测，退出码 0/1（供 distroless 健康检查）
  - `slog` 结构化日志
- **验收标准**：本地 `go run ./cmd/server` 可启动，`/health` 返回 200，`Ctrl+C` 优雅退出。
- **依赖**：Step 7

### Step 9 — client 逻辑与入口 + 单元测试

- **优先级**：P0
- **目标**：独立程序读取本地 JSON → 调 server → 展示结果。
- **涉及文件（业务）**：
  - `internal/client/client.go`：HTTP 调用封装 + 结果渲染（可测）
  - `cmd/client/main.go`：`-file` 参数、调用、输出（stdout 打印 + 可选落盘）
- **涉及文件（测试）**：`internal/client/client_test.go`（`httptest.NewServer` 打桩）
  - 覆盖：正常返回解析 / server 5xx 报错处理 / 超时处理 / 结果渲染格式
- **验收标准**：`go run ./cmd/client -file testdata/input.json` 输出 23 条结果。
- **依赖**：Step 2、Step 7

---

## 阶段 D：交付与验证

### Step 10 — 容器化（多阶段构建 + 编排）

- **优先级**：P1
- **目标**：`docker compose up` 一键启动，满足生产级部署检查项。
- **涉及文件**：
  - `deploy/Dockerfile.server`：builder（`golang:1.23-alpine`，`CGO_ENABLED=0`，`-trimpath -ldflags="-s -w"`）→ runtime（`gcr.io/distroless/static:nonroot`）
  - `deploy/Dockerfile.client`：同上，产物为 client
  - `docker-compose.yml`
- **关键点（对应评估者检查项）**：
  1. **访问收敛**：自定义 `backend` 网络，server **不映射宿主机端口**，client 用服务名 `http://server:8080`
  2. **真实健康检测**：`healthcheck: ["CMD","/server","healthcheck"]`，`depends_on` 用 `condition: service_healthy`
  3. **编译打包**：多阶段 + 静态编译 + 去符号，运行层无工具链
  4. **权限收紧**：`user: nonroot`、`read_only: true`、`cap_drop: [ALL]`、`security_opt: [no-new-privileges:true]`、`tmpfs: /tmp`
  5. **规则解耦**：`rules.yaml` 以只读 volume 挂载到 `/etc/fingerprint/rules.yaml`，`FINGERPRINT_RULES` 指向它
- **验收标准**：
  - `docker compose up` 一次成功，client 输出正确结果
  - `docker inspect` 显示 healthcheck 为 healthy
  - 容器内 `whoami` 非 root（distroless 无 shell，通过 compose `user` 配置与镜像 `USER` 双重确认）
- **依赖**：Step 3、Step 8、Step 9

### Step 11 — 集成测试（端到端）

- **优先级**：P1
- **目标**：验证 client → server → engine 全链路，并与期望输出对拍。
- **涉及文件**：
  - `testdata/input.json`：题目示例输入（23 条）
  - `testdata/expected.json`：题目示例期望输出
  - `tests/integration_test.go`（`//go:build integration`）
- **关键点**：
  - 进程内启动真实 `http.Server`（随机端口），client 指向它跑完整链路
  - 读取 `testdata/input.json` → 调用 → 与 `expected.json` 逐字段对拍
  - 单独用例验证：**未知输入的条目返回 unknown 且服务存活**（后续正常请求仍成功）
- **验收标准**：`go test -tags=integration ./tests/...` 全绿。
- **依赖**：Step 10

### Step 12 — 文档与交付收尾

- **优先级**：P0
- **目标**：代码可自证，评估者离线克隆即可理解与运行。
- **涉及文件**：
  - `README.md`：项目简介、目录结构、`docker compose up` 用法、接口说明与示例、规则扩展方式、设计取舍（访问收敛 / 健康检测 / 权限收紧 / 规则解耦的说明）
  - 复核 `需求.md`、`架构.md`、`plan.md` 与实际实现一致
  - `Makefile`：补齐常用命令
- **验收标准**：仅凭 README 可完成启动、调用、验证；注释覆盖关键逻辑。
- **依赖**：Step 11

---

## 测试步骤汇总

| 步骤 | 测试类型 | 文件 | 核心断言 |
| --- | --- | --- | --- |
| Step 2 | 单元 | `internal/model/model_test.go` | JSON 往返、字段名 |
| Step 3 | 单元 | `internal/config/config_test.go` | 默认值、非法值回退 |
| Step 4 | 单元 | `internal/rules/*_test.go` | 加载、覆盖、回退、排序 |
| Step 5 | 单元 | `internal/engine/normalize_test.go` | 转义还原、二进制、截断 |
| Step 6 | 单元 | `internal/engine/engine_test.go` | 23 条示例逐条对拍、unknown 兜底 |
| Step 7 | 单元 | `internal/api/handler_test.go` | 200/400/405/500、recover |
| Step 9 | 单元 | `internal/client/client_test.go` | 正常/错误/超时/渲染 |
| Step 11 | 集成 | `tests/integration_test.go` | 全链路 + expected 对拍 + unknown 不崩 |

### 测试执行命令

```bash
make test                # 单元测试
make test-integration    # 集成测试（-tags=integration）
make test-race           # 并发竞态检测
```

---

## 里程碑与验收点

| 里程碑 | 完成标志 |
| --- | --- |
| M1 骨架可编译（Step 1–3） | `go build ./...` 通过 |
| M2 识别内核可用（Step 4–6） | 23 条示例单元测试通过 |
| M3 服务链路打通（Step 7–9） | 本地 client 打出正确结果 |
| M4 一键启动（Step 10–11） | `docker compose up` 成功，集成测试通过 |
| M5 可交付（Step 12） | README 完整，提交 GitHub |

---

## 风险与应对

| 风险 | 触发点 | 应对 |
| --- | --- | --- |
| YAML 依赖拉取失败 | Step 1 | 规则改 JSON，用标准库解析，结构不变 |
| 正则回溯导致慢 | Step 5/6 | 截断 banner + 避免贪婪嵌套正则 |
| distroless 无法健康检查 | Step 10 | 用二进制 `healthcheck` 子命令代替 `wget/curl` |
| 时间不足 | 全局 | 保 P0+P1；P2（单测细化、规则挂载）按其后的优先级补 |
| compose 启动顺序问题 | Step 10 | 必须用 `service_healthy` 而非仅 `depends_on` |
