//go:build integration

// Package tests 是端到端集成测试。
//
// 与各包内的单元测试不同，这里不替换任何组件：真实启动一个 HTTP 服务
// （与 cmd/server 装配方式一致），用真实的 client 包发起请求，读取真实的
// testdata 文件，并逐字段与 testdata/expected.json 对拍。
//
// 因此本文件带 integration 构建标签，默认不参与 `go test ./...`：
//
//	go test -tags=integration ./tests/... -v
package tests

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"banner-fingerprint/internal/api"
	"banner-fingerprint/internal/client"
	"banner-fingerprint/internal/engine"
	"banner-fingerprint/internal/model"
	"banner-fingerprint/internal/rules"
)

// testdataDir 指向仓库根目录下的 testdata。
const testdataDir = "../testdata"

// startServer 以与 cmd/server 相同的方式装配依赖，并在随机端口上启动真实 HTTP 服务。
// 返回服务基地址，测试结束时自动关闭。
func startServer(t *testing.T) string {
	t.Helper()

	rs, _, err := rules.Load("")
	if err != nil {
		t.Fatalf("加载规则失败: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// 监听 127.0.0.1 的随机空闲端口，避免与其它测试或本机服务冲突。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}

	srv := &http.Server{
		Handler:           api.New(engine.New(rs), logger).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			t.Logf("服务退出: %v", err)
		}
	}()

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	return "http://" + ln.Addr().String()
}

// TestEndToEndMatchesExpected 跑通 client -> server -> engine 全链路，
// 并把结果与 testdata/expected.json 逐字段对拍。
//
// 这是最接近验收方式的测试：给定输入文件，产出必须与期望完全一致。
func TestEndToEndMatchesExpected(t *testing.T) {
	baseURL := startServer(t)

	inputPath := filepath.Join(testdataDir, "input.json")
	expectedPath := filepath.Join(testdataDir, "expected.json")

	recs, err := client.ReadRecords(inputPath)
	if err != nil {
		t.Fatalf("读取输入失败: %v", err)
	}
	if len(recs) == 0 {
		t.Fatal("输入为空，测试无意义")
	}

	want := readExpected(t, expectedPath)
	if len(want) != len(recs) {
		t.Fatalf("期望数据 %d 条与输入 %d 条不匹配", len(want), len(recs))
	}

	c := client.New(baseURL, 10*time.Second)
	got, err := c.Fingerprint(context.Background(), recs)
	if err != nil {
		t.Fatalf("调用服务端失败: %v", err)
	}

	if len(got) != len(want) {
		t.Fatalf("结果条数 = %d, 期望 %d", len(got), len(want))
	}

	for i := range want {
		if got[i] != want[i] {
			t.Errorf("第 %d 条不符 (输入 %s:%d)\n  得到 %+v\n  期望 %+v",
				i, recs[i].IP, recs[i].Port, got[i], want[i])
		}
	}

	// 统计识别覆盖率，便于人工确认识别深度。
	var identified int
	for _, r := range got {
		if r.Protocol != model.ProtocolUnknown {
			identified++
		}
	}
	t.Logf("全链路识别完成：共 %d 条，识别出 %d 条，unknown %d 条",
		len(got), identified, len(got)-identified)
}

// TestEndToEndUnknownDoesNotBreakService 验证「认不出来不报错、服务不崩」：
// 连续提交未知输入后，服务必须仍能正常处理后续请求。
func TestEndToEndUnknownDoesNotBreakService(t *testing.T) {
	baseURL := startServer(t)

	c := client.New(baseURL, 10*time.Second)
	ctx := context.Background()

	// 一批全是认不出来的输入。
	unknownBatch := []model.Record{
		{IP: "10.0.0.1", Port: 9999, Banner: `\x16\x03\x01\x00\xa5\x01\x00\x00\xa1`},
		{IP: "10.0.0.2", Port: 12345, Banner: `QUIT\r\n`},
		{IP: "10.0.0.3", Port: 1, Banner: ""},
		{IP: "10.0.0.4", Port: 2, Banner: "\xff\xfe\x80\x81"},
	}

	got, err := c.Fingerprint(ctx, unknownBatch)
	if err != nil {
		t.Fatalf("未知输入不应导致请求失败: %v", err)
	}
	if len(got) != len(unknownBatch) {
		t.Fatalf("结果条数 = %d, 期望 %d", len(got), len(unknownBatch))
	}
	for i, r := range got {
		if r.Protocol != model.ProtocolUnknown {
			t.Errorf("第 %d 条 Protocol = %q, 期望 unknown", i, r.Protocol)
		}
		if r.Confidence != 0 {
			t.Errorf("第 %d 条 Confidence = %v, 期望 0", i, r.Confidence)
		}
		if r.IP != unknownBatch[i].IP {
			t.Errorf("第 %d 条 IP 未回填: %q", i, r.IP)
		}
	}

	// 关键断言：经历未知输入之后，正常输入依然能正确识别。
	normal := []model.Record{
		{IP: "10.0.0.5", Port: 22, Banner: `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3`},
	}
	got, err = c.Fingerprint(ctx, normal)
	if err != nil {
		t.Fatalf("未知输入之后服务应仍可用: %v", err)
	}
	if got[0].Protocol != "SSH" || got[0].Product != "OpenSSH" || got[0].Version != "8.9p1" {
		t.Errorf("未知输入之后识别异常: %+v", got[0])
	}
}

// TestEndToEndEmptyInput 验证空输入不会让服务端出错。
func TestEndToEndEmptyInput(t *testing.T) {
	baseURL := startServer(t)

	c := client.New(baseURL, 10*time.Second)
	got, err := c.Fingerprint(context.Background(), []model.Record{})
	if err != nil {
		t.Fatalf("空输入不应报错: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("结果条数 = %d, 期望 0", len(got))
	}
}

// TestEndToEndLargeBatch 验证较大批量下端到端依然正确、有序。
func TestEndToEndLargeBatch(t *testing.T) {
	baseURL := startServer(t)

	const n = 2000
	banners := []string{
		`SSH-2.0-OpenSSH_8.9p1 Ubuntu-3`,
		`HTTP/1.1 200 OK\r\nServer: nginx/1.24.0`,
		`220 (vsFTPd 3.0.5)`,
		`+PONG`,
	}

	recs := make([]model.Record, 0, n)
	for i := 0; i < n; i++ {
		recs = append(recs, model.Record{IP: "10.1.0.1", Port: 10000 + i, Banner: banners[i%len(banners)]})
	}

	c := client.New(baseURL, 30*time.Second)
	got, err := c.Fingerprint(context.Background(), recs)
	if err != nil {
		t.Fatalf("批量识别失败: %v", err)
	}
	if len(got) != n {
		t.Fatalf("结果条数 = %d, 期望 %d", len(got), n)
	}

	for i := range recs {
		if got[i].IP != recs[i].IP || got[i].Port != recs[i].Port {
			t.Fatalf("第 %d 条顺序错乱: 得到 %s:%d, 期望 %s:%d",
				i, got[i].IP, got[i].Port, recs[i].IP, recs[i].Port)
		}
		if got[i].Protocol == model.ProtocolUnknown {
			t.Fatalf("第 %d 条未识别: %+v", i, got[i])
		}
	}
}

// TestEndToEndHealth 验证健康检查接口在全链路下可用（对应容器 healthcheck）。
func TestEndToEndHealth(t *testing.T) {
	baseURL := startServer(t)

	resp, err := http.Get(baseURL + api.PathHealth)
	if err != nil {
		t.Fatalf("健康检查请求失败: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("状态码 = %d, 期望 200", resp.StatusCode)
	}

	var payload api.HealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	if payload.Status != "ok" {
		t.Errorf("Status = %q, 期望 ok", payload.Status)
	}
	if payload.Rules != 13 {
		t.Errorf("Rules = %d, 期望 13（内置规则条数）", payload.Rules)
	}
}

// readExpected 读取期望结果文件。
func readExpected(t *testing.T, path string) []model.Result {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取期望文件失败: %v", err)
	}

	var want []model.Result
	if err := json.Unmarshal(data, &want); err != nil {
		t.Fatalf("解析期望文件失败: %v", err)
	}
	return want
}
