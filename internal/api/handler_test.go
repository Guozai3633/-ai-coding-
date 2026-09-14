package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"banner-fingerprint/internal/engine"
	"banner-fingerprint/internal/model"
	"banner-fingerprint/internal/rules"
)

// newTestServer 用内置规则装配一个 API 服务，日志丢弃以免污染测试输出。
func newTestServer(t *testing.T) (*Server, http.Handler) {
	t.Helper()

	rs, _, err := rules.Load("")
	if err != nil {
		t.Fatalf("加载规则失败: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := New(engine.New(rs), logger)
	return s, s.Handler()
}

// doJSON 发一个请求并返回响应。
func doJSON(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()

	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}

	req := httptest.NewRequest(method, path, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestFingerprintEndpoint 验证正常批量识别。
func TestFingerprintEndpoint(t *testing.T) {
	_, h := newTestServer(t)

	body := `[
		{"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
		{"ip":"1.2.3.5","port":80,"banner":"HTTP/1.1 200 OK\\r\\nServer: nginx/1.24.0"}
	]`

	rec := doJSON(t, h, http.MethodPost, PathFingerprint, body)

	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d, 期望 200, body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, 期望 application/json", ct)
	}

	var got []model.Result
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("响应不是合法 JSON: %v body=%s", err, rec.Body.String())
	}

	want := []model.Result{
		{IP: "1.2.3.4", Port: 22, Protocol: "SSH", Product: "OpenSSH", Version: "8.9p1", OSHint: "Ubuntu", Confidence: 0.95},
		{IP: "1.2.3.5", Port: 80, Protocol: "HTTP", Product: "nginx", Version: "1.24.0", Confidence: 0.9},
	}
	if len(got) != len(want) {
		t.Fatalf("结果条数 = %d, 期望 %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("第 %d 条不符\n  得到 %+v\n  期望 %+v", i, got[i], want[i])
		}
	}
}

// TestFingerprintUnknownIsNotError 验证无法识别的条目返回 unknown 且整体仍是 200。
// 这是需求中「认不出来不允许报错崩掉」的接口级约束。
func TestFingerprintUnknownIsNotError(t *testing.T) {
	_, h := newTestServer(t)

	body := `[{"ip":"1.2.3.19","port":9999,"banner":"\\x16\\x03\\x01\\x00\\xa5"}]`
	rec := doJSON(t, h, http.MethodPost, PathFingerprint, body)

	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d, 期望 200（未知输入不是错误）", rec.Code)
	}

	var got []model.Result
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("结果条数 = %d, 期望 1", len(got))
	}
	if got[0].Protocol != model.ProtocolUnknown {
		t.Errorf("Protocol = %q, 期望 unknown", got[0].Protocol)
	}
	if got[0].IP != "1.2.3.19" || got[0].Port != 9999 {
		t.Errorf("IP/Port 未回填: %+v", got[0])
	}
}

// TestFingerprintEmptyArray 验证空数组返回空结果，且形状为 [] 而非 null。
func TestFingerprintEmptyArray(t *testing.T) {
	_, h := newTestServer(t)

	rec := doJSON(t, h, http.MethodPost, PathFingerprint, `[]`)

	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d, 期望 200", rec.Code)
	}
	if got := strings.TrimSpace(rec.Body.String()); got != `[]` {
		t.Errorf("响应体 = %q, 期望 []", got)
	}
}

// TestFingerprintNullBody 验证 null 请求体不报错（解析为空集）。
func TestFingerprintNullBody(t *testing.T) {
	_, h := newTestServer(t)

	rec := doJSON(t, h, http.MethodPost, PathFingerprint, `null`)

	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d, 期望 200, body=%s", rec.Code, rec.Body.String())
	}
	if got := strings.TrimSpace(rec.Body.String()); got != `[]` {
		t.Errorf("响应体 = %q, 期望 []", got)
	}
}

// TestFingerprintBadRequest 覆盖各类非法请求体，均应返回 400 且不崩。
func TestFingerprintBadRequest(t *testing.T) {
	_, h := newTestServer(t)

	cases := map[string]string{
		"非法 JSON": `{"ip":`,
		"类型不匹配":   `[{"ip":123,"port":"abc"}]`,
		"不是数组":    `{"ip":"1.2.3.4"}`,
		"尾部有多余内容": `[] []`,
		"尾部有垃圾字符": `[] garbage`,
		"空字符串请求体": ``,
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			rec := doJSON(t, h, http.MethodPost, PathFingerprint, body)

			if rec.Code != http.StatusBadRequest {
				t.Errorf("状态码 = %d, 期望 400, body=%s", rec.Code, rec.Body.String())
			}

			var errResp ErrorResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
				t.Fatalf("错误响应不是合法 JSON: %v body=%s", err, rec.Body.String())
			}
			if errResp.Error == "" {
				t.Errorf("错误响应缺少 error 字段: %s", rec.Body.String())
			}
		})
	}
}

// TestHealthEndpoint 验证健康检查接口。
func TestHealthEndpoint(t *testing.T) {
	_, h := newTestServer(t)

	rec := doJSON(t, h, http.MethodGet, PathHealth, "")

	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d, 期望 200", rec.Code)
	}

	var got HealthResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}
	if got.Status != "ok" {
		t.Errorf("Status = %q, 期望 ok", got.Status)
	}
	if got.Rules <= 0 {
		t.Errorf("Rules = %d, 期望大于 0", got.Rules)
	}
}

// TestMethodNotAllowed 验证路径存在但方法不符时返回 405 并带 Allow 头。
func TestMethodNotAllowed(t *testing.T) {
	_, h := newTestServer(t)

	cases := []struct {
		method string
		path   string
	}{
		{http.MethodGet, PathFingerprint},
		{http.MethodPut, PathFingerprint},
		{http.MethodPost, PathHealth},
		{http.MethodDelete, PathHealth},
	}

	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			rec := doJSON(t, h, tc.method, tc.path, "")

			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("状态码 = %d, 期望 405", rec.Code)
			}
			if allow := rec.Header().Get("Allow"); allow == "" {
				t.Error("405 响应缺少 Allow 头")
			}
		})
	}
}

// TestNotFound 验证未知路径返回 JSON 格式的 404。
func TestNotFound(t *testing.T) {
	_, h := newTestServer(t)

	rec := doJSON(t, h, http.MethodGet, "/does-not-exist", "")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("状态码 = %d, 期望 404", rec.Code)
	}

	var errResp ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("404 响应不是合法 JSON: %v body=%s", err, rec.Body.String())
	}
	if errResp.Error != "not found" {
		t.Errorf("Error = %q, 期望 not found", errResp.Error)
	}
}

// TestPanicRecoveredAndServiceSurvives 验证处理器 panic 被兜底，且进程/服务继续可用。
func TestPanicRecoveredAndServiceSurvives(t *testing.T) {
	s, h := newTestServer(t)

	// 注入一个必定 panic 的路由，模拟处理器内部异常。
	s.mux.HandleFunc("GET /panic", func(http.ResponseWriter, *http.Request) {
		panic("boom")
	})

	rec := doJSON(t, h, http.MethodGet, "/panic", "")
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("状态码 = %d, 期望 500", rec.Code)
	}

	var errResp ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("panic 后响应不是合法 JSON: %v body=%s", err, rec.Body.String())
	}

	// 关键：panic 之后服务仍能正常响应。
	health := doJSON(t, h, http.MethodGet, PathHealth, "")
	if health.Code != http.StatusOK {
		t.Errorf("panic 之后 /health 状态码 = %d, 期望 200（服务不应崩溃）", health.Code)
	}
}

// TestFingerprintLargeBatch 验证较大批量下结果与输入等长同序。
func TestFingerprintLargeBatch(t *testing.T) {
	_, h := newTestServer(t)

	const n = 500
	recs := make([]model.Record, 0, n)
	banners := []string{
		"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3",
		`HTTP/1.1 200 OK\r\nServer: nginx/1.24.0`,
		"+PONG",
		`QUIT\r\n`,
	}
	for i := 0; i < n; i++ {
		recs = append(recs, model.Record{
			IP:     "10.0.0.1",
			Port:   1000 + i,
			Banner: banners[i%len(banners)],
		})
	}

	payload, err := json.Marshal(recs)
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}

	rec := doJSON(t, h, http.MethodPost, PathFingerprint, string(payload))
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d, 期望 200", rec.Code)
	}

	var got []model.Result
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}
	if len(got) != n {
		t.Fatalf("结果条数 = %d, 期望 %d", len(got), n)
	}
	for i := range got {
		if got[i].IP != recs[i].IP || got[i].Port != recs[i].Port {
			t.Fatalf("第 %d 条顺序错乱: 得到 %s:%d, 期望 %s:%d",
				i, got[i].IP, got[i].Port, recs[i].IP, recs[i].Port)
		}
	}
}
