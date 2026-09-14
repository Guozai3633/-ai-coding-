package client

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"banner-fingerprint/internal/model"
)

func TestReadRecords(t *testing.T) {
	t.Run("正常读取", func(t *testing.T) {
		path := writeTempFile(t, `[
			{"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
			{"ip":"1.2.3.5","port":80,"banner":"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0"}
		]`)

		recs, err := ReadRecords(path)
		if err != nil {
			t.Fatalf("读取失败: %v", err)
		}
		if len(recs) != 2 {
			t.Fatalf("记录数 = %d, 期望 2", len(recs))
		}
		if recs[0].IP != "1.2.3.4" || recs[0].Port != 22 {
			t.Errorf("第 1 条不符: %+v", recs[0])
		}
		if recs[1].Banner != "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0" {
			t.Errorf("banner 未正确解析: %q", recs[1].Banner)
		}
	})

	t.Run("空数组", func(t *testing.T) {
		path := writeTempFile(t, `[]`)
		recs, err := ReadRecords(path)
		if err != nil {
			t.Fatalf("读取失败: %v", err)
		}
		if len(recs) != 0 {
			t.Errorf("记录数 = %d, 期望 0", len(recs))
		}
	})

	t.Run("文件不存在", func(t *testing.T) {
		if _, err := ReadRecords(filepath.Join(t.TempDir(), "nope.json")); err == nil {
			t.Error("期望报错，但成功了")
		}
	})

	t.Run("非法 JSON", func(t *testing.T) {
		path := writeTempFile(t, `{"ip":`)
		if _, err := ReadRecords(path); err == nil {
			t.Error("期望报错，但成功了")
		}
	})

	t.Run("不是数组", func(t *testing.T) {
		path := writeTempFile(t, `{"ip":"1.2.3.4"}`)
		if _, err := ReadRecords(path); err == nil {
			t.Error("期望报错，但成功了")
		}
	})
}

func TestFingerprintSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("方法 = %s, 期望 POST", r.Method)
		}
		if r.URL.Path != "/fingerprint" {
			t.Errorf("路径 = %s, 期望 /fingerprint", r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, 期望 application/json", ct)
		}

		var recs []model.Record
		if err := json.NewDecoder(r.Body).Decode(&recs); err != nil {
			t.Errorf("请求体解析失败: %v", err)
		}
		if len(recs) != 1 {
			t.Errorf("收到 %d 条记录, 期望 1", len(recs))
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]model.Result{
			{IP: "1.2.3.4", Port: 22, Protocol: "SSH", Product: "OpenSSH", Version: "8.9p1", OSHint: "Ubuntu", Confidence: 0.95},
		})
	}))
	defer srv.Close()

	c := New(srv.URL, 5*time.Second)
	got, err := c.Fingerprint(context.Background(), []model.Record{
		{IP: "1.2.3.4", Port: 22, Banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
	})
	if err != nil {
		t.Fatalf("调用失败: %v", err)
	}

	want := model.Result{IP: "1.2.3.4", Port: 22, Protocol: "SSH", Product: "OpenSSH", Version: "8.9p1", OSHint: "Ubuntu", Confidence: 0.95}
	if len(got) != 1 || got[0] != want {
		t.Errorf("结果不符:\n  得到 %+v\n  期望 %+v", got, want)
	}
}

// TestFingerprintServerError 验证服务端错误响应被还原成可读 error。
func TestFingerprintServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid request body","detail":"unexpected EOF"}`))
	}))
	defer srv.Close()

	c := New(srv.URL, 5*time.Second)
	_, err := c.Fingerprint(context.Background(), []model.Record{{IP: "1.1.1.1", Port: 1}})

	if err == nil {
		t.Fatal("期望报错，但成功了")
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("错误信息未包含状态码: %v", err)
	}
	if !strings.Contains(err.Error(), "invalid request body") {
		t.Errorf("错误信息未包含服务端详情: %v", err)
	}
}

// TestFingerprintInvalidResponse 验证服务端返回非法 JSON 时报错而非静默成功。
func TestFingerprintInvalidResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`not json at all`))
	}))
	defer srv.Close()

	c := New(srv.URL, 5*time.Second)
	if _, err := c.Fingerprint(context.Background(), []model.Record{{IP: "1.1.1.1", Port: 1}}); err == nil {
		t.Error("期望报错，但成功了")
	}
}

// TestFingerprintTimeout 验证超时被正确处理。
func TestFingerprintTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(300 * time.Millisecond)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	c := New(srv.URL, 50*time.Millisecond)
	if _, err := c.Fingerprint(context.Background(), []model.Record{{IP: "1.1.1.1", Port: 1}}); err == nil {
		t.Error("期望超时报错，但成功了")
	}
}

// TestFingerprintConnectionRefused 验证服务不可达时报错。
func TestFingerprintConnectionRefused(t *testing.T) {
	// 起一个服务再立刻关掉，得到一个确定不可达的地址。
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()

	c := New(url, time.Second)
	if _, err := c.Fingerprint(context.Background(), []model.Record{{IP: "1.1.1.1", Port: 1}}); err == nil {
		t.Error("期望连接失败报错，但成功了")
	}
}

// TestFingerprintContextCancelled 验证 context 取消能中断请求。
func TestFingerprintContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(300 * time.Millisecond)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c := New(srv.URL, 5*time.Second)
	if _, err := c.Fingerprint(ctx, []model.Record{{IP: "1.1.1.1", Port: 1}}); err == nil {
		t.Error("期望 context 取消报错，但成功了")
	}
}

func TestRender(t *testing.T) {
	results := []model.Result{
		{IP: "1.2.3.4", Port: 22, Protocol: "SSH", Product: "OpenSSH", Version: "8.9p1", OSHint: "Ubuntu", Confidence: 0.95},
		{IP: "1.2.3.8", Port: 6379, Protocol: "Redis", Product: "Redis", Version: "", OSHint: "", Confidence: 0.7},
	}

	var buf bytes.Buffer
	if err := Render(&buf, results); err != nil {
		t.Fatalf("渲染失败: %v", err)
	}
	out := buf.String()

	for _, want := range []string{"IP", "PROTOCOL", "CONFIDENCE", "1.2.3.4", "OpenSSH", "8.9p1", "Ubuntu", "0.95", "0.70"} {
		if !strings.Contains(out, want) {
			t.Errorf("输出缺少 %q\n%s", want, out)
		}
	}

	// 空字段应显示为 "-"，与「漏输出」区分开。
	if !strings.Contains(out, "-") {
		t.Errorf("空字段未显示为 -\n%s", out)
	}
}

func TestRenderJSON(t *testing.T) {
	results := []model.Result{
		{IP: "1.2.3.4", Port: 22, Protocol: "SSH", Product: "OpenSSH", Version: "8.9p1", OSHint: "Ubuntu", Confidence: 0.95},
	}

	var buf bytes.Buffer
	if err := RenderJSON(&buf, results); err != nil {
		t.Fatalf("渲染失败: %v", err)
	}

	var got []model.Result
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("输出不是合法 JSON: %v\n%s", err, buf.String())
	}
	if len(got) != 1 || got[0] != results[0] {
		t.Errorf("往返结果不符:\n  得到 %+v\n  期望 %+v", got, results)
	}
	if !strings.Contains(buf.String(), `"os_hint"`) {
		t.Errorf("JSON 字段名不符: %s", buf.String())
	}
}

// writeTempFile 写一个临时文件并返回路径。
func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("写临时文件失败: %v", err)
	}
	return path
}
