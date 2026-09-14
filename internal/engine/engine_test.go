package engine

import (
	"sync"
	"testing"

	"banner-fingerprint/internal/model"
	"banner-fingerprint/internal/rules"
)

// newTestEngine 用内置规则构造引擎。
func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	rs, _, err := rules.Load("")
	if err != nil {
		t.Fatalf("加载内置规则失败: %v", err)
	}
	return New(rs)
}

// sampleCases 是需求文档中给出的全部 20 条样例数据。
//
// 前 7 条带期望值为题目明示（含 confidence），其余为按规则推导的自测期望。
// banner 采用扫描器常见的可打印转义形态（\r\n、\x00），用于同时验证归一化。
var sampleCases = []struct {
	rec  model.Record
	want model.Result
}{
	{
		rec:  model.Record{IP: "1.2.3.4", Port: 22, Banner: `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3`},
		want: model.Result{IP: "1.2.3.4", Port: 22, Protocol: "SSH", Product: "OpenSSH", Version: "8.9p1", OSHint: "Ubuntu", Confidence: 0.95},
	},
	{
		rec:  model.Record{IP: "1.2.3.5", Port: 80, Banner: `HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html`},
		want: model.Result{IP: "1.2.3.5", Port: 80, Protocol: "HTTP", Product: "nginx", Version: "1.24.0", OSHint: "", Confidence: 0.9},
	},
	{
		rec:  model.Record{IP: "1.2.3.6", Port: 443, Banner: `HTTP/1.1 200 OK\r\nServer: Apache/2.4.57`},
		want: model.Result{IP: "1.2.3.6", Port: 443, Protocol: "HTTP", Product: "Apache", Version: "2.4.57", OSHint: "", Confidence: 0.9},
	},
	{
		rec:  model.Record{IP: "1.2.3.7", Port: 3306, Banner: `J\x00\x00\x00\n8.0.32\x00`},
		want: model.Result{IP: "1.2.3.7", Port: 3306, Protocol: "MySQL", Product: "MySQL", Version: "8.0.32", OSHint: "", Confidence: 0.9},
	},
	{
		rec:  model.Record{IP: "1.2.3.8", Port: 6379, Banner: `-ERR wrong number of arguments for 'get' command`},
		want: model.Result{IP: "1.2.3.8", Port: 6379, Protocol: "Redis", Product: "Redis", Version: "", OSHint: "", Confidence: 0.7},
	},
	{
		rec:  model.Record{IP: "1.2.3.9", Port: 21, Banner: `220 ProFTPD 1.3.7 Server (ProFTPD)`},
		want: model.Result{IP: "1.2.3.9", Port: 21, Protocol: "FTP", Product: "ProFTPD", Version: "1.3.7", OSHint: "", Confidence: 0.9},
	},
	{
		rec:  model.Record{IP: "1.2.3.10", Port: 8080, Banner: `HTTP/1.1 404 Not Found\r\nServer: Jetty/9.4.51`},
		want: model.Result{IP: "1.2.3.10", Port: 8080, Protocol: "HTTP", Product: "Jetty", Version: "9.4.51", OSHint: "", Confidence: 0.85},
	},

	// ---- 以下为同一批数据中的其它形态（自测期望） ----
	{
		rec:  model.Record{IP: "1.2.3.11", Port: 22, Banner: `SSH-2.0-OpenSSH_9.3 Debian-1`},
		want: model.Result{IP: "1.2.3.11", Port: 22, Protocol: "SSH", Product: "OpenSSH", Version: "9.3", OSHint: "Debian", Confidence: 0.95},
	},
	{
		rec:  model.Record{IP: "1.2.3.12", Port: 80, Banner: `HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)`},
		want: model.Result{IP: "1.2.3.12", Port: 80, Protocol: "HTTP", Product: "nginx", Version: "1.18.0", OSHint: "Ubuntu", Confidence: 0.9},
	},
	{
		rec:  model.Record{IP: "1.2.3.13", Port: 443, Banner: `HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)`},
		want: model.Result{IP: "1.2.3.13", Port: 443, Protocol: "HTTP", Product: "Apache", Version: "2.4.41", OSHint: "Ubuntu", Confidence: 0.9},
	},
	{
		rec:  model.Record{IP: "1.2.3.14", Port: 3306, Banner: `J\x00\x00\x00\n5.7.42\x00`},
		want: model.Result{IP: "1.2.3.14", Port: 3306, Protocol: "MySQL", Product: "MySQL", Version: "5.7.42", OSHint: "", Confidence: 0.9},
	},
	{
		rec:  model.Record{IP: "1.2.3.15", Port: 6379, Banner: `+PONG`},
		want: model.Result{IP: "1.2.3.15", Port: 6379, Protocol: "Redis", Product: "Redis", Version: "", OSHint: "", Confidence: 0.7},
	},
	{
		rec:  model.Record{IP: "1.2.3.16", Port: 21, Banner: `220 (vsFTPd 3.0.5)`},
		want: model.Result{IP: "1.2.3.16", Port: 21, Protocol: "FTP", Product: "vsFTPd", Version: "3.0.5", OSHint: "", Confidence: 0.9},
	},
	{
		rec:  model.Record{IP: "1.2.3.17", Port: 8443, Banner: `HTTP/1.1 200 OK\r\nServer: nginx/1.25.3`},
		want: model.Result{IP: "1.2.3.17", Port: 8443, Protocol: "HTTP", Product: "nginx", Version: "1.25.3", OSHint: "", Confidence: 0.9},
	},
	{
		rec:  model.Record{IP: "1.2.3.18", Port: 22, Banner: `SSH-1.99-OpenSSH_4.3`},
		want: model.Result{IP: "1.2.3.18", Port: 22, Protocol: "SSH", Product: "OpenSSH", Version: "4.3", OSHint: "", Confidence: 0.95},
	},
	{
		rec:  model.Record{IP: "1.2.3.19", Port: 9999, Banner: `\x16\x03\x01\x00\xa5\x01\x00\x00\xa1`},
		want: model.Result{IP: "1.2.3.19", Port: 9999, Protocol: model.ProtocolUnknown, Confidence: 0},
	},
	{
		rec:  model.Record{IP: "1.2.3.20", Port: 8888, Banner: `HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0`},
		want: model.Result{IP: "1.2.3.20", Port: 8888, Protocol: "HTTP", Product: "IIS", Version: "10.0", OSHint: "", Confidence: 0.9},
	},
	{
		rec:  model.Record{IP: "1.2.3.21", Port: 6379, Banner: `-NOAUTH Authentication required.`},
		want: model.Result{IP: "1.2.3.21", Port: 6379, Protocol: "Redis", Product: "Redis", Version: "", OSHint: "", Confidence: 0.7},
	},
	{
		rec:  model.Record{IP: "1.2.3.22", Port: 21, Banner: `220 Welcome to Pure-FTPd`},
		want: model.Result{IP: "1.2.3.22", Port: 21, Protocol: "FTP", Product: "Pure-FTPd", Version: "", OSHint: "", Confidence: 0.9},
	},
	{
		rec:  model.Record{IP: "1.2.3.23", Port: 12345, Banner: `QUIT\r\n`},
		want: model.Result{IP: "1.2.3.23", Port: 12345, Protocol: model.ProtocolUnknown, Confidence: 0},
	},
}

// TestSampleData 逐条对拍需求文档中的全部样例数据。
// 这是识别深度的主要验收测试。
func TestSampleData(t *testing.T) {
	eng := newTestEngine(t)

	for _, tc := range sampleCases {
		t.Run(tc.rec.IP, func(t *testing.T) {
			got := eng.Fingerprint(tc.rec)
			if got != tc.want {
				t.Errorf("识别结果不符\n  输入 %+v\n  得到 %+v\n  期望 %+v", tc.rec, got, tc.want)
			}
		})
	}
}

// TestSampleBatchMatchesInputOrder 验证批量接口结果与输入等长同序。
func TestSampleBatchMatchesInputOrder(t *testing.T) {
	eng := newTestEngine(t)

	recs := make([]model.Record, 0, len(sampleCases))
	for _, tc := range sampleCases {
		recs = append(recs, tc.rec)
	}

	got := eng.FingerprintBatch(recs)

	if len(got) != len(recs) {
		t.Fatalf("结果长度 = %d, 期望 %d", len(got), len(recs))
	}
	for i := range recs {
		if got[i].IP != recs[i].IP || got[i].Port != recs[i].Port {
			t.Errorf("第 %d 条顺序错乱: 得到 %s:%d, 期望 %s:%d",
				i, got[i].IP, got[i].Port, recs[i].IP, recs[i].Port)
		}
		if got[i] != sampleCases[i].want {
			t.Errorf("第 %d 条结果不符\n  得到 %+v\n  期望 %+v", i, got[i], sampleCases[i].want)
		}
	}
}

// TestUnknownNeverFails 覆盖各类「认不出来」的输入，全部应得到 unknown 而非 panic。
func TestUnknownNeverFails(t *testing.T) {
	eng := newTestEngine(t)

	cases := []struct {
		name string
		rec  model.Record
	}{
		{"空 banner", model.Record{IP: "1.1.1.1", Port: 80, Banner: ""}},
		{"纯空白", model.Record{IP: "1.1.1.1", Port: 80, Banner: "   "}},
		{"未知明文", model.Record{IP: "1.1.1.1", Port: 12345, Banner: `QUIT\r\n`}},
		{"TLS 握手", model.Record{IP: "1.1.1.1", Port: 9999, Banner: `\x16\x03\x01\x00\xa5\x01\x00\x00\xa1`}},
		{"二进制乱码", model.Record{IP: "1.1.1.1", Port: 1, Banner: "\xff\xfe\x80\x81"}},
		{"孤立反斜杠", model.Record{IP: "1.1.1.1", Port: 1, Banner: `\`}},
		{"超长噪声", model.Record{IP: "1.1.1.1", Port: 1, Banner: longNoise()}},
		{"端口为零", model.Record{IP: "1.1.1.1", Port: 0, Banner: "hello"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("识别时 panic: %v", r)
				}
			}()

			got := eng.Fingerprint(tc.rec)
			if got.Protocol != model.ProtocolUnknown {
				t.Errorf("Protocol = %q, 期望 %q", got.Protocol, model.ProtocolUnknown)
			}
			if got.Confidence != 0 {
				t.Errorf("Confidence = %v, 期望 0", got.Confidence)
			}
			if got.IP != tc.rec.IP || got.Port != tc.rec.Port {
				t.Errorf("IP/Port 未回填: %+v", got)
			}
		})
	}
}

// TestRawControlCharacters 验证输入已经是真实控制字符时同样能识别。
//
// 评估数据可能是用 JSON 的 \u0000 / \r\n 转义写入的，解析出来就是真实字节，
// 与样例中的可打印转义形态必须得到一致结果。
func TestRawControlCharacters(t *testing.T) {
	eng := newTestEngine(t)

	cases := []struct {
		name string
		rec  model.Record
		want model.Result
	}{
		{
			name: "HTTP 真实 CRLF",
			rec:  model.Record{IP: "9.9.9.1", Port: 80, Banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html"},
			want: model.Result{IP: "9.9.9.1", Port: 80, Protocol: "HTTP", Product: "nginx", Version: "1.24.0", Confidence: 0.9},
		},
		{
			name: "MySQL 真实 NUL",
			rec:  model.Record{IP: "9.9.9.2", Port: 3306, Banner: "J\x00\x00\x00\n8.0.32\x00"},
			want: model.Result{IP: "9.9.9.2", Port: 3306, Protocol: "MySQL", Product: "MySQL", Version: "8.0.32", Confidence: 0.9},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := eng.Fingerprint(tc.rec); got != tc.want {
				t.Errorf("识别结果不符\n  得到 %+v\n  期望 %+v", got, tc.want)
			}
		})
	}
}

// TestNonStandardPortStillIdentified 验证端口只是弱提示：
// 服务跑在非典型端口上，协议/产品/版本依然要识别出来。
func TestNonStandardPortStillIdentified(t *testing.T) {
	eng := newTestEngine(t)

	cases := []struct {
		name      string
		rec       model.Record
		wantProto string
		wantProd  string
		wantVer   string
	}{
		{
			name:      "nginx 跑在 3000",
			rec:       model.Record{IP: "9.9.9.3", Port: 3000, Banner: `HTTP/1.1 200 OK\r\nServer: nginx/1.20.0`},
			wantProto: "HTTP", wantProd: "nginx", wantVer: "1.20.0",
		},
		{
			name:      "SSH 跑在 2222",
			rec:       model.Record{IP: "9.9.9.4", Port: 2222, Banner: `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3`},
			wantProto: "SSH", wantProd: "OpenSSH", wantVer: "8.9p1",
		},
		{
			name:      "Redis 跑在 7777",
			rec:       model.Record{IP: "9.9.9.5", Port: 7777, Banner: `+PONG`},
			wantProto: "Redis", wantProd: "Redis", wantVer: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := eng.Fingerprint(tc.rec)
			if got.Protocol != tc.wantProto {
				t.Errorf("Protocol = %q, 期望 %q", got.Protocol, tc.wantProto)
			}
			if got.Product != tc.wantProd {
				t.Errorf("Product = %q, 期望 %q", got.Product, tc.wantProd)
			}
			if got.Version != tc.wantVer {
				t.Errorf("Version = %q, 期望 %q", got.Version, tc.wantVer)
			}
		})
	}
}

// TestEmptyRulesetNeverPanics 验证规则集为空时服务仍可用（全部 unknown）。
func TestEmptyRulesetNeverPanics(t *testing.T) {
	eng := New(nil)

	if eng.RuleCount() != 0 {
		t.Errorf("RuleCount = %d, 期望 0", eng.RuleCount())
	}
	got := eng.Fingerprint(model.Record{IP: "1.1.1.1", Port: 80, Banner: `HTTP/1.1 200 OK`})
	if got.Protocol != model.ProtocolUnknown {
		t.Errorf("Protocol = %q, 期望 unknown", got.Protocol)
	}
}

// TestEngineConcurrentUse 验证引擎无状态、可并发调用（配合 -race 使用）。
func TestEngineConcurrentUse(t *testing.T) {
	eng := newTestEngine(t)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, tc := range sampleCases {
				if got := eng.Fingerprint(tc.rec); got != tc.want {
					t.Errorf("并发识别结果不符: %+v", got)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// longNoise 生成一段超长且不含任何特征的内容。
func longNoise() string {
	const chunk = "the quick brown fox jumps over the lazy dog "
	out := make([]byte, 0, 200000)
	for len(out) < 200000 {
		out = append(out, chunk...)
	}
	return string(out)
}
