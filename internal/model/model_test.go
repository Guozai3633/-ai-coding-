package model

import (
	"encoding/json"
	"reflect"
	"testing"
)

// jsonFieldNames 按结构体声明顺序返回 JSON 字段名。
func jsonFieldNames(v any) []string {
	t := reflect.TypeOf(v)
	names := make([]string, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		names = append(names, t.Field(i).Tag.Get("json"))
	}
	return names
}

func assertFieldNames(t *testing.T, v any, want []string) {
	t.Helper()
	got := jsonFieldNames(v)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("JSON 字段不符:\n  得到 %v\n  期望 %v", got, want)
	}
}

// TestResultJSONTags 锁定输出契约的字段名与顺序。
// 这些标签是接口协议的一部分，改动即为破坏性变更。
func TestResultJSONTags(t *testing.T) {
	assertFieldNames(t, Result{}, []string{
		"ip", "port", "protocol", "product", "version", "os_hint", "confidence",
	})
}

// TestRecordJSONTags 锁定输入契约的字段名与顺序。
func TestRecordJSONTags(t *testing.T) {
	assertFieldNames(t, Record{}, []string{"ip", "port", "banner"})
}

// TestResultRoundTrip 验证序列化 / 反序列化往返一致。
func TestResultRoundTrip(t *testing.T) {
	in := Result{
		IP:         "1.2.3.4",
		Port:       22,
		Protocol:   "SSH",
		Product:    "OpenSSH",
		Version:    "8.9p1",
		OSHint:     "Ubuntu",
		Confidence: 0.95,
	}

	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}

	var out Result
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("反序列化失败: %v", err)
	}

	if out != in {
		t.Errorf("往返后不一致:\n  得到 %+v\n  期望 %+v", out, in)
	}
}

// TestResultJSONShape 固定一条结果的 JSON 形态，防止字段名被无意改动。
func TestResultJSONShape(t *testing.T) {
	got, err := json.Marshal(Result{
		IP: "1.2.3.5", Port: 80, Protocol: "HTTP", Product: "nginx",
		Version: "1.24.0", OSHint: "", Confidence: 0.9,
	})
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}

	want := `{"ip":"1.2.3.5","port":80,"protocol":"HTTP","product":"nginx","version":"1.24.0","os_hint":"","confidence":0.9}`
	if string(got) != want {
		t.Errorf("JSON 形态不符:\n  得到 %s\n  期望 %s", got, want)
	}
}

// TestNewUnknown 验证兜底结果：IP/Port 回填、协议为 unknown、置信度为 0。
func TestNewUnknown(t *testing.T) {
	rec := Record{IP: "10.0.0.1", Port: 9999, Banner: `\x16\x03\x01`}
	got := NewUnknown(rec)

	if got.IP != rec.IP || got.Port != rec.Port {
		t.Errorf("IP/Port 未回填: %+v", got)
	}
	if got.Protocol != ProtocolUnknown {
		t.Errorf("Protocol = %q, 期望 %q", got.Protocol, ProtocolUnknown)
	}
	if got.Confidence != 0 {
		t.Errorf("Confidence = %v, 期望 0", got.Confidence)
	}
	if got.Product != "" || got.Version != "" || got.OSHint != "" {
		t.Errorf("无法识别时 product/version/os_hint 应为空: %+v", got)
	}
}
