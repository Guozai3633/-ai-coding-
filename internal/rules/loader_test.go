package rules

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadBuiltin 验证内置规则可用，且覆盖需求要求的全部协议。
func TestLoadBuiltin(t *testing.T) {
	rs, source, err := Load("")
	if err != nil {
		t.Fatalf("加载内置规则失败: %v", err)
	}
	if source != "built-in" {
		t.Errorf("来源 = %q, 期望 built-in", source)
	}
	if len(rs) == 0 {
		t.Fatal("内置规则为空")
	}

	wantProtocols := []string{"SSH", "HTTP", "MySQL", "Redis", "FTP"}
	have := map[string]bool{}
	for _, r := range rs {
		have[r.Protocol] = true
	}
	for _, p := range wantProtocols {
		if !have[p] {
			t.Errorf("内置规则缺少协议 %s", p)
		}
	}
}

// TestLoadBuiltinIsSorted 验证加载后已按优先级排序，engine 可直接顺序匹配。
func TestLoadBuiltinIsSorted(t *testing.T) {
	rs, _, err := Load("")
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	for i := 1; i < len(rs); i++ {
		if rs[i-1].Priority < rs[i].Priority {
			t.Fatalf("规则未按优先级降序排列: %s(%d) 在 %s(%d) 之前",
				rs[i-1].ID, rs[i-1].Priority, rs[i].ID, rs[i].Priority)
		}
	}
}

// TestLoadExternalOverride 验证外部规则文件覆盖内置规则。
func TestLoadExternalOverride(t *testing.T) {
	path := writeTempRules(t, `
version: 1
rules:
  - id: custom-only
    protocol: CUSTOM
    product: TestProduct
    priority: 10
    banner:
      - '^CUSTOM/'
    confidence: 0.5
`)

	rs, source, err := Load(path)
	if err != nil {
		t.Fatalf("加载外部规则失败: %v", err)
	}
	if source != path {
		t.Errorf("来源 = %q, 期望 %q", source, path)
	}
	if len(rs) != 1 || rs[0].ID != "custom-only" {
		t.Errorf("外部规则未生效: %v", idsOf(rs))
	}
}

// TestLoadMissingFileFallsBackToBuiltin 验证文件不存在时回退内置规则而非报错。
func TestLoadMissingFileFallsBackToBuiltin(t *testing.T) {
	rs, source, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err != nil {
		t.Fatalf("期望回退内置规则, 却返回错误: %v", err)
	}
	if source != "built-in" {
		t.Errorf("来源 = %q, 期望 built-in", source)
	}
	if len(rs) == 0 {
		t.Error("回退后规则集为空")
	}
}

// TestLoadBrokenFileFallsBackToBuiltin 验证内容损坏时回退内置规则。
func TestLoadBrokenFileFallsBackToBuiltin(t *testing.T) {
	cases := map[string]string{
		"非法 YAML":     "rules: [:::\n  - bad",
		"空规则集":        "version: 1\nrules: []\n",
		"id 重复":       "version: 1\nrules:\n  - id: a\n    protocol: X\n    banner: ['^a']\n    confidence: 0.5\n  - id: a\n    protocol: Y\n    banner: ['^b']\n    confidence: 0.5\n",
		"正则可编译失败":     "version: 1\nrules:\n  - id: a\n    protocol: X\n    banner: ['^a(']\n    confidence: 0.5\n",
		"置信度越界":       "version: 1\nrules:\n  - id: a\n    protocol: X\n    banner: ['^a']\n    confidence: 2.0\n",
		"缺少 protocol": "version: 1\nrules:\n  - id: a\n    banner: ['^a']\n    confidence: 0.5\n",
	}

	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			path := writeTempRules(t, content)
			rs, source, err := Load(path)
			if err != nil {
				t.Fatalf("期望回退内置规则, 却返回错误: %v", err)
			}
			if source != "built-in" {
				t.Errorf("来源 = %q, 期望 built-in（应回退）", source)
			}
			if len(rs) == 0 {
				t.Error("回退后规则集为空")
			}
		})
	}
}

// writeTempRules 写一个临时规则文件并返回路径。
func writeTempRules(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("写临时规则文件失败: %v", err)
	}
	return path
}
