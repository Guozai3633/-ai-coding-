package rules

import "testing"

// TestCompileRejectsInvalid 验证非法规则被拒绝，避免坏配置静默生效。
func TestCompileRejectsInvalid(t *testing.T) {
	cases := []struct {
		name string
		rule Rule
	}{
		{
			name: "缺少 id",
			rule: Rule{Protocol: "SSH", Banner: []string{`^SSH`}, Confidence: 0.5},
		},
		{
			name: "缺少 protocol",
			rule: Rule{ID: "x", Banner: []string{`^SSH`}, Confidence: 0.5},
		},
		{
			name: "缺少 banner",
			rule: Rule{ID: "x", Protocol: "SSH", Confidence: 0.5},
		},
		{
			name: "banner 正则非法",
			rule: Rule{ID: "x", Protocol: "SSH", Banner: []string{`^SSH(`}, Confidence: 0.5},
		},
		{
			name: "confidence 过大",
			rule: Rule{ID: "x", Protocol: "SSH", Banner: []string{`^SSH`}, Confidence: 1.5},
		},
		{
			name: "confidence 为负",
			rule: Rule{ID: "x", Protocol: "SSH", Banner: []string{`^SSH`}, Confidence: -0.1},
		},
		{
			name: "version_regex 非法",
			rule: Rule{ID: "x", Protocol: "SSH", Banner: []string{`^SSH`}, VersionRegex: `(`, Confidence: 0.5},
		},
		{
			name: "os_regex 非法",
			rule: Rule{ID: "x", Protocol: "SSH", Banner: []string{`^SSH`}, OSRegex: `(`, Confidence: 0.5},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.rule
			if err := r.compile(); err == nil {
				t.Errorf("期望报错，但编译通过了: %+v", tc.rule)
			}
		})
	}
}

// TestMatches 验证多正则中任意一条命中即算命中。
func TestMatches(t *testing.T) {
	r := Rule{ID: "redis", Protocol: "Redis", Banner: []string{`^\+PONG`, `^-ERR\b`}, Confidence: 0.7}
	if err := r.compile(); err != nil {
		t.Fatalf("编译失败: %v", err)
	}

	cases := map[string]bool{
		"+PONG":                            true,
		"-ERR unknown command":             true,
		"-NOAUTH Authentication required.": false,
		"":                                 false,
	}

	for banner, want := range cases {
		if got := r.Matches(banner); got != want {
			t.Errorf("Matches(%q) = %v, 期望 %v", banner, got, want)
		}
	}
}

// TestExtractVersionAndOS 验证捕获组提取。
func TestExtractVersionAndOS(t *testing.T) {
	r := Rule{
		ID:           "ssh-openssh",
		Protocol:     "SSH",
		Banner:       []string{`^SSH-\d+\.\d+-OpenSSH`},
		VersionRegex: `^SSH-[\d.]+-OpenSSH_(\S+)`,
		OSRegex:      `(Ubuntu|Debian)`,
		Confidence:   0.95,
	}
	if err := r.compile(); err != nil {
		t.Fatalf("编译失败: %v", err)
	}

	cases := []struct {
		banner      string
		wantVersion string
		wantOS      string
	}{
		{"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3", "8.9p1", "Ubuntu"},
		{"SSH-1.99-OpenSSH_4.3", "4.3", ""},
		{"SSH-2.0-OpenSSH_9.3 Debian-1", "9.3", "Debian"},
	}

	for _, tc := range cases {
		t.Run(tc.banner, func(t *testing.T) {
			if got := r.Version(tc.banner); got != tc.wantVersion {
				t.Errorf("Version(%q) = %q, 期望 %q", tc.banner, got, tc.wantVersion)
			}
			if got := r.OSHint(tc.banner); got != tc.wantOS {
				t.Errorf("OSHint(%q) = %q, 期望 %q", tc.banner, got, tc.wantOS)
			}
		})
	}
}

// TestVersionAndOSWithoutRegex 验证未配置正则时返回空串而非 panic。
func TestVersionAndOSWithoutRegex(t *testing.T) {
	r := Rule{ID: "x", Protocol: "Redis", Banner: []string{`^\+PONG`}, Confidence: 0.7}
	if err := r.compile(); err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	if got := r.Version("+PONG"); got != "" {
		t.Errorf("Version = %q, 期望空串", got)
	}
	if got := r.OSHint("+PONG"); got != "" {
		t.Errorf("OSHint = %q, 期望空串", got)
	}
}

// TestSortByPriority 验证排序：优先级降序，同优先级按 ID 升序，保证匹配顺序稳定。
func TestSortByPriority(t *testing.T) {
	rs := []Rule{
		{ID: "b", Priority: 10},
		{ID: "a", Priority: 100},
		{ID: "c", Priority: 10},
	}

	sortByPriority(rs)

	want := []string{"a", "b", "c"}
	for i, w := range want {
		if rs[i].ID != w {
			t.Errorf("第 %d 位为 %q, 期望 %q（结果: %v）", i, rs[i].ID, w, idsOf(rs))
		}
	}
}

// TestPortHint 验证端口弱提示判定。
func TestPortHint(t *testing.T) {
	r := Rule{ID: "x", Protocol: "SSH", Banner: []string{`^SSH`}, Ports: []int{22, 2222}, Confidence: 0.9}

	if !r.PortDeclared() {
		t.Error("PortDeclared 应为 true")
	}
	if !r.PortMatches(22) {
		t.Error("应命中端口 22")
	}
	if r.PortMatches(8080) {
		t.Error("不应命中端口 8080")
	}

	none := Rule{ID: "y", Protocol: "SSH", Banner: []string{`^SSH`}, Confidence: 0.9}
	if none.PortDeclared() {
		t.Error("未声明端口时 PortDeclared 应为 false")
	}
}

func idsOf(rs []Rule) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.ID)
	}
	return out
}
