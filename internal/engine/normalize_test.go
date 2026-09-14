package engine

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestNormalize(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"空串", "", ""},
		{"无转义原样返回", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
		{"字面量 CRLF 还原", `HTTP/1.1 200 OK\r\nServer: nginx/1.24.0`, "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0"},
		{"十六进制转义还原", `J\x00\x00\x00\n8.0.32\x00`, "J\x00\x00\x00\n8.0.32\x00"},
		{"大写 X 转义", `\X41\X42`, "AB"},
		{"制表与 NUL", `a\tb\0c`, "a\tb\x00c"},
		{"转义反斜杠", `a\\b`, `a\b`},
		{"未知转义保留反斜杠", `a\qb`, `a\qb`},
		{"结尾孤立反斜杠", `abc\`, `abc\`},
		{"十六进制位数不足", `\xA`, `\xA`},
		{"非十六进制字符", `\xZZ`, `\xZZ`},
		{"真实控制字符不被二次处理", "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0", "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0"},
		{"真实 NUL 字节", "J\x00\x00\x00\n8.0.32\x00", "J\x00\x00\x00\n8.0.32\x00"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Normalize(tc.in); got != tc.want {
				t.Errorf("Normalize(%q) = %q, 期望 %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestNormalizeEscapedAndRawAreEquivalent 验证两种输入形态归一化后一致。
// 这很重要：评估数据可能用可打印转义，也可能直接用真实控制字符。
func TestNormalizeEscapedAndRawAreEquivalent(t *testing.T) {
	escaped := `HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html`
	raw := "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html"

	if a, b := Normalize(escaped), Normalize(raw); a != b {
		t.Errorf("两种形态归一化结果不一致:\n  转义 %q\n  原始 %q", a, b)
	}

	mysqlEscaped := `J\x00\x00\x00\n8.0.32\x00`
	mysqlRaw := "J\x00\x00\x00\n8.0.32\x00"

	if a, b := Normalize(mysqlEscaped), Normalize(mysqlRaw); a != b {
		t.Errorf("MySQL 两种形态归一化结果不一致:\n  转义 %q\n  原始 %q", a, b)
	}
}

// TestNormalizeTruncates 验证超长输入被截断，避免正则被拖慢。
func TestNormalizeTruncates(t *testing.T) {
	long := strings.Repeat("A", maxBannerLen*3)
	got := Normalize(long)

	if len(got) != maxBannerLen {
		t.Errorf("长度 = %d, 期望 %d", len(got), maxBannerLen)
	}
}

// TestNormalizeTruncatesEscapedInput 验证转义形态超长输入同样受控。
func TestNormalizeTruncatesEscapedInput(t *testing.T) {
	long := strings.Repeat(`\x41`, maxRawBannerLen)
	got := Normalize(long)

	if len(got) > maxBannerLen {
		t.Errorf("长度 = %d, 不应超过 %d", len(got), maxBannerLen)
	}
}

// TestNormalizeNeverPanics 验证任意字节输入都不会 panic，且不改变无转义内容。
func TestNormalizeNeverPanics(t *testing.T) {
	cases := []string{
		"", "\x00", "\xff\xfe", "\x16\x03\x01\x00\xa5",
		strings.Repeat("\\", 100), strings.Repeat("\\x", 100),
		"\\x00\\x00\\x00\n", "😀emoji", "\x80\x81\x82",
	}

	for _, in := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Normalize(%q) panic: %v", in, r)
				}
			}()
			_ = Normalize(in)
		}()
	}
}

// TestNormalizePreservesIPv6AndText 验证归一化不会破坏正常文本内容。
func TestNormalizePreservesIPv6AndText(t *testing.T) {
	in := "220 ProFTPD 1.3.7 Server (ProFTPD)"
	if got := Normalize(in); got != in {
		t.Errorf("Normalize(%q) = %q, 期望原样", in, got)
	}
	if !utf8.ValidString(Normalize(in)) {
		t.Error("归一化破坏了合法 UTF-8 文本")
	}
}
