package engine

import "strings"

const (
	// maxRawBannerLen 限制参与归一化的原始 banner 长度。
	// 转义序列最长 4 字符（\xNN），因此原始长度放宽 4 倍。
	maxRawBannerLen = maxBannerLen * 4

	// maxBannerLen 限制归一化后的 banner 长度，防止超长输入拖慢正则匹配。
	maxBannerLen = 8192
)

// Normalize 把原始 banner 转换为便于正则匹配的形式。
//
// 扫描器（以及题目提供的样例数据）通常以「可打印转义序列」的形式承载 banner，
// 例如把真实的换行写成字面量 `\r\n`、把二进制字节写成 `\x00`。而归一化后
// 这些转义会被还原成真实字节，于是规则里就能直接写字节级正则。
//
// 同时兼容另一种输入形态：banner 中已经是真实控制字符（例如 JSON 里的
// \u0000 被解析成真实 NUL）。这种情况下字符串里没有反斜杠，函数原样返回。
//
// 处理规则：
//
//	\xNN / \XNN  -> 对应的字节（NN 为两位十六进制）
//	\n \r \t \0  -> 换行 / 回车 / 制表 / NUL
//	\\           -> 单个反斜杠
//	其它          -> 反斜杠原样保留（避免误伤正常内容）
//
// 注意：反斜杠后跟 n/r/t/0 会被解释为转义，这是与扫描器输出约定的格式；
// 对明文 banner（真实换行而非 `\n` 两字符）无影响。
func Normalize(banner string) string {
	if banner == "" {
		return ""
	}
	if len(banner) > maxRawBannerLen {
		banner = banner[:maxRawBannerLen]
	}

	// 快路径：不含反斜杠时无需任何转换。
	if !strings.ContainsRune(banner, '\\') {
		return truncate(banner, maxBannerLen)
	}

	var b strings.Builder
	b.Grow(len(banner))

	for i := 0; i < len(banner); {
		c := banner[i]
		if c != '\\' || i+1 >= len(banner) {
			b.WriteByte(c)
			i++
			continue
		}

		switch banner[i+1] {
		case 'x', 'X':
			// 需要 i+2、i+3 两个十六进制位
			if i+3 < len(banner) {
				hi, okHi := hexVal(banner[i+2])
				lo, okLo := hexVal(banner[i+3])
				if okHi && okLo {
					b.WriteByte(hi<<4 | lo)
					i += 4
					continue
				}
			}
			b.WriteByte(c)
			i++
		case 'n':
			b.WriteByte('\n')
			i += 2
		case 'r':
			b.WriteByte('\r')
			i += 2
		case 't':
			b.WriteByte('\t')
			i += 2
		case '0':
			b.WriteByte(0)
			i += 2
		case '\\':
			b.WriteByte('\\')
			i += 2
		default:
			b.WriteByte(c)
			i++
		}
	}

	return truncate(b.String(), maxBannerLen)
}

// hexVal 把十六进制字符转成数值。
func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

// truncate 按字节上限截断字符串。
func truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit]
}
