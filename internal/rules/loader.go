package rules

import (
	_ "embed"
	"fmt"
	"log/slog"
	"os"

	"gopkg.in/yaml.v3"
)

// builtinRules 是编译进二进制的默认规则集，保证开箱即用。
//
// 运行时若设置了 FINGERPRINT_RULES 指向外部文件，则外部文件优先，
// 从而实现「不改镜像换规则」。详见 Load。
//
//go:embed rules.yaml
var builtinRules []byte

// document 对应 rules.yaml 的顶层结构。
type document struct {
	Version int    `yaml:"version"`
	Rules   []Rule `yaml:"rules"`
}

// Load 加载规则集，返回规则、来源描述与错误。
//
// 优先级：外部文件（path）> 内置规则。
// 外部文件不可读或内容非法时，记录 WARN 并回退内置规则 —— 规则问题
// 不应导致服务无法启动。只有内置规则本身损坏（构建期问题）才返回错误。
func Load(path string) ([]Rule, string, error) {
	if path != "" {
		rs, err := loadFile(path)
		if err == nil {
			return rs, path, nil
		}
		slog.Warn("外部规则不可用，回退到内置规则", "path", path, "err", err)
	}

	rs, err := parse(builtinRules)
	if err != nil {
		return nil, "", fmt.Errorf("内置规则损坏: %w", err)
	}
	return rs, "built-in", nil
}

// loadFile 从磁盘读取并解析规则文件。
func loadFile(path string) ([]Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取规则文件失败: %w", err)
	}
	rs, err := parse(data)
	if err != nil {
		return nil, fmt.Errorf("解析规则文件失败: %w", err)
	}
	return rs, nil
}

// parse 反序列化、校验、编译并排序规则集。
func parse(data []byte) ([]Rule, error) {
	var doc document
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("YAML 反序列化失败: %w", err)
	}
	if len(doc.Rules) == 0 {
		return nil, fmt.Errorf("规则集为空")
	}

	seen := make(map[string]struct{}, len(doc.Rules))
	for i := range doc.Rules {
		r := &doc.Rules[i]
		if err := r.compile(); err != nil {
			return nil, err
		}
		if _, dup := seen[r.ID]; dup {
			return nil, fmt.Errorf("规则 id 重复: %s", r.ID)
		}
		seen[r.ID] = struct{}{}
	}

	sortByPriority(doc.Rules)
	return doc.Rules, nil
}
