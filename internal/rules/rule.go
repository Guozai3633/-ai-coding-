// Package rules 负责指纹规则的建模、加载、校验与编译。
//
// 设计目标：识别规则完全由配置文件（rules.yaml）承载，程序只做
// 「加载 -> 校验 -> 编译」，不包含任何硬编码的指纹特征。新增一个
// 软件指纹只需改配置，无需改代码、无需重新构建镜像。
package rules

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Rule 是一条指纹规则。
//
// 一条规则描述「什么样的 banner 属于哪个协议/产品，以及如何从中提取版本与 OS 线索」。
// 带 yaml 标签的字段来自配置文件；小写字段是编译产物，不参与序列化。
type Rule struct {
	// ID 规则唯一标识，用于日志与排错。
	ID string `yaml:"id"`
	// Protocol 命中后返回的协议名，如 SSH / HTTP / MySQL。
	Protocol string `yaml:"protocol"`
	// Product 命中后返回的软件名，如 nginx / OpenSSH；留空表示只识别到协议。
	Product string `yaml:"product"`
	// Priority 匹配优先级，越大越先匹配，命中即返回。
	Priority int `yaml:"priority"`
	// Ports 是该服务的典型端口，作为「弱提示」使用：
	// 命中不额外加分，未命中会小幅下调置信度（服务可能跑在非标端口）。
	Ports []int `yaml:"ports"`
	// Banner 是特征正则列表，任意一条命中即视为该规则匹配。
	Banner []string `yaml:"banner"`
	// VersionRegex 含一个捕获组，用于从 banner 中提取版本号。
	VersionRegex string `yaml:"version_regex"`
	// OSRegex 含一个捕获组，用于从 banner 中提取操作系统线索。
	OSRegex string `yaml:"os_regex"`
	// Confidence 是该规则的基础置信度，取值 [0,1]。
	Confidence float64 `yaml:"confidence"`

	// ---- 编译产物 ----
	bannerRE  []*regexp.Regexp
	versionRE *regexp.Regexp
	osRE      *regexp.Regexp
}

// compile 校验规则字段并把正则编译成 regexp.Regexp。
// 任何一项不合法都会返回错误，由调用方决定是回退还是终止。
func (r *Rule) compile() error {
	if strings.TrimSpace(r.ID) == "" {
		return fmt.Errorf("规则缺少 id")
	}
	if strings.TrimSpace(r.Protocol) == "" {
		return fmt.Errorf("规则 %s 缺少 protocol", r.ID)
	}
	if len(r.Banner) == 0 {
		return fmt.Errorf("规则 %s 至少需要一条 banner 正则", r.ID)
	}
	if r.Confidence < 0 || r.Confidence > 1 {
		return fmt.Errorf("规则 %s 的 confidence=%v 超出 [0,1]", r.ID, r.Confidence)
	}

	r.bannerRE = r.bannerRE[:0]
	for i, expr := range r.Banner {
		re, err := regexp.Compile(expr)
		if err != nil {
			return fmt.Errorf("规则 %s 第 %d 条 banner 正则非法: %w", r.ID, i+1, err)
		}
		r.bannerRE = append(r.bannerRE, re)
	}

	if r.VersionRegex != "" {
		re, err := regexp.Compile(r.VersionRegex)
		if err != nil {
			return fmt.Errorf("规则 %s 的 version_regex 非法: %w", r.ID, err)
		}
		r.versionRE = re
	}

	if r.OSRegex != "" {
		re, err := regexp.Compile(r.OSRegex)
		if err != nil {
			return fmt.Errorf("规则 %s 的 os_regex 非法: %w", r.ID, err)
		}
		r.osRE = re
	}

	return nil
}

// Matches 判断 banner 是否命中本规则，任意一条特征正则命中即算命中。
func (r *Rule) Matches(banner string) bool {
	for _, re := range r.bannerRE {
		if re.MatchString(banner) {
			return true
		}
	}
	return false
}

// Version 从 banner 中提取版本号；未配置或未匹配到时返回空字符串。
//
// 取第一个捕获组：配置规则时保证用括号包住版本号部分。
func (r *Rule) Version(banner string) string {
	if r.versionRE == nil {
		return ""
	}
	m := r.versionRE.FindStringSubmatch(banner)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(m[1])
}

// OSHint 从 banner 中提取操作系统线索；未配置或未匹配到时返回空字符串。
func (r *Rule) OSHint(banner string) string {
	if r.osRE == nil {
		return ""
	}
	m := r.osRE.FindStringSubmatch(banner)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(m[1])
}

// PortDeclared 返回该规则是否声明了典型端口。
func (r *Rule) PortDeclared() bool { return len(r.Ports) > 0 }

// PortMatches 返回给定端口是否属于该规则的典型端口。
func (r *Rule) PortMatches(port int) bool {
	for _, p := range r.Ports {
		if p == port {
			return true
		}
	}
	return false
}

// sortByPriority 按优先级降序、ID 升序排序，保证匹配顺序稳定可复现。
func sortByPriority(rs []Rule) {
	sort.SliceStable(rs, func(i, j int) bool {
		if rs[i].Priority != rs[j].Priority {
			return rs[i].Priority > rs[j].Priority
		}
		return rs[i].ID < rs[j].ID
	})
}
