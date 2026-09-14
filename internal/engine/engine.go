// Package engine 是指纹识别内核。
//
// 职责边界：engine 只负责「归一化 -> 逐条规则匹配 -> 择优 -> 兜底」这套流程，
// 不关心 HTTP、不关心配置来源、也不持有任何指纹特征。指纹特征全部来自
// rules 包加载的规则集，因此 engine 可以脱离网络独立测试。
package engine

import (
	"math"

	"banner-fingerprint/internal/model"
	"banner-fingerprint/internal/rules"
)

// Engine 持有已排序的规则集，对输入做无状态识别，可被并发调用。
type Engine struct {
	rules []rules.Rule
}

// New 用给定规则集构造引擎。
//
// 规则集应来自 rules.Load，已按优先级降序排列；引擎不再改动其顺序。
// 传入空规则集是合法的：此时所有输入都会被判为 unknown，服务不会崩。
func New(rs []rules.Rule) *Engine {
	return &Engine{rules: rs}
}

// RuleCount 返回已加载的规则条数，供健康检查等场景使用。
func (e *Engine) RuleCount() int { return len(e.rules) }

// Fingerprint 识别单条记录。
//
// 无论输入是什么（空 banner、纯二进制、超长内容），都返回一个合法的
// model.Result：认不出来时返回 protocol=unknown、confidence=0。
// 这是需求中「认不出来不允许报错崩掉」的落地点。
func (e *Engine) Fingerprint(rec model.Record) model.Result {
	banner := Normalize(rec.Banner)
	if banner == "" {
		return model.NewUnknown(rec)
	}

	idx := e.bestMatch(banner, rec.Port)
	if idx < 0 {
		return model.NewUnknown(rec)
	}

	r := &e.rules[idx]
	return model.Result{
		IP:         rec.IP,
		Port:       rec.Port,
		Protocol:   r.Protocol,
		Product:    r.Product,
		Version:    r.Version(banner),
		OSHint:     r.OSHint(banner),
		Confidence: round2(r.Confidence),
	}
}

// FingerprintBatch 批量识别，逐条独立处理。
//
// 单条识别失败不会影响整批（本实现中识别本身不会失败，只会得到 unknown），
// 返回结果与输入等长且顺序一一对应。
func (e *Engine) FingerprintBatch(recs []model.Record) []model.Result {
	out := make([]model.Result, len(recs))
	for i := range recs {
		out[i] = e.Fingerprint(recs[i])
	}
	return out
}

// bestMatch 返回最佳命中规则的索引，未命中返回 -1。
//
// 择优规则：
//  1. 规则集已按优先级降序排列，优先级高者优先；
//  2. 仅当同一优先级内出现多条命中时，用端口做区分 ——
//     端口属于规则声明的典型端口者优先。
//
// 端口始终是「弱提示」：不匹配不会被否决，只是在同优先级竞争时落选。
func (e *Engine) bestMatch(banner string, port int) int {
	best := -1
	for i := range e.rules {
		r := &e.rules[i]

		if best >= 0 && r.Priority < e.rules[best].Priority {
			// 已越过最优优先级区间，后面的规则不可能更优。
			break
		}

		if !r.Matches(banner) {
			continue
		}

		if best < 0 {
			best = i
			continue
		}

		// 同优先级：端口命中者胜出。
		cur := &e.rules[best]
		curHit := cur.PortDeclared() && cur.PortMatches(port)
		newHit := r.PortDeclared() && r.PortMatches(port)
		if newHit && !curHit {
			best = i
		}
	}
	return best
}

// round2 把置信度保留两位小数，避免浮点误差影响输出稳定性。
func round2(v float64) float64 {
	return math.Round(v*100) / 100
}
