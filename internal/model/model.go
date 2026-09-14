// Package model 定义指纹识别系统对外的数据契约。
//
// 这些结构同时是 HTTP 接口的请求/响应体，字段名（JSON 标签）即对外契约，
// 修改需同步更新 README 与 testdata。
package model

// ProtocolUnknown 表示无法识别出的协议。
//
// 需求明确：认不出来时统一返回该值，而不是返回错误或让服务崩溃。
const ProtocolUnknown = "unknown"

// Record 是一条网络扫描原始数据：IP、端口、以及从该端口读到的 banner 原文。
//
// Banner 中可能包含 \r\n、\x00 等字面量转义，也可能包含无法以 UTF-8 解码的
// 二进制字节（例如 MySQL 握手包），归一化由 engine 层负责。
type Record struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Banner string `json:"banner"`
}

// Result 是一条识别结果。
//
// 字段语义：
//   - Protocol 认不出时为 ProtocolUnknown；
//   - Product / Version / OSHint 无对应信息时为空字符串（而非省略字段）；
//   - Confidence 取值 [0,1]，0 表示完全无法识别。
type Result struct {
	IP         string  `json:"ip"`
	Port       int     `json:"port"`
	Protocol   string  `json:"protocol"`
	Product    string  `json:"product"`
	Version    string  `json:"version"`
	OSHint     string  `json:"os_hint"`
	Confidence float64 `json:"confidence"`
}

// NewUnknown 为一条无法识别的记录构造兜底结果。
//
// IP/Port 原样回填，保证输出与输入一一对应；其余识别字段留空，
// Protocol 显式置为 ProtocolUnknown。这是「认不出不算错」的落地点。
func NewUnknown(rec Record) Result {
	return Result{
		IP:         rec.IP,
		Port:       rec.Port,
		Protocol:   ProtocolUnknown,
		Confidence: 0,
	}
}
