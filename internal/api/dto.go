package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// ErrorResponse 是所有错误响应的统一结构。
//
// 无论请求体非法、路径不存在还是内部 panic，客户端拿到的都是这个形状，
// 便于程序化处理，也便于排错时快速定位原因。
type ErrorResponse struct {
	Error  string `json:"error"`
	Detail string `json:"detail,omitempty"`
}

// HealthResponse 是 GET /health 的响应体。
//
// Rules 用于暴露当前生效的规则条数：既能确认服务带了多少条指纹规则，
// 也能在外部规则挂载生效时一眼看出规则是否被替换。
type HealthResponse struct {
	Status string `json:"status"`
	Rules  int    `json:"rules"`
}

// writeJSON 写出 JSON 响应。
//
// 序列化失败时（理论上不会发生）回退为 500，避免把半截响应发出去。
func writeJSON(w http.ResponseWriter, status int, payload any) {
	body, err := json.Marshal(payload)
	if err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"failed to encode response"}`))
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if _, err := w.Write(body); err != nil {
		slog.Debug("响应写出失败", "err", err)
	}
}

// writeError 写出统一格式的错误响应。
func writeError(w http.ResponseWriter, status int, msg, detail string) {
	writeJSON(w, status, ErrorResponse{Error: msg, Detail: detail})
}
