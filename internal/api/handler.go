package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"banner-fingerprint/internal/model"
)

// handleFingerprint 处理 POST /fingerprint：批量识别。
//
// 请求体是 model.Record 数组，响应体是与输入等长同序的 model.Result 数组。
// 设计要点：单条无法识别不是错误 —— 该条返回 protocol=unknown，整体仍是 200。
// 只有「请求体本身不合法」才返回 400。
func (s *Server) handleFingerprint(w http.ResponseWriter, r *http.Request) {
	// 限制请求体大小，避免超大请求打爆内存。
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	defer func() { _ = r.Body.Close() }()

	dec := json.NewDecoder(r.Body)

	var recs []model.Record
	if err := dec.Decode(&recs); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large", maxErr.Error())
			return
		}
		writeError(w, http.StatusBadRequest, "invalid request body", err.Error())
		return
	}

	// 请求体后不允许再有第二个 JSON 值，避免静默丢弃数据。
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid request body", "请求体只能包含一个 JSON 数组")
		return
	}

	// 引擎对每条记录独立识别，任何输入都有返回，不会失败。
	results := s.engine.FingerprintBatch(recs)

	// 空输入返回 [] 而不是 null，保持响应形状稳定。
	if results == nil {
		results = []model.Result{}
	}

	writeJSON(w, http.StatusOK, results)
}

// handleHealth 处理 GET /health：健康检查。
//
// 该接口只反映进程自身的存活与规则装载情况，不做下游依赖探测，
// 因此适合作为容器 healthcheck 与编排的 service_healthy 判定依据。
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, HealthResponse{
		Status: "ok",
		Rules:  s.engine.RuleCount(),
	})
}

// handleNotFound 兜底未注册的路径，返回 JSON 而不是 Go 默认的纯文本。
func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotFound, "not found", r.URL.Path)
}
