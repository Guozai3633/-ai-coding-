// Package api 提供指纹识别服务的 HTTP 接口层。
//
// 只做三件事：路由、请求/响应编解码、错误与 panic 兜底。
// 识别逻辑全部委托给 engine，本包不含任何指纹知识。
package api

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"banner-fingerprint/internal/engine"
)

// 对外暴露的接口路径。集中定义，便于测试与文档保持一致。
const (
	PathFingerprint = "/fingerprint"
	PathHealth      = "/health"
)

// maxRequestBytes 限制单次请求体大小（16 MiB）。
const maxRequestBytes = 16 << 20

// Server 承载路由与依赖。
type Server struct {
	engine *engine.Engine
	logger *slog.Logger
	mux    *http.ServeMux
}

// New 构造 API 服务。
func New(eng *engine.Engine, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}

	s := &Server{
		engine: eng,
		logger: logger,
		mux:    http.NewServeMux(),
	}
	s.routes()
	return s
}

// routes 注册路由。
//
// 使用 Go 1.22+ ServeMux 的「方法 + 路径」模式。每个路径额外注册一条
// 「不带方法」的模式作为兜底：方法不符的请求会落到它上面，
// 从而返回带 Allow 头的 405，而不是被最后的 "/" 兜底吞成 404。
//
// 优先级由 ServeMux 保证："POST /fingerprint" 比 "/fingerprint" 更具体，
// 因此 POST 命中前者，其余方法命中后者。
func (s *Server) routes() {
	s.mux.HandleFunc("POST "+PathFingerprint, s.handleFingerprint)
	s.mux.HandleFunc(PathFingerprint, methodNotAllowed(http.MethodPost))

	s.mux.HandleFunc("GET "+PathHealth, s.handleHealth)
	s.mux.HandleFunc(PathHealth, methodNotAllowed(http.MethodGet))

	// 未注册的路径统一走 JSON 404。
	s.mux.HandleFunc("/", s.handleNotFound)
}

// methodNotAllowed 返回一个只负责声明 Allow 并回 405 的处理器。
func methodNotAllowed(allowed ...string) http.HandlerFunc {
	allow := strings.Join(allowed, ", ")
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Allow", allow)
		writeError(w, http.StatusMethodNotAllowed, "method not allowed",
			r.Method+" 不被支持，允许: "+allow)
	}
}

// Handler 返回带中间件的最终处理器：日志 + panic 兜底。
//
// panic 兜底保证「任何异常输入都不会让服务崩溃」——
// 即使某个处理器意外 panic，也只是这一个请求返回 500，进程继续服务后续请求。
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &responseRecorder{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()

		defer func() {
			if p := recover(); p != nil {
				s.logger.Error("请求处理 panic", "method", r.Method, "path", r.URL.Path, "panic", p)
				if !rec.wrote {
					writeError(rec, http.StatusInternalServerError, "internal server error", "")
				}
			}

			s.logger.Info("请求完成",
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.status,
				"duration", time.Since(start).String(),
			)
		}()

		s.mux.ServeHTTP(rec, r)
	})
}

// responseRecorder 记录响应状态码，供日志与 panic 兜底判断是否已写出响应。
type responseRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (r *responseRecorder) WriteHeader(code int) {
	if r.wrote {
		return
	}
	r.status = code
	r.wrote = true
	r.ResponseWriter.WriteHeader(code)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	if !r.wrote {
		r.status = http.StatusOK
		r.wrote = true
	}
	return r.ResponseWriter.Write(b)
}
