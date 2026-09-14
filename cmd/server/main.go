// Command server 是指纹识别服务端。
//
// 启动流程：加载配置 -> 加载规则 -> 装配引擎与 HTTP 接口 -> 监听并等待退出信号。
//
// 除正常启动外还支持一个子命令：
//
//	server healthcheck
//
// 它会向自身 /health 发一次请求，成功退出码 0，失败退出码 1。
// 之所以把健康检查做进二进制，是因为运行镜像是 distroless（无 shell、无 curl/wget），
// 无法在容器里执行外部探测命令，而 compose 的 healthcheck 需要一条可执行的命令。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"banner-fingerprint/internal/api"
	"banner-fingerprint/internal/config"
	"banner-fingerprint/internal/engine"
	"banner-fingerprint/internal/rules"
)

// healthcheckSubcommand 是健康探测子命令名。
const healthcheckSubcommand = "healthcheck"

func main() {
	if len(os.Args) > 1 && os.Args[1] == healthcheckSubcommand {
		os.Exit(runHealthcheck())
	}

	if err := run(); err != nil {
		slog.Error("服务异常退出", "err", err)
		os.Exit(1)
	}
}

// run 启动服务并阻塞直到收到退出信号。
func run() error {
	cfg := config.Load()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	slog.SetDefault(logger)

	// 规则加载失败只在「内置规则损坏」时发生，属于构建问题，直接退出。
	rs, source, err := rules.Load(cfg.RulesPath)
	if err != nil {
		return fmt.Errorf("加载规则失败: %w", err)
	}
	logger.Info("规则加载完成", "source", source, "count", len(rs))
	if cfg.RulesPath != "" && source == "built-in" {
		logger.Warn("已配置外部规则但未能生效，当前使用内置规则", "path", cfg.RulesPath)
	}

	eng := engine.New(rs)
	handler := api.New(eng, logger).Handler()

	srv := &http.Server{
		Addr:              net.JoinHostPort("", strconv.Itoa(cfg.Port)),
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// 收到 SIGINT/SIGTERM 后结束阻塞，进入优雅关闭。
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		logger.Info("服务已启动", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("监听失败: %w", err)
	case <-ctx.Done():
		logger.Info("收到退出信号，开始优雅关闭")
	}

	// 给在途请求留出处理时间，超时则强制关闭。
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("优雅关闭失败: %w", err)
	}

	logger.Info("服务已停止")
	return nil
}

// runHealthcheck 向本机 /health 发一次探测，返回进程退出码。
//
// 供容器 healthcheck 使用：容器内没有 shell 和探测工具，只能调用自身二进制。
func runHealthcheck() int {
	cfg := config.Load()

	url := fmt.Sprintf("http://127.0.0.1:%d%s", cfg.Port, api.PathHealth)

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck 请求失败: %v\n", err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "healthcheck 状态码异常: %d\n", resp.StatusCode)
		return 1
	}

	var payload api.HealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck 响应解析失败: %v\n", err)
		return 1
	}
	if payload.Status != "ok" {
		fmt.Fprintf(os.Stderr, "healthcheck 状态异常: %q\n", payload.Status)
		return 1
	}

	return 0
}
