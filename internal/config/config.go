// Package config 集中管理运行参数。
//
// 所有参数均来自环境变量，遵循 12-Factor 原则：镜像不写死配置，
// 同一镜像可在不同环境（本地 / compose / 生产）以不同参数运行。
// 非法或缺失的值一律回退到默认值，保证服务永远能启动。
package config

import (
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

// 环境变量名。集中定义，避免在代码各处散落字符串字面量。
const (
	EnvPort           = "FINGERPRINT_PORT"
	EnvRulesPath      = "FINGERPRINT_RULES"
	EnvLogLevel       = "LOG_LEVEL"
	EnvServerURL      = "SERVER_URL"
	EnvRequestTimeout = "REQUEST_TIMEOUT"
)

// 默认值。
const (
	DefaultPort           = 8080
	DefaultLogLevel       = "info"
	DefaultServerURL      = "http://localhost:8080"
	DefaultRequestTimeout = 10 * time.Second
)

// Config 是服务端与客户端的合并配置。
//
// server 只使用 Port / RulesPath / LogLevel；
// client 只使用 ServerURL / RequestTimeout / LogLevel。
// 合并为一个结构体是为了让两个入口共用同一套加载与默认值逻辑。
type Config struct {
	// Port 是 server 的监听端口。
	Port int
	// RulesPath 是外部规则文件路径；为空时使用编译进二进制的内置规则。
	RulesPath string
	// LogLevel 是 slog 日志级别：debug / info / warn / error。
	LogLevel slog.Level
	// ServerURL 是 client 要访问的 server 地址。
	ServerURL string
	// RequestTimeout 是 client 单次 HTTP 请求的超时时间。
	RequestTimeout time.Duration
}

// Load 从环境变量加载配置，缺失或非法时使用默认值。
func Load() Config {
	return Config{
		Port:           envInt(EnvPort, DefaultPort),
		RulesPath:      strings.TrimSpace(os.Getenv(EnvRulesPath)),
		LogLevel:       envLogLevel(EnvLogLevel, DefaultLogLevel),
		ServerURL:      envString(EnvServerURL, DefaultServerURL),
		RequestTimeout: envDuration(EnvRequestTimeout, DefaultRequestTimeout),
	}
}

func envString(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 || v > 65535 {
		return def
	}
	return v
}

func envDuration(key string, def time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	v, err := time.ParseDuration(raw)
	if err != nil || v <= 0 {
		return def
	}
	return v
}

// envLogLevel 解析日志级别，非法值回退到 def。
func envLogLevel(key, def string) slog.Level {
	switch strings.ToLower(envString(key, def)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
