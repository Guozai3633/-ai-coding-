package config

import (
	"log/slog"
	"testing"
	"time"
)

// TestLoadDefaults 验证环境变量全部缺失时回退到默认值。
// t.Setenv 由 testing 自动清理，无需手动恢复。
func TestLoadDefaults(t *testing.T) {
	t.Setenv(EnvPort, "")
	t.Setenv(EnvRulesPath, "")
	t.Setenv(EnvLogLevel, "")
	t.Setenv(EnvServerURL, "")
	t.Setenv(EnvRequestTimeout, "")

	cfg := Load()

	if cfg.Port != DefaultPort {
		t.Errorf("Port = %d, 期望 %d", cfg.Port, DefaultPort)
	}
	if cfg.RulesPath != "" {
		t.Errorf("RulesPath = %q, 期望空（使用内置规则）", cfg.RulesPath)
	}
	if cfg.LogLevel != slog.LevelInfo {
		t.Errorf("LogLevel = %v, 期望 %v", cfg.LogLevel, slog.LevelInfo)
	}
	if cfg.ServerURL != DefaultServerURL {
		t.Errorf("ServerURL = %q, 期望 %q", cfg.ServerURL, DefaultServerURL)
	}
	if cfg.RequestTimeout != DefaultRequestTimeout {
		t.Errorf("RequestTimeout = %v, 期望 %v", cfg.RequestTimeout, DefaultRequestTimeout)
	}
}

// TestLoadFromEnv 验证设置后能正确读取。
func TestLoadFromEnv(t *testing.T) {
	t.Setenv(EnvPort, "9090")
	t.Setenv(EnvRulesPath, "/etc/fingerprint/rules.yaml")
	t.Setenv(EnvLogLevel, "debug")
	t.Setenv(EnvServerURL, "http://server:8080")
	t.Setenv(EnvRequestTimeout, "3s")

	cfg := Load()

	if cfg.Port != 9090 {
		t.Errorf("Port = %d, 期望 9090", cfg.Port)
	}
	if cfg.RulesPath != "/etc/fingerprint/rules.yaml" {
		t.Errorf("RulesPath = %q", cfg.RulesPath)
	}
	if cfg.LogLevel != slog.LevelDebug {
		t.Errorf("LogLevel = %v, 期望 debug", cfg.LogLevel)
	}
	if cfg.ServerURL != "http://server:8080" {
		t.Errorf("ServerURL = %q", cfg.ServerURL)
	}
	if cfg.RequestTimeout != 3*time.Second {
		t.Errorf("RequestTimeout = %v, 期望 3s", cfg.RequestTimeout)
	}
}

// TestLoadInvalidValuesFallback 验证非法值回退默认，保证服务不会因坏配置起不来。
func TestLoadInvalidValuesFallback(t *testing.T) {
	cases := []struct {
		name  string
		key   string
		value string
		check func(t *testing.T, cfg Config)
	}{
		{
			name: "端口非数字", key: EnvPort, value: "abc",
			check: func(t *testing.T, cfg Config) {
				if cfg.Port != DefaultPort {
					t.Errorf("Port = %d, 期望默认 %d", cfg.Port, DefaultPort)
				}
			},
		},
		{
			name: "端口超范围", key: EnvPort, value: "70000",
			check: func(t *testing.T, cfg Config) {
				if cfg.Port != DefaultPort {
					t.Errorf("Port = %d, 期望默认 %d", cfg.Port, DefaultPort)
				}
			},
		},
		{
			name: "端口为零", key: EnvPort, value: "0",
			check: func(t *testing.T, cfg Config) {
				if cfg.Port != DefaultPort {
					t.Errorf("Port = %d, 期望默认 %d", cfg.Port, DefaultPort)
				}
			},
		},
		{
			name: "超时非法", key: EnvRequestTimeout, value: "not-a-duration",
			check: func(t *testing.T, cfg Config) {
				if cfg.RequestTimeout != DefaultRequestTimeout {
					t.Errorf("RequestTimeout = %v, 期望默认 %v", cfg.RequestTimeout, DefaultRequestTimeout)
				}
			},
		},
		{
			name: "超时为负", key: EnvRequestTimeout, value: "-5s",
			check: func(t *testing.T, cfg Config) {
				if cfg.RequestTimeout != DefaultRequestTimeout {
					t.Errorf("RequestTimeout = %v, 期望默认 %v", cfg.RequestTimeout, DefaultRequestTimeout)
				}
			},
		},
		{
			name: "日志级别非法", key: EnvLogLevel, value: "verbose",
			check: func(t *testing.T, cfg Config) {
				if cfg.LogLevel != slog.LevelInfo {
					t.Errorf("LogLevel = %v, 期望 info", cfg.LogLevel)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(tc.key, tc.value)
			tc.check(t, Load())
		})
	}
}

// TestEnvLogLevelAliases 验证别名解析（warning → warn）。
func TestEnvLogLevelAliases(t *testing.T) {
	cases := map[string]slog.Level{
		"debug":   slog.LevelDebug,
		"info":    slog.LevelInfo,
		"warn":    slog.LevelWarn,
		"warning": slog.LevelWarn,
		"error":   slog.LevelError,
		"ERROR":   slog.LevelError,
	}

	for in, want := range cases {
		t.Run(in, func(t *testing.T) {
			if got := envLogLevel(EnvLogLevel, in); got != want {
				t.Errorf("envLogLevel(%q) = %v, 期望 %v", in, got, want)
			}
		})
	}
}
