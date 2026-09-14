// Command client 是指纹识别系统的独立客户端。
//
// 用法：
//
//	client -file testdata/input.json [-server http://localhost:8080] [-json]
//
// 职责：读取本地 JSON 扫描数据 -> 调用服务端 /fingerprint -> 展示识别结果。
// 服务端地址与超时可由环境变量 SERVER_URL、REQUEST_TIMEOUT 提供默认值。
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"banner-fingerprint/internal/client"
	"banner-fingerprint/internal/config"
)

func main() {
	cfg := config.Load()

	var (
		filePath  string
		serverURL string
		asJSON    bool
	)
	flag.StringVar(&filePath, "file", "testdata/input.json", "本地输入的 JSON 文件路径")
	flag.StringVar(&serverURL, "server", cfg.ServerURL, "服务端地址（默认取环境变量 SERVER_URL）")
	flag.BoolVar(&asJSON, "json", false, "以 JSON 输出识别结果（默认以表格输出）")
	flag.Parse()

	if err := run(cfg, filePath, serverURL, asJSON); err != nil {
		fmt.Fprintf(os.Stderr, "错误: %v\n", err)
		os.Exit(1)
	}
}

func run(cfg config.Config, filePath, serverURL string, asJSON bool) error {
	recs, err := client.ReadRecords(filePath)
	if err != nil {
		return err
	}
	if len(recs) == 0 {
		fmt.Fprintln(os.Stderr, "输入文件为空，没有需要识别的记录")
		return nil
	}

	c := client.New(serverURL, cfg.RequestTimeout)

	// 支持 Ctrl+C 中断；超时由 client 内部的 http.Client 控制。
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	results, err := c.Fingerprint(ctx, recs)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "已识别 %d 条记录（服务端: %s）\n", len(results), serverURL)

	if asJSON {
		return client.RenderJSON(os.Stdout, results)
	}
	return client.Render(os.Stdout, results)
}
