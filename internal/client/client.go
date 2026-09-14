// Package client 实现指纹识别系统的客户端逻辑。
//
// 与 cmd/client 分离是为了让「读文件 -> 调服务 -> 渲染结果」这条链路
// 可以脱离命令行独立测试：本包不读 os.Args、不调用 os.Exit。
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"banner-fingerprint/internal/model"
)

// maxResponseBytes 限制读取的响应体大小，防止异常服务端拖垮客户端。
const maxResponseBytes = 64 << 20

// Client 是指纹识别服务的客户端。
type Client struct {
	baseURL string
	http    *http.Client
}

// New 构造客户端。timeout <= 0 时使用 10 秒默认值。
func New(baseURL string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		http:    &http.Client{Timeout: timeout},
	}
}

// ReadRecords 从本地 JSON 文件读取原始扫描数据。
func ReadRecords(path string) ([]model.Record, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取输入文件失败: %w", err)
	}

	var recs []model.Record
	if err := json.Unmarshal(data, &recs); err != nil {
		return nil, fmt.Errorf("解析输入文件失败（应为 JSON 数组）: %w", err)
	}
	return recs, nil
}

// Fingerprint 调用服务端的批量识别接口。
//
// 服务端返回非 2xx 时，把其结构化错误还原成 error 返回，便于定位问题。
func (c *Client) Fingerprint(ctx context.Context, recs []model.Record) ([]model.Result, error) {
	payload, err := json.Marshal(recs)
	if err != nil {
		return nil, fmt.Errorf("序列化请求失败: %w", err)
	}

	url := c.baseURL + "/fingerprint"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("构造请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求服务端失败: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("服务端返回 %d: %s", resp.StatusCode, describeError(body))
	}

	var results []model.Result
	if err := json.Unmarshal(body, &results); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}
	return results, nil
}

// describeError 尽量从服务端错误响应里取出可读信息。
func describeError(body []byte) string {
	var errResp struct {
		Error  string `json:"error"`
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(body, &errResp); err == nil && errResp.Error != "" {
		if errResp.Detail != "" {
			return errResp.Error + ": " + errResp.Detail
		}
		return errResp.Error
	}
	return strings.TrimSpace(string(body))
}

// Render 把识别结果渲染成对齐的文本表格。
//
// 空字符串字段（无版本 / 无 OS 线索）显示为 "-"，让「确实没有该信息」
// 与「漏输出」在视觉上可区分。
func Render(w io.Writer, results []model.Result) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)

	if _, err := fmt.Fprintln(tw, "IP\tPORT\tPROTOCOL\tPRODUCT\tVERSION\tOS_HINT\tCONFIDENCE"); err != nil {
		return err
	}

	for _, r := range results {
		if _, err := fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\t%s\t%.2f\n",
			r.IP,
			r.Port,
			orDash(r.Protocol),
			orDash(r.Product),
			orDash(r.Version),
			orDash(r.OSHint),
			r.Confidence,
		); err != nil {
			return err
		}
	}

	return tw.Flush()
}

// RenderJSON 把识别结果以 JSON 输出，便于与期望数据对拍或管道处理。
func RenderJSON(w io.Writer, results []model.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(results)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
