package checker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const requestTimeout = 8 * time.Second

type IPInspector interface {
	Lookup(ctx context.Context) (IPInfo, error)
}

type Checker struct {
	IPInspector IPInspector
	Timeout     time.Duration
}

type Result struct {
	IP IPInfo
}

type IPInfo struct {
	IP           string
	CountryCode  string
	CountryName  string
	Source       string
	RawResponse  string
	ASN          int
	ASNOrg       string
	ASNType      string
	CompanyName  string
	CompanyType  string
	IsMobile     bool
	IsSatellite  bool
	IsDatacenter bool
	IsCrawler    bool
	IsTor        bool
	IsProxy      bool
	IsVPN        bool
}

type httpIPInspector struct {
	Client     *http.Client
	RichSource string
	Fallbacks  []string
}

func NewDefaultChecker() *Checker {
	client := &http.Client{
		Timeout: requestTimeout,
	}

	return &Checker{
		IPInspector: &httpIPInspector{
			Client:     client,
			RichSource: "https://api.ipapi.is",
			Fallbacks: []string{
				"https://ipapi.co/json/",
				"https://ifconfig.co/json",
			},
		},
		Timeout: requestTimeout,
	}
}

func (c *Checker) Check() (Result, error) {
	if c == nil {
		return Result{}, errors.New("检查器未初始化")
	}

	timeout := c.Timeout
	if timeout <= 0 {
		timeout = requestTimeout
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ipInfo, err := c.IPInspector.Lookup(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("查询出口 IP 失败: %w", err)
	}

	return Result{
		IP: ipInfo,
	}, nil
}

func (h *httpIPInspector) Lookup(ctx context.Context) (IPInfo, error) {
	if h == nil || h.Client == nil {
		return IPInfo{}, errors.New("IP 查询器未初始化")
	}

	info, err := h.lookupRich(ctx)
	if err == nil {
		return info, nil
	}

	var errs []string
	errs = append(errs, fmt.Sprintf("%s: %v", h.RichSource, err))

	for _, source := range h.Fallbacks {
		info, fallbackErr := h.lookupFallback(ctx, source)
		if fallbackErr == nil {
			return info, nil
		}
		errs = append(errs, fmt.Sprintf("%s: %v", source, fallbackErr))
	}

	return IPInfo{}, fmt.Errorf("所有 IP 信息源均失败: %s", strings.Join(errs, "; "))
}

func (h *httpIPInspector) lookupRich(ctx context.Context) (IPInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.RichSource, nil)
	if err != nil {
		return IPInfo{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "cc-vpn-check/1.0")

	resp, err := h.Client.Do(req)
	if err != nil {
		return IPInfo{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return IPInfo{}, fmt.Errorf("HTTP 状态码异常: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return IPInfo{}, err
	}

	return parseIPAPIISResponse(h.RichSource, body)
}

func (h *httpIPInspector) lookupFallback(ctx context.Context, source string) (IPInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return IPInfo{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "cc-vpn-check/1.0")

	resp, err := h.Client.Do(req)
	if err != nil {
		return IPInfo{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return IPInfo{}, fmt.Errorf("HTTP 状态码异常: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return IPInfo{}, err
	}

	return parseFallbackResponse(source, body)
}

func parseIPAPIISResponse(source string, body []byte) (IPInfo, error) {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return IPInfo{}, err
	}

	if apiError := getString(payload, "error"); apiError != "" {
		return IPInfo{}, fmt.Errorf("接口返回错误: %s", apiError)
	}

	location := getMap(payload, "location")
	asn := getMap(payload, "asn")
	company := getMap(payload, "company")

	info := IPInfo{
		IP:           strings.TrimSpace(getString(payload, "ip")),
		CountryCode:  strings.ToUpper(strings.TrimSpace(getString(location, "country_code"))),
		CountryName:  strings.TrimSpace(getString(location, "country")),
		Source:       source,
		RawResponse:  string(body),
		ASN:          getInt(asn, "asn"),
		ASNOrg:       strings.TrimSpace(getString(asn, "org")),
		ASNType:      strings.ToLower(strings.TrimSpace(getString(asn, "type"))),
		CompanyName:  strings.TrimSpace(getString(company, "name")),
		CompanyType:  strings.ToLower(strings.TrimSpace(getString(company, "type"))),
		IsMobile:     getBool(payload, "is_mobile"),
		IsSatellite:  getBool(payload, "is_satellite"),
		IsDatacenter: getBool(payload, "is_datacenter"),
		IsCrawler:    getCrawlerFlag(payload, "is_crawler"),
		IsTor:        getBool(payload, "is_tor"),
		IsProxy:      getBool(payload, "is_proxy"),
		IsVPN:        getBool(payload, "is_vpn"),
	}

	if info.IP == "" || info.CountryCode == "" {
		return IPInfo{}, errors.New("响应缺少必要字段")
	}

	return info, nil
}

func ValidateUSResidentialLikeIP(info IPInfo) error {
	if info.CountryCode != "US" {
		return fmt.Errorf(
			"当前出口 IP 不符合要求: ip=%s country=%s(%s)，仅允许美国出口 IP 启动目标程序",
			info.IP,
			info.CountryCode,
			info.CountryName,
		)
	}

	if info.ASNType != "isp" {
		return fmt.Errorf(
			"当前出口 IP 的 ASN 类型不是 isp，已阻止启动: asn=%d org=%s asn_type=%s",
			info.ASN,
			info.ASNOrg,
			emptyAsUnknown(info.ASNType),
		)
	}

	if info.CompanyType != "" && info.CompanyType != "isp" {
		return fmt.Errorf(
			"当前出口 IP 的公司类型不是 isp，已阻止启动: company=%s company_type=%s",
			info.CompanyName,
			info.CompanyType,
		)
	}

	if info.IsDatacenter {
		return fmt.Errorf(
			"当前出口 IP 被识别为数据中心或托管网络，已阻止启动: asn=%d org=%s",
			info.ASN,
			info.ASNOrg,
		)
	}

	if info.IsVPN {
		return errors.New("当前出口 IP 被识别为 VPN 出口节点，已阻止启动")
	}

	if info.IsProxy {
		return errors.New("当前出口 IP 被识别为代理出口节点，已阻止启动")
	}

	if info.IsTor {
		return errors.New("当前出口 IP 被识别为 Tor 出口节点，已阻止启动")
	}

	if info.IsMobile {
		return errors.New("当前出口 IP 被识别为移动网络，不符合家庭宽带判定要求，已阻止启动")
	}

	if info.IsSatellite {
		return errors.New("当前出口 IP 被识别为卫星网络，不符合家庭宽带判定要求，已阻止启动")
	}

	if info.IsCrawler {
		return errors.New("当前出口 IP 被识别为爬虫或机器人网络，已阻止启动")
	}

	return nil
}

func parseFallbackResponse(source string, body []byte) (IPInfo, error) {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return IPInfo{}, err
	}

	info := IPInfo{
		IP:          strings.TrimSpace(firstNonEmpty(getString(payload, "ip"), getString(payload, "ip_addr"))),
		CountryCode: strings.ToUpper(strings.TrimSpace(firstNonEmpty(getString(payload, "country_code"), getString(payload, "country_iso")))),
		CountryName: strings.TrimSpace(firstNonEmpty(getString(payload, "country"), getString(payload, "country_name"))),
		Source:      source,
		RawResponse: string(body),
	}

	if info.IP == "" || info.CountryCode == "" {
		return IPInfo{}, errors.New("响应缺少必要字段")
	}

	return info, nil
}

func getMap(data map[string]any, key string) map[string]any {
	value, ok := data[key]
	if !ok {
		return map[string]any{}
	}

	result, ok := value.(map[string]any)
	if !ok {
		return map[string]any{}
	}

	return result
}

func getString(data map[string]any, key string) string {
	value, ok := data[key]
	if !ok || value == nil {
		return ""
	}

	switch v := value.(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		if v {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}

func getInt(data map[string]any, key string) int {
	value, ok := data[key]
	if !ok || value == nil {
		return 0
	}

	switch v := value.(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		n, err := strconv.Atoi(v)
		if err != nil {
			return 0
		}
		return n
	default:
		return 0
	}
}

func getBool(data map[string]any, key string) bool {
	value, ok := data[key]
	if !ok || value == nil {
		return false
	}

	switch v := value.(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "true")
	default:
		return false
	}
}

func getCrawlerFlag(data map[string]any, key string) bool {
	value, ok := data[key]
	if !ok || value == nil {
		return false
	}

	switch v := value.(type) {
	case bool:
		return v
	case string:
		return strings.TrimSpace(v) != "" && !strings.EqualFold(v, "false")
	default:
		return false
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}

	return ""
}

func emptyAsUnknown(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unknown"
	}

	return value
}

func RunCommand(name string, args []string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return fmt.Errorf("目标程序退出，状态码=%s", strconv.Itoa(exitErr.ExitCode()))
		}
		return fmt.Errorf("启动目标程序失败: %w", err)
	}

	return nil
}
