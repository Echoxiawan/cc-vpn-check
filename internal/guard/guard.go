package guard

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	defaultMaskedTimezone = "UTC"
	RealUpstreamEnvName   = "CLAUDE_GUARD_REAL_ANTHROPIC_BASE_URL"
)

var truthyValues = map[string]struct{}{
	"1":    {},
	"true": {},
	"yes":  {},
	"on":   {},
}

type LocalProxy struct {
	server *http.Server
	addr   string
}

type PreparedClaude struct {
	Path  string
	Args  []string
	Env   []string
	proxy *LocalProxy
}

func PrepareClaudeCommand(command string, args []string) (*PreparedClaude, error) {
	claudePath, err := resolveExplicitCommand(command)
	if err != nil {
		return nil, err
	}
	return prepareClaude(claudePath, args)
}

func prepareClaude(claudePath string, args []string) (*PreparedClaude, error) {
	childEnv := os.Environ()
	childEnv = setEnv(childEnv, "TZ", maskedTimezone())

	upstreamURL, err := parseUpstreamURL(os.Getenv("ANTHROPIC_BASE_URL"))
	if err != nil {
		return nil, err
	}

	var proxy *LocalProxy
	if upstreamURL != nil && !baseURLProxyDisabled() && !isLoopbackURL(upstreamURL) {
		proxy, err = startLocalProxy(upstreamURL)
		if err != nil {
			return nil, err
		}

		localBaseURL := buildLocalBaseURL(proxy, upstreamURL)
		childEnv = setEnv(childEnv, "ANTHROPIC_BASE_URL", localBaseURL)
		childEnv = setEnv(childEnv, RealUpstreamEnvName, upstreamURL.String())
		logInfo("已隐藏 ANTHROPIC_BASE_URL host：%s -> %s", upstreamURL.Host, mustParseURL(localBaseURL).Host)
	}

	logInfo("已为 Claude 子进程设置 TZ=%s", getEnv(childEnv, "TZ"))
	return &PreparedClaude{
		Path:  claudePath,
		Args:  args,
		Env:   childEnv,
		proxy: proxy,
	}, nil
}

func (p *PreparedClaude) Close() {
	if p == nil || p.proxy == nil {
		return
	}
	shutdownProxy(p.proxy)
}

func IsClaudeCommand(command string) bool {
	if isClaudeExecutableName(command) {
		return true
	}
	if envValue := os.Getenv(command); envValue != "" {
		return isClaudeExecutableName(envValue)
	}
	return false
}

func isClaudeExecutableName(command string) bool {
	name := strings.ToLower(filepath.Base(command))
	if runtime.GOOS == "windows" {
		name = strings.TrimSuffix(name, ".exe")
		name = strings.TrimSuffix(name, ".cmd")
		name = strings.TrimSuffix(name, ".bat")
	}
	return name == "claude"
}

func resolveExplicitCommand(command string) (string, error) {
	if command == "" {
		return "", errors.New("Claude Code 启动命令不能为空")
	}

	if envValue := os.Getenv(command); envValue != "" {
		return resolveExecutable(envValue, "环境变量 "+command)
	}

	return resolveExecutable(command, "目标程序 "+command)
}

func resolveExecutable(command string, label string) (string, error) {
	var resolvedPath string
	var err error
	if strings.ContainsAny(command, `/\`) || filepath.IsAbs(command) {
		resolvedPath = command
	} else {
		resolvedPath, err = exec.LookPath(command)
		if err != nil {
			return "", fmt.Errorf("未能从 PATH 解析%s：%w", label, err)
		}
	}

	if !isExecutableFile(resolvedPath) {
		return "", fmt.Errorf("%s 指向的文件不可执行：%s", label, command)
	}

	selfPath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("获取当前可执行文件路径失败：%w", err)
	}
	if sameExecutable(resolvedPath, realPathOrOriginal(selfPath)) {
		return "", fmt.Errorf("%s 指向当前 cc-vpn-check，可执行文件会递归启动，请显式指定真实 Claude Code 入口", label)
	}

	return resolvedPath, nil
}

func ExecCommand(name string, args []string, env []string) error {
	cmd := exec.Command(name, args...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动目标程序失败: %w", err)
	}

	go func() {
		<-signalCtx.Done()
		if cmd.Process == nil {
			return
		}
		if err := cmd.Process.Signal(os.Interrupt); err != nil {
			_ = cmd.Process.Kill()
		}
	}()

	err := cmd.Wait()
	if err == nil {
		return nil
	}

	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return ExitError{Code: exitError.ExitCode()}
	}
	return err
}

type ExitError struct {
	Code int
}

func (e ExitError) Error() string {
	return "目标程序退出，状态码=" + strconv.Itoa(e.Code)
}

func isExecutableFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	if runtime.GOOS == "windows" {
		return true
	}
	return info.Mode().Perm()&0111 != 0
}

func sameExecutable(candidatePath string, realSelfPath string) bool {
	realCandidatePath := realPathOrOriginal(candidatePath)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(realCandidatePath, realSelfPath)
	}
	return realCandidatePath == realSelfPath
}

func realPathOrOriginal(path string) string {
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return path
	}
	cleanPath := filepath.Clean(realPath)
	if runtime.GOOS == "windows" {
		return strings.ToLower(cleanPath)
	}
	return cleanPath
}

func maskedTimezone() string {
	if timezone := os.Getenv("CLAUDE_GUARD_TZ"); timezone != "" {
		return timezone
	}
	return defaultMaskedTimezone
}

func parseUpstreamURL(rawURL string) (*url.URL, error) {
	if rawURL == "" {
		return nil, nil
	}
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("ANTHROPIC_BASE_URL 不是合法 URL：%s；%w", rawURL, err)
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("ANTHROPIC_BASE_URL 只支持 http/https：%s", rawURL)
	}
	if parsedURL.Host == "" {
		return nil, fmt.Errorf("ANTHROPIC_BASE_URL 缺少 host：%s", rawURL)
	}
	return parsedURL, nil
}

func baseURLProxyDisabled() bool {
	_, ok := truthyValues[strings.ToLower(os.Getenv("CLAUDE_GUARD_DISABLE_BASE_URL_PROXY"))]
	return ok
}

func isLoopbackURL(parsedURL *url.URL) bool {
	host := strings.Trim(strings.ToLower(parsedURL.Hostname()), "[]")
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func startLocalProxy(upstreamURL *url.URL) (*LocalProxy, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("启动本地监听失败：%w", err)
	}

	reverseProxy := httputil.NewSingleHostReverseProxy(&url.URL{
		Scheme: upstreamURL.Scheme,
		Host:   upstreamURL.Host,
	})
	defaultDirector := reverseProxy.Director
	reverseProxy.Director = func(req *http.Request) {
		defaultDirector(req)
		req.URL.Scheme = upstreamURL.Scheme
		req.URL.Host = upstreamURL.Host
		req.Host = upstreamURL.Host
		req.URL.Path = joinURLPath(upstreamURL.Path, req.URL.Path)
		req.URL.RawPath = ""
	}
	reverseProxy.ErrorHandler = func(resp http.ResponseWriter, req *http.Request, err error) {
		http.Error(resp, "本地 Claude 代理转发失败："+err.Error(), http.StatusBadGateway)
	}

	server := &http.Server{
		Handler:           reverseProxy,
		ReadHeaderTimeout: 30 * time.Second,
	}

	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("[claude-guard] 本地代理异常退出：%v", err)
		}
	}()

	return &LocalProxy{
		server: server,
		addr:   listener.Addr().String(),
	}, nil
}

func joinURLPath(basePath string, requestPath string) string {
	if basePath == "" || basePath == "/" {
		if requestPath == "" {
			return "/"
		}
		return requestPath
	}
	if requestPath == "" || requestPath == "/" {
		return basePath
	}
	return strings.TrimRight(basePath, "/") + "/" + strings.TrimLeft(requestPath, "/")
}

func buildLocalBaseURL(proxy *LocalProxy, upstreamURL *url.URL) string {
	localURL := &url.URL{
		Scheme:   "http",
		Host:     proxy.addr,
		Path:     upstreamURL.Path,
		RawQuery: upstreamURL.RawQuery,
	}
	return strings.TrimRight(localURL.String(), "/")
}

func mustParseURL(rawURL string) *url.URL {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	return parsedURL
}

func shutdownProxy(proxy *LocalProxy) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = proxy.server.Shutdown(ctx)
}

func setEnv(env []string, name string, value string) []string {
	prefix := name + "="
	for index, entry := range env {
		if envNameMatches(entry, name) {
			env[index] = prefix + value
			return env
		}
	}
	return append(env, prefix+value)
}

func getEnv(env []string, name string) string {
	for _, entry := range env {
		if envNameMatches(entry, name) {
			_, value, _ := strings.Cut(entry, "=")
			return value
		}
	}
	return ""
}

func envNameMatches(entry string, name string) bool {
	entryName, _, ok := strings.Cut(entry, "=")
	if !ok {
		return false
	}
	if runtime.GOOS == "windows" {
		return strings.EqualFold(entryName, name)
	}
	return entryName == name
}

func logInfo(format string, args ...any) {
	if os.Getenv("CLAUDE_GUARD_QUIET") != "" {
		return
	}
	fmt.Fprintf(os.Stderr, "[claude-guard] "+format+"\n", args...)
}
