package guard

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestIsClaudeCommandByName(t *testing.T) {
	if !IsClaudeCommand("claude") {
		t.Fatal("期望识别 claude 命令")
	}
}

func TestIsClaudeCommandByEnvName(t *testing.T) {
	t.Setenv("TEST_CLAUDE_BIN", filepath.Join("opt", "bin", executableName("claude")))

	if !IsClaudeCommand("TEST_CLAUDE_BIN") {
		t.Fatal("期望通过环境变量值识别 Claude 命令")
	}
}

func TestResolveExplicitCommandByEnvName(t *testing.T) {
	dir := t.TempDir()
	claudePath := filepath.Join(dir, executableName("claude"))
	if err := os.WriteFile(claudePath, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatalf("写入测试可执行文件失败: %v", err)
	}
	t.Setenv("TEST_CLAUDE_BIN", claudePath)

	resolvedPath, err := resolveExplicitCommand("TEST_CLAUDE_BIN")
	if err != nil {
		t.Fatalf("期望解析环境变量命令成功，实际报错: %v", err)
	}
	if resolvedPath != claudePath {
		t.Fatalf("期望解析路径为 %s，实际为 %s", claudePath, resolvedPath)
	}
}

func TestJoinURLPath(t *testing.T) {
	tests := []struct {
		name        string
		basePath    string
		requestPath string
		want        string
	}{
		{name: "根路径拼接请求路径", basePath: "/", requestPath: "/v1/messages", want: "/v1/messages"},
		{name: "基础路径拼接请求路径", basePath: "/api", requestPath: "/v1/messages", want: "/api/v1/messages"},
		{name: "请求路径为空时保留基础路径", basePath: "/api", requestPath: "/", want: "/api"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := joinURLPath(tt.basePath, tt.requestPath); got != tt.want {
				t.Fatalf("期望 %s，实际 %s", tt.want, got)
			}
		})
	}
}

func executableName(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}
