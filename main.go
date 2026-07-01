package main

import (
	"errors"
	"fmt"
	"os"

	"cc-vpn-check/internal/checker"
	"cc-vpn-check/internal/guard"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		var exitErr guard.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.Code)
		}
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func run(args []string) error {
	skipIPCheck := false
	if len(args) > 0 && args[0] == "--skip-ip-check" {
		skipIPCheck = true
		args = args[1:]
	}

	if len(args) == 0 || args[0] == "" {
		return errors.New("用法: cc-vpn-check [--skip-ip-check] <程序> [参数...]")
	}

	if skipIPCheck {
		fmt.Println("已跳过 IP 校验，直接启动目标程序")
		return runTarget(args)
	}

	c := checker.NewDefaultChecker()
	result, err := c.Check()

	if err != nil {
		return fmt.Errorf("启动前检查失败: %w", err)
	}

	fmt.Printf("IP 信息源: %s\n", result.IP.Source)
	fmt.Printf("IP 接口原始响应: %s\n", result.IP.RawResponse)
	fmt.Printf("地理信息: country=%s(%s) continent=%s\n", result.IP.CountryCode, result.IP.CountryName, result.IP.Continent)
	fmt.Printf("RIR: ip_rir=%s asn_rir=%s\n", result.IP.RIR, result.IP.ASNRIR)
	fmt.Printf("AS 信息: asn=%d org=%s type=%s country=%s active=%t abuser_score=%.4f\n",
		result.IP.ASN, result.IP.ASNOrg, result.IP.ASNType,
		result.IP.ASNCountry, result.IP.ASNActive, result.IP.ASNAbuserScore)
	fmt.Printf("公司信息: name=%s type=%s abuser_score=%.4f\n",
		result.IP.CompanyName, result.IP.CompanyType, result.IP.CompanyAbuserScore)
	fmt.Printf(
		"网络标记: mobile=%t satellite=%t crawler=%t datacenter=%t tor=%t proxy=%t vpn=%t abuser=%t bogon=%t\n",
		result.IP.IsMobile,
		result.IP.IsSatellite,
		result.IP.IsCrawler,
		result.IP.IsDatacenter,
		result.IP.IsTor,
		result.IP.IsProxy,
		result.IP.IsVPN,
		result.IP.IsAbuser,
		result.IP.IsBogon,
	)

	if err := checker.ValidateUSResidentialLikeIP(result.IP); err != nil {
		return err
	}

	fmt.Printf("检查通过: 出口 IP=%s，国家=%s(%s)\n", result.IP.IP, result.IP.CountryCode, result.IP.CountryName)
	return runTarget(args)
}

func runTarget(args []string) error {
	if len(args) == 0 || args[0] == "" {
		return errors.New("用法: cc-vpn-check [--skip-ip-check] <程序> [参数...]")
	}

	if guard.IsClaudeCommand(args[0]) {
		prepared, err := guard.PrepareClaudeCommand(args[0], args[1:])
		if err != nil {
			return err
		}
		defer prepared.Close()
		return guard.ExecCommand(prepared.Path, prepared.Args, prepared.Env)
	}

	return checker.RunCommand(args[0], args[1:])
}
