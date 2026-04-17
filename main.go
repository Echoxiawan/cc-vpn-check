package main

import (
	"errors"
	"fmt"
	"os"

	"cc-vpn-check/internal/checker"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("用法: cc-vpn-check <程序> [参数...]")
	}

	c := checker.NewDefaultChecker()
	result, err := c.Check()

	if err != nil {
		return fmt.Errorf("启动前检查失败: %w", err)
	}

	fmt.Printf("IP 信息源: %s\n", result.IP.Source)
	fmt.Printf("IP 接口原始响应: %s\n", result.IP.RawResponse)
	fmt.Printf("AS 信息: asn=%d org=%s type=%s\n", result.IP.ASN, result.IP.ASNOrg, result.IP.ASNType)
	fmt.Printf("公司信息: name=%s type=%s\n", result.IP.CompanyName, result.IP.CompanyType)
	fmt.Printf(
		"网络标记: mobile=%t satellite=%t crawler=%t datacenter=%t tor=%t proxy=%t vpn=%t\n",
		result.IP.IsMobile,
		result.IP.IsSatellite,
		result.IP.IsCrawler,
		result.IP.IsDatacenter,
		result.IP.IsTor,
		result.IP.IsProxy,
		result.IP.IsVPN,
	)

	if err := checker.ValidateUSResidentialLikeIP(result.IP); err != nil {
		return err
	}

	fmt.Printf("检查通过: 出口 IP=%s，国家=%s(%s)\n", result.IP.IP, result.IP.CountryCode, result.IP.CountryName)
	return checker.RunCommand(args[0], args[1:])
}
