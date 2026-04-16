package checker

import (
	"context"
	"testing"
	"time"
)

type stubIPInspector struct {
	info IPInfo
	err  error
}

func (s stubIPInspector) Lookup(context.Context) (IPInfo, error) {
	return s.info, s.err
}

func TestCheckerCheckSuccess(t *testing.T) {
	c := &Checker{
		IPInspector: stubIPInspector{
			info: IPInfo{
				IP:          "1.2.3.4",
				CountryCode: "US",
				CountryName: "United States",
			},
		},
		Timeout: time.Second,
	}

	result, err := c.Check()
	if err != nil {
		t.Fatalf("期望成功，实际报错: %v", err)
	}
	if result.IP.CountryCode != "US" {
		t.Fatalf("期望国家代码为 US，实际为 %s", result.IP.CountryCode)
	}
}

func TestCheckerCheckIPError(t *testing.T) {
	c := &Checker{
		IPInspector: stubIPInspector{
			err: context.DeadlineExceeded,
		},
		Timeout: time.Second,
	}

	_, err := c.Check()
	if err == nil {
		t.Fatal("期望返回错误")
	}
}

func TestParseIPAPIISResponse(t *testing.T) {
	body := []byte(`{
		"ip":"23.236.48.55",
		"is_mobile":false,
		"is_datacenter":true,
		"is_tor":false,
		"is_proxy":false,
		"is_vpn":false,
		"company":{"name":"Google LLC","type":"hosting"},
		"asn":{"asn":396982,"org":"Google LLC","type":"hosting"},
		"location":{"country":"United States","country_code":"US"}
	}`)

	info, err := parseIPAPIISResponse("https://api.ipapi.is", body)
	if err != nil {
		t.Fatalf("期望成功解析 ipapi.is 响应，实际报错: %v", err)
	}
	if info.ASNType != "hosting" {
		t.Fatalf("期望 ASN Type 为 hosting，实际为 %s", info.ASNType)
	}
	if !info.IsDatacenter {
		t.Fatal("期望识别 datacenter 标记")
	}
	if info.CountryCode != "US" {
		t.Fatalf("期望国家代码为 US，实际为 %s", info.CountryCode)
	}
}
