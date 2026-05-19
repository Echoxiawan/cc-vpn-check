# cc-vpn-check

一个使用 Go 编写的命令行守卫程序。

它的作用是在启动指定程序之前，先检查当前出口 IP 是否满足预设条件。只有检查通过，才会真正启动目标程序；否则直接拒绝启动。

当前已实现的检查规则：

- 出口 IP 必须位于美国，且大洲为北美（NA）
- IP 地址块必须由 ARIN（北美地址分配机构）分配
- ASN 必须注册在 ARIN，归属国必须是美国，且处于活跃状态
- `asn.type` 必须为 `isp`
- `company.type` 如果有值，必须为 `isp`
- ASN 与公司的滥用评分（abuser_score）不超过 0.15
- 排除 `datacenter`、`vpn`、`proxy`、`tor`、`abuser`、`bogon`
- 排除 `mobile`、`satellite`、`crawler`

程序优先使用 `ipapi.is` 获取较完整的网络属性信息，并在失败时回退到其他 IP 信息源。

## 用法

```
cc-vpn-check [--skip-ip-check] <程序> [参数...]
```

| 参数 | 说明 |
|---|---|
| `--skip-ip-check` | 跳过所有 IP 校验，直接启动目标程序 |

## 适用场景

- 启动某个命令前，必须确认出口 IP 在美国
- 只允许更接近家庭宽带特征的 ISP 网络
- 过滤掉机房、云主机、托管、移动、卫星、爬虫、VPN、代理等出口

## 工作原理

程序执行流程如下：

1. 接收要启动的目标程序及参数
2. 查询当前出口 IP 的地理和网络属性信息
3. 输出 IP 情报摘要
4. 执行预设规则校验
5. 校验通过后，启动目标程序

### IP 校验规则（按顺序执行）

| 规则 | 要求 |
|---|---|
| `country_code` | 必须为 `US` |
| `continent` | 如果有值，必须为 `NA` |
| `asn.country` | 如果有值，必须为 `us` |
| `rir`（IP 块 RIR） | 如果有值，必须为 `ARIN` |
| `asn.rir` | 如果有值，必须为 `ARIN` |
| `asn.active` | 如果 `asn.rir` 有值，必须为 `true` |
| `asn.type` | 必须为 `isp` |
| `company.type` | 如果有值，必须为 `isp` |
| `asn.abuser_score` | 必须 ≤ 0.15 |
| `company.abuser_score` | 必须 ≤ 0.15 |
| `is_datacenter` | 必须为 `false` |
| `is_vpn` | 必须为 `false` |
| `is_proxy` | 必须为 `false` |
| `is_tor` | 必须为 `false` |
| `is_abuser` | 必须为 `false` |
| `is_bogon` | 必须为 `false` |
| `is_mobile` | 必须为 `false` |
| `is_satellite` | 必须为 `false` |
| `is_crawler` | 必须为 `false` |

## 项目结构

```text
cc-vpn-check/
├── go.mod
├── main.go
├── build.sh
├── README.md
└── internal/
    └── checker/
        ├── checker.go
        └── checker_test.go
```

## 环境要求

直接使用 `dist/` 目录中已编译的可执行文件，无需安装 Go。

从源码编译需要：Go 1.22 或更高版本。

## 快速开始

`dist/` 目录已包含各平台编译好的可执行文件，**无需安装 Go，下载即用**。

| 文件                            | 平台                    |
| ------------------------------- | ----------------------- |
| `dist/cc-vpn-check-mac`         | macOS（默认，同 arm64） |
| `dist/cc-vpn-check-mac-arm64`   | macOS Apple Silicon     |
| `dist/cc-vpn-check-mac-amd64`   | macOS Intel             |
| `dist/cc-vpn-check-linux`       | Linux amd64             |
| `dist/cc-vpn-check-windows.exe` | Windows amd64           |

### macOS

```bash
chmod +x ./dist/cc-vpn-check-mac
./dist/cc-vpn-check-mac claude
./dist/cc-vpn-check-mac claude --help
./dist/cc-vpn-check-mac python app.py
```

Apple Silicon 与 Intel 各有独立版本：

```bash
./dist/cc-vpn-check-mac-arm64   # Apple Silicon
./dist/cc-vpn-check-mac-amd64   # Intel
```

### Linux

```bash
chmod +x ./dist/cc-vpn-check-linux
./dist/cc-vpn-check-linux claude
```

### Windows PowerShell

```powershell
.\dist\cc-vpn-check-windows.exe claude
.\dist\cc-vpn-check-windows.exe claude --help
```

### 跳过 IP 校验

```bash
cc-vpn-check --skip-ip-check claude
```

## 从源码编译

> `dist/` 中的文件已是最新编译版本，通常不需要手动编译。

如需自行编译，使用项目自带的脚本一次生成所有平台的可执行文件：

```bash
bash build.sh
```

也可以只编译当前平台：

```bash
go build -o cc-vpn-check .
```

## 如何加入 PATH

将可执行文件复制到 `$HOME/bin`，并加入 `PATH`：

### macOS / Linux

```bash
mkdir -p "$HOME/bin"
cp ./dist/cc-vpn-check-mac "$HOME/bin/cc-vpn-check"
chmod +x "$HOME/bin/cc-vpn-check"
```

在 `~/.zshrc` 或 `~/.bashrc` 中加入：

```bash
export PATH="$HOME/bin:$PATH"
```

重新加载配置：

```bash
source ~/.zshrc
```

### Windows PowerShell

```powershell
New-Item -ItemType Directory -Force "$HOME\bin"
Copy-Item .\dist\cc-vpn-check-windows.exe "$HOME\bin\cc-vpn-check.exe" -Force
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";$HOME\bin", "User")
```

## 如何接管 `claude` 命令

推荐使用包装脚本，而不是直接覆盖官方二进制，方便随时回退。

### macOS / Linux：shell 函数

先确认真实 `claude` 路径：

```bash
which claude
```

在 `~/.zshrc` 或 `~/.bashrc` 中加入：

```bash
claude() {
  cc-vpn-check /usr/local/bin/claude "$@"
}
```

重新加载配置后，执行 `claude` 会自动经过 IP 校验。

### Windows PowerShell：函数包装

编辑配置文件：

```powershell
notepad $PROFILE
```

加入：

```powershell
function claude {
    cc-vpn-check.exe "C:\Program Files\Claude\claude.exe" @args
}
```

## 典型输出

校验通过：

```text
IP 信息源: https://api.ipapi.is
IP 接口原始响应: {...完整JSON...}
地理信息: country=US(United States) continent=NA
RIR: ip_rir=ARIN asn_rir=ARIN
AS 信息: asn=7922 org=COMCAST-7922 type=isp country=us active=true abuser_score=0.0012
公司信息: name=Comcast Cable Communications type=isp abuser_score=0.0008
网络标记: mobile=false satellite=false crawler=false datacenter=false tor=false proxy=false vpn=false abuser=false bogon=false
检查通过: 出口 IP=1.2.3.4，国家=US(United States)
```

校验失败示例：

```text
当前出口 IP 不符合要求: ip=1.2.3.4 country=CN(China)，仅允许美国出口 IP 启动目标程序
当前出口 IP 的 RIR 不是 ARIN: rir=APNIC，已阻止启动
当前出口 IP 的 ASN 滥用评分过高(0.3500 > 0.15): asn=12345 org=Example Hosting，已阻止启动
当前出口 IP 的 ASN 类型不是 isp，已阻止启动: asn=12345 org=Example Cloud asn_type=hosting
当前出口 IP 被识别为 VPN 出口节点，已阻止启动
当前出口 IP 被识别为移动网络，不符合家庭宽带判定要求，已阻止启动
```

## 注意事项

- 如果目标程序不在 `PATH` 中，请传入完整路径
- 本程序只做出口 IP 与网络属性校验，不检查系统是否开启代理
- `asn.type == isp` 只能说明出口属于 ISP，不等于 100% 证明是传统家庭宽带
- RIR / ASN country 等字段仅在使用富数据源（`ipapi.is`）时填充；回退到其他数据源时这些规则自动跳过

## 开发与测试

```bash
go test ./...
go build ./...
```
