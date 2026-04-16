# cc-vpn-check

一个使用 Go 编写的命令行守卫程序。

它的作用是在启动指定程序之前，先检查当前出口 IP 是否满足预设条件。只有检查通过，才会真正启动目标程序；否则直接拒绝启动。

当前已实现的检查规则：

- 检查出口 IP 是否为美国 IP
- 检查 ASN Type 是否为 `hosting`
- 如果 `asn.type == hosting`，则拒绝启动
- 启动前打印 IP 情报接口的原始 JSON，便于继续扩展规则

目前程序优先使用 `ipapi.is` 获取较完整的网络属性信息，并在失败时回退到其他 IP 信息源。

## 适用场景

适用于这类需求：

- 启动某个命令前，必须确认出口 IP 在美国
- 希望过滤掉明显的机房、云主机、托管网络出口
- 希望后续继续增加住宅宽带、移动网络、VPN、代理等校验维度

## 工作原理

程序执行流程如下：

1. 接收你要启动的目标程序及参数
2. 查询当前出口 IP 的地理和网络属性信息
3. 输出 IP 接口原始响应
4. 执行预设规则校验
5. 校验通过后，启动目标程序

当前 IP 校验规则：

- `country_code` 必须为 `US`
- `asn.type` 不能为 `hosting`

## 项目结构

```text
cc-vpn-check/
├── go.mod
├── main.go
├── README.md
└── internal/
    └── checker/
        ├── checker.go
        └── checker_test.go
```

## 环境要求

- Go 1.22 或更高版本

可先检查本机 Go 版本：

```bash
go version
```

## 快速开始

在项目目录中执行：

```bash
go run . claude
```

如果你要给目标程序传参数：

```bash
go run . claude --help
go run . python app.py
go run . node server.js
```

程序会先打印 IP 信息源、原始响应、AS 信息和网络标记，然后决定是否放行启动目标程序。

## 编译教程

### macOS

在项目根目录执行：

```bash
go build -o cc-vpn-check .
```

编译完成后会生成：

```text
./cc-vpn-check
```

直接运行：

```bash
./cc-vpn-check claude
```

### Linux

在项目根目录执行：

```bash
go build -o cc-vpn-check .
```

编译完成后会生成：

```text
./cc-vpn-check
```

直接运行：

```bash
./cc-vpn-check claude
```

### Windows PowerShell

在项目根目录执行：

```powershell
go build -o cc-vpn-check.exe .
```

编译完成后会生成：

```text
.\cc-vpn-check.exe
```

直接运行：

```powershell
.\cc-vpn-check.exe claude
```

## 交叉编译教程

如果你想在一个系统上编译另一个系统可执行文件，可以这样做。

### 编译 macOS 可执行文件

```bash
GOOS=darwin GOARCH=amd64 go build -o cc-vpn-check-macos-amd64 .
GOOS=darwin GOARCH=arm64 go build -o cc-vpn-check-macos-arm64 .
```

### 编译 Linux 可执行文件

```bash
GOOS=linux GOARCH=amd64 go build -o cc-vpn-check-linux-amd64 .
GOOS=linux GOARCH=arm64 go build -o cc-vpn-check-linux-arm64 .
```

### 编译 Windows 可执行文件

```bash
GOOS=windows GOARCH=amd64 go build -o cc-vpn-check-windows-amd64.exe .
GOOS=windows GOARCH=arm64 go build -o cc-vpn-check-windows-arm64.exe .
```

## 如何加入环境变量 PATH

为了可以在任意目录直接运行 `cc-vpn-check`，需要把可执行文件所在目录加入 `PATH`。

推荐做法：

- 新建一个专门存放个人命令行工具的目录
- 把编译好的二进制文件放进去
- 把该目录加入 `PATH`

下面分别说明。

### macOS

先创建目录：

```bash
mkdir -p "$HOME/bin"
```

把程序复制进去：

```bash
cp ./cc-vpn-check "$HOME/bin/cc-vpn-check"
chmod +x "$HOME/bin/cc-vpn-check"
```

如果你使用 `zsh`，编辑 `~/.zshrc`：

```bash
export PATH="$HOME/bin:$PATH"
```

让配置生效：

```bash
source ~/.zshrc
```

验证：

```bash
which cc-vpn-check
cc-vpn-check
```

如果你使用 `bash`，把同样内容写入 `~/.bashrc` 或 `~/.bash_profile`。

### Linux

先创建目录：

```bash
mkdir -p "$HOME/bin"
```

把程序复制进去：

```bash
cp ./cc-vpn-check "$HOME/bin/cc-vpn-check"
chmod +x "$HOME/bin/cc-vpn-check"
```

编辑 `~/.bashrc`、`~/.zshrc` 或你当前 shell 的配置文件，加入：

```bash
export PATH="$HOME/bin:$PATH"
```

让配置生效：

```bash
source ~/.bashrc
```

或：

```bash
source ~/.zshrc
```

验证：

```bash
which cc-vpn-check
cc-vpn-check
```

### Windows PowerShell

先创建一个目录，例如：

```powershell
New-Item -ItemType Directory -Force "$HOME\bin"
```

复制可执行文件：

```powershell
Copy-Item .\cc-vpn-check.exe "$HOME\bin\cc-vpn-check.exe" -Force
```

将目录加入当前用户 PATH：

```powershell
[Environment]::SetEnvironmentVariable(
  "Path",
  $env:Path + ";$HOME\bin",
  "User"
)
```

关闭并重新打开 PowerShell 后验证：

```powershell
Get-Command cc-vpn-check
cc-vpn-check
```

如果想立刻在当前会话生效：

```powershell
$env:Path = $env:Path + ";$HOME\bin"
```

## 如何接管 `claude` 命令

如果你的目标是输入 `claude` 时，先经过本程序检查，再决定是否启动真正的 `claude`，推荐使用包装脚本，而不是直接覆盖官方二进制。

原因：

- 更安全
- 更容易回退
- 不会破坏原始程序

下面给出各平台推荐做法。

### macOS / Linux：使用 shell 函数

先确认真实 `claude` 程序路径，例如：

```bash
which claude
```

假设真实路径为：

```text
/usr/local/bin/claude
```

在 `~/.zshrc` 或 `~/.bashrc` 中加入：

```bash
claude() {
  cc-vpn-check /usr/local/bin/claude "$@"
}
```

重新加载配置：

```bash
source ~/.zshrc
```

或者：

```bash
source ~/.bashrc
```

以后执行：

```bash
claude
claude --help
```

都会先经过 `cc-vpn-check` 检查。

### Windows PowerShell：使用函数包装

先查真实 `claude.exe` 路径：

```powershell
Get-Command claude
```

假设真实路径为：

```text
C:\Program Files\Claude\claude.exe
```

编辑你的 PowerShell 配置文件：

```powershell
notepad $PROFILE
```

加入：

```powershell
function claude {
    cc-vpn-check.exe "C:\Program Files\Claude\claude.exe" @args
}
```

重新打开 PowerShell，或者执行：

```powershell
. $PROFILE
```

以后执行：

```powershell
claude
claude --help
```

都会先经过 `cc-vpn-check.exe` 检查。

## 使用示例

### 启动 claude

```bash
cc-vpn-check claude
```

### 启动 Python 程序

```bash
cc-vpn-check python app.py
```

### 启动 Node.js 程序

```bash
cc-vpn-check node server.js
```

### 指定真实二进制路径

```bash
cc-vpn-check /usr/local/bin/claude
```

## 典型输出示例

```text
IP 信息源: https://api.ipapi.is
IP 接口原始响应: {...完整JSON...}
AS 信息: asn=12345 org=Example Org type=isp
公司信息: name=Example ISP type=isp
网络标记: mobile=false datacenter=false tor=false proxy=false vpn=false
检查通过: 出口 IP=1.2.3.4，国家=US(United States)
```

如果校验失败，可能输出：

```text
当前出口 IP 不符合要求: ip=1.2.3.4 country=CN(China)，仅允许美国出口 IP 启动目标程序
```

或：

```text
当前出口 IP 的 ASN 类型为 hosting，判定为非住宅宽带倾向网络，已阻止启动: asn=12345 org=Example Hosting
```

## 当前限制

目前还不能严格、准确地判断“是否家庭宽带”，原因是：

- 不是所有 IP 情报服务都会返回明确的住宅宽带字段
- 即使有 `asn.type` 和 `company.type`，也只能提高判断置信度，不能做到绝对准确
- 同一个 ASN 下可能同时存在家庭宽带、企业宽带、专线等多种出口

当前规则更适合完成：

- 排除明显机房网络
- 排除明显托管或云服务出口
- 保留后续继续增强住宅宽带判断的能力

## 后续可扩展方向

可以继续增加这些校验维度：

- `company.type`
- `is_mobile`
- `is_proxy`
- `is_vpn`
- `is_tor`
- `is_datacenter`
- ASN 组织白名单 / 黑名单
- 住宅宽带三态判定：`通过 / 拒绝 / 不确定`

## 开发与测试

在项目根目录执行测试：

```bash
go test ./...
```

编译：

```bash
go build ./...
```

## 注意事项

- 如果目标程序本身不在 `PATH` 中，请传入完整路径
- 本程序当前只做出口 IP 与网络属性校验，不检查系统是否开启代理
- 如果后续需要更强的住宅宽带判定，可以继续增加更多 IP 情报源和规则
