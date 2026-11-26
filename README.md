# ESurfingClient-GoVersion

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8.svg)](https://go.dev/)

轻量级、跨平台、零外挂依赖的广东电信天翼校园网（GDPortal / ESurfing）认证客户端套件，包含纯 Go 核心（`gdportal-lite`）与现代 Windows 桌面端（`GDPortal` Desktop）。

> [!NOTE]
> 欢迎各位提Issues和PR，看到会及时处理

---
## 主要优势
- **摆脱原版客户端的恶心限制**
- **处理了原版客户端在DNS更换后无法正常认证**
- **处理了代理客户端使用TUN模式时导致无法正常认证**
- **本项目基于原版客户端的动态解析作认证，理论上只要x信不更新客户端或者算法加密就一直都能正常认证，无视算法更新**
  
## 核心特性

- **纯 Go 跨平台动态算法引擎 (`gdportal-lite/x86emu`)**
  - 内置自主实现的纯 Go x86-32 PE32 加载器、指令缓存与 HLE 模拟器，原生执行服务端动态下发的 32 位加密算法 DLL（兼容静态 AES / SM4 / ZUC / XTEA / 3DES 与动态 `gen` 家族模板）。
  - 零 CGO、零 RWX 内存页、无需 32 位系统库，可直接运行于 `Windows (amd64/386)`、`Linux (amd64/arm64/mipsle)`、`macOS (arm64/amd64)` 及 OpenWrt 路由器。
- **零配置全省多高校自适应**
  - 自动沿物理网卡多跳重定向与 `<server-clusters>` 识别 `school` / `domain` / `area` 与认证集群节点，无需手动抓包填参。
  - 支持 `:7001` 故障节点快速切换与降权重试，取票重试共享总预算与退避保护，避免无意义长等待。
- **TUN 代理 / 自定义 DNS 免疫**
  - 通过 `IP_UNICAST_IF`（Windows）与源 IP 绑定强行让认证/探测流量直出物理网卡，自动绕过 Clash / Mihomo / sing-box / Tailscale 等 TUN 虚拟网卡与系统代理。
  - 支持从 Windows 注册表恢复被自定义 DNS 覆盖的原始 DHCP DNS，并发 RFC1035 IPv4 竞速过滤 Fake-IP（`198.18.0.0/15`），且内置省调度节点保底。
- **8 秒轻量哨兵与断网自愈**
  - 低开销标准库接口巡检（无频繁路由表/注册表扫描），实时感知物理网卡断连、IP 变更与强制认证劫持，配合心跳会话失效瞬时判定，掉线后自动恢复认证。
- **安全与防隐私泄露设计**
  - 桌面凭据通过 Windows DPAPI（`CryptProtectData`）加密落盘；切换账号时严禁误用旧密码，认证成功后才更新已保存凭据。
  - 桌面反代服务启用独立会话 Token Cookie（`HttpOnly; SameSite=Strict`）、`Host`/`Origin`/`Sec-Fetch-Site` 防护及写操作 HTTP 方法强制校验。
  - 桌面界面默认开启 **隐私保护模式**（隐藏手机号、学校参数、IP、MAC 方便截图），内置一键 `Doctor` 链路体检及严格脱敏后的 GitHub Issue 报告导出（Markdown / JSON）。

---

## 快速开始

前往 [Releases](https://github.com/shixin08052/GDPortal/releases) 下载对应平台的预编译文件：

### 1. Windows 桌面版（推荐）

下载 `GDPortal-v2.0.0-windows-amd64.exe` 直接双击运行即可（单文件免安装，内置 gzip 压缩核心与系统托盘，依赖 Windows 自带或常用的 Edge WebView2 Runtime；未安装时自动回退浏览器展示受保护本地控制台）。

- 输入校园网账号与密码，点击 **连接校园网**，学校参数会自动识别。
- 关闭窗口可最小化至托盘低内存保活，支持设置开机自启与启动自动连接。

### 2. 命令行 / 路由器 / 服务器版 (`gdportal-lite`)

```bash
# 基本认证与后台心跳保活（默认自动识别学校/域名/区号与物理出口）
./gdportal-lite -u <手机号或学号> -p <密码>

# 常用参数示例
./gdportal-lite -u <账号> -p <密码> -force          # 强制跳过在线探测重新认证
./gdportal-lite -u <账号> -p <密码> -iface WLAN     # 手动指定物理出口网卡 (支持 ifIndex / 网卡名 / IPv4)
./gdportal-lite -doctor                             # 只读网络体检 (物理网卡 / TUN 绕过 / DNS / 节点)
./gdportal-lite -issue                              # 输出严格脱敏后的 Issue Markdown 报告
```

<details>
<summary>完整命令行参数列表</summary>

| 参数 | 说明 |
| --- | --- |
| `-u` | 校园网账号（手机号 / 学号） |
| `-p` | 校园网密码 |
| `-force` | 跳过在线检测，强制重新发起认证 |
| `-iface` | 指定物理出口网卡（支持 `ifIndex`、网卡名或 IPv4） |
| `-school` / `-domain` / `-area` | 手动覆盖学校 ID / 域名 / 区号（默认自动发现，通常留空） |
| `-query-state` | 登录前查询 `state.cgi` 状态（默认关闭以降低耗时） |
| `-ostag` | 覆盖上报的操作系统版本标识 |
| `-doctor` | 运行只读网络与绕过诊断体检 |
| `-issue` | 输出严格脱敏后的 GitHub Issue Markdown 诊断报告 |
| `-debug` | 开启详细协议与调试日志落盘 |

</details>

---

## 目录结构

```text
.
├── build.ps1                  # Windows 一键测试、静态检查与单文件桌面版打包脚本
├── LICENSE                    # MIT 开源协议
├── gdportal-lite/             # 跨平台核心 CLI / Daemon 与协议加密实现
│   ├── cipher/                # 内置静态分组/流加密算法实现 (AES/SM4/ZUC/XTEA/3DES)
│   ├── x86emu/                # 纯 Go x86-32 PE32 加载器、指令缓存与 HLE 模拟器
│   └── vendor/                # 离线依赖包 (emmansun/gmsm, ulikunitz/xz)
└── gdportal-desktop/          # Windows 桌面外壳 (WebView2 + 托盘 + 受保护反代 + 内嵌核心)
    └── ui/                    # 前端静态资源 (HTML / CSS / JS)
```

---

## 从源码构建与测试

### 环境要求
- Go 1.26+
- （仅运行 `-race` 竞态检测时需要 GCC，常规构建与 `build.ps1` 均使用纯 Go `CGO_ENABLED=0`）

### 一键完整测试并构建桌面单文件 (`GDPortal.exe`)

```powershell
.\build.ps1
```

产物将输出至根目录 `GDPortal.exe` 与 `gdportal-lite/gdportal-lite.exe`（均已在 `.gitignore` 中排除）。

### 手动测试与竞态检查

> [!IMPORTANT]
> `gdportal-lite/vendor` 中的 `gmsm` 使用纯 Go 实现，运行 `gdportal-lite` 的所有 `go test` / `go vet` / `go build` 命令时请务必加上 `-tags purego`。

```powershell
# 常规全量测试与静态检查 (CGO_ENABLED=0)
$env:CGO_ENABLED = '0'
Push-Location gdportal-lite
$env:GOARCH = '386';   go test -tags purego -count=1 ./...; go vet -tags purego -unsafeptr=false ./...
$env:GOARCH = 'amd64'; go test -tags purego -count=1 ./...; go vet -tags purego -unsafeptr=false ./...
Pop-Location

Push-Location gdportal-desktop
$env:GOARCH = 'amd64'; go test -v ./...; go vet -unsafeptr=false ./...
Pop-Location

# 竞态检测（Windows amd64，需 CGO_ENABLED=1 与 gcc）
$env:CGO_ENABLED = '1'; $env:GOARCH = 'amd64'
Push-Location gdportal-lite;    go test -race -tags purego -count=1 ./...; Pop-Location
Push-Location gdportal-desktop; go test -race -count=1 ./...; Pop-Location
```

### 跨平台编译核心 (`gdportal-lite`)

```powershell
Push-Location gdportal-lite
$env:CGO_ENABLED = '0'

$env:GOOS = 'linux';   $env:GOARCH = 'amd64';  go build -tags purego -trimpath -ldflags='-s -w' -o gdportal-lite-linux-amd64 .
$env:GOOS = 'linux';   $env:GOARCH = 'arm64';  go build -tags purego -trimpath -ldflags='-s -w' -o gdportal-lite-linux-arm64 .
$env:GOOS = 'linux';   $env:GOARCH = 'mipsle'; $env:GOMIPS = 'softfloat'; go build -tags purego -trimpath -ldflags='-s -w' -o gdportal-lite-linux-mipsle .
Remove-Item Env:GOMIPS -ErrorAction SilentlyContinue

$env:GOOS = 'darwin';  $env:GOARCH = 'arm64';  go build -tags purego -trimpath -ldflags='-s -w' -o gdportal-lite-darwin-arm64 .
$env:GOOS = 'darwin';  $env:GOARCH = 'amd64';  go build -tags purego -trimpath -ldflags='-s -w' -o gdportal-lite-darwin-amd64 .
Pop-Location
```

### 可选：使用本地算法样本集运行回归验证

若本地保存有历史抓包下发的 `.bin` 算法样本目录，可通过环境变量 `GDPORTAL_SAMPLE_DIR` 启用真实样本端到端往返与 32 位原生交叉对拍测试（未设置时自动跳过）：

```powershell
$env:GDPORTAL_SAMPLE_DIR = 'D:\path\to\dll-samples'
Push-Location gdportal-lite
$env:CGO_ENABLED = '0'; $env:GOARCH = 'amd64'
go test -tags purego -v ./x86emu
Pop-Location
Remove-Item Env:GDPORTAL_SAMPLE_DIR
```

---

## 隐私与安全说明

- 个人配置文件（`config.json`）、桌面本地启动脚本（`启动.bat`）、节点/会话运行时缓存（`portal_cache.txt`、`profile.txt`、`session.txt`）、抓包样本（`*.bin`、`*.pcap`）与发布包目录（`release/`）均已在 `.gitignore` 中排除。
- 提交诊断信息到 Issue 前，请优先使用程序内置的 **一键复制 GitHub Issue 报告** 或 `-issue` 命令，勿粘贴未脱敏日志或个人配置。
- 本项目基于 [MIT License](LICENSE) 开源，仅供网络协议研究与校园网用户合规自用。

## 致谢
感谢[Linux.do](https://linux.do)社区能支持本项目推广，非常感谢所有人的贡献和Stars还有Issues  
同类支持多平台的优秀项目[BadGhost520/ESurfingClient-CVersion](https://github.com/BadGhost520/ESurfingClient-CVersion)
