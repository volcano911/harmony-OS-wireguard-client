# HarmonyOS WireGuard VPN Client

面向 HarmonyOS NEXT API 23 的 WireGuard VPN 客户端与原生 TUN 适配实现。

> [!IMPORTANT]
> 原作者/上游维护者：[wan0791](https://github.com/wan0791)
>
> 原始项目：[wan0791/harmonyos-wg-client](https://github.com/wan0791/harmonyos-wg-client)
>
> 本项目基于该作者以 MIT License 发布的成果继续开发。ArkTS 密码学、
> WireGuard 握手与传输、配置导入、扫码及基础 HarmonyOS 客户端实现来自
> 上游项目；本仓库主要整理 API 23 上的原生 TUN 读取、路由构造、UDP
> 数据面和后台生命周期适配。

## 当前状态

以下数据路径已在 HarmonyOS 6.1 / API 23 ARM64 零售设备上完成验证：

```text
WireGuard Noise IKpsk2 握手            ✅
ChaCha20-Poly1305 Transport 双向通信    ✅
C++ 独立线程 poll/read TUN             ✅
VpnExtension 内原生 UDP 收发            ✅
AllowedIPs 按 CIDR 分流                 ✅
TCP 三次握手和 HTTP 双向传输             ✅
```

公开仓库不包含真实服务器地址、内网网段、设备标识、调试证书、Provision
Profile、签名 HAP 或 WireGuard 密钥。

## API 23 适配要点

### 1. 完整构造 `VpnConfig.routes`

将 WireGuard `AllowedIPs` 转换为 `connection.RouteInfo[]`。API 23
实测需要明确设置 `vpn-tun`、destination、gateway 和 route flags；字段
不完整时，`VpnConnection.create()` 可能成功，但路由不会按预期生效。

### 2. 原生线程读取 TUN

不在 ArkTS 事件循环中持续调用 `fileIo.read()`。当前实现由 C++ pthread
执行：

```text
poll(TUN fd, POLLIN)
  → read() 完整 IP 包
  → napi_threadsafe_function
  → ArkTS 顺序处理队列
```

返回数据通过原生 `write()` 写回 TUN，避免阻塞 VpnExtension 的 ArkTS
执行线程。

### 3. 数据面留在 VpnExtension

原生 WireGuard UDP Socket 在创建 TUN 前建立，握手、Transport、重密钥和
TUN 转发留在 VpnExtension 中。主界面只负责配置、启动、停止和诊断，因此
切换到浏览器或其他应用后不会依赖前台页面继续运行。

## 架构

```text
应用请求
  → HarmonyOS RouteInfo
  → TUN fd
  → C++ poll/read 线程
  → ArkTS 顺序队列
  → SNAT + WireGuard Transport 加密
  → NAPI sendto
  → WireGuard 服务端

WireGuard 服务端回包
  → C++ UDP 收包线程
  → WireGuard Transport 解密
  → 反向 SNAT + checksum 修正
  → 原生 write(TUN fd)
  → 发起请求的应用
```

## 功能

| 功能 | 状态 |
|---|---|
| WireGuard `.conf` 导入 | ✅ |
| 二维码扫描 | ✅ |
| Noise IKpsk2 握手 | ✅ |
| Transport 加解密 | ✅ |
| Keepalive 与 Rekey | ✅ |
| SNAT 与 TCP/UDP checksum 修正 | ✅ |
| Transport 反重放 | ✅ |
| AllowedIPs IPv4 CIDR 分流 | ✅ |
| 后台 VpnExtension 数据转发 | ✅ |

## 配置

推荐导入标准 WireGuard `.conf` 文件。请使用自己的配置，不要把实际密钥、
Endpoint 或内网地址提交到 Git：

```ini
[Interface]
PrivateKey = <CLIENT_PRIVATE_KEY>
Address = <TUN_ADDRESS>/<PREFIX_LENGTH>
DNS = <DNS_SERVER>

[Peer]
PublicKey = <SERVER_PUBLIC_KEY>
PresharedKey = <OPTIONAL_PRESHARED_KEY>
Endpoint = <WG_SERVER_HOST>:<WG_SERVER_PORT>
AllowedIPs = <PRIVATE_CIDR>[,<ANOTHER_CIDR>]
PersistentKeepalive = 25
```

## 构建

需要 HarmonyOS SDK API 23 和官方命令行工具。设置工具目录后执行：

```bash
export HARMONYOS_COMMANDLINE_HOME=/path/to/command-line-tools
./scripts/build-official-unsigned.sh
```

脚本只生成 unsigned HAP。零售设备安装包必须使用你自己的华为开发者证书和
Provision Profile 签名。证书、私钥、Profile 和签名产物不应提交到仓库。

## 已知限制

- 当前数据面只处理 IPv4。
- `fileIo.read()` 与 TUN fd 的正式支持边界仍需平台文档进一步明确；本项目
  使用 NAPI/POSIX `poll/read`。
- `protectProcessNet()` 在不同系统版本上的行为可能不同；当前实现不把它
  作为唯一的自路由保护手段。
- 目标服务仍需监听对应端口，并由服务端防火墙和转发策略放行。

## 公开发布说明


- 不发布调试证书绑定的签名 HAP。
- 示例全部使用占位符，不对应任何真实网络。
- 详细技术说明见
  [docs/harmonyos-wg-ffi-report.md](docs/harmonyos-wg-ffi-report.md)。

## 上游与致谢

- 原作者/上游维护者：[wan0791](https://github.com/wan0791)
- 原始项目：[wan0791/harmonyos-wg-client](https://github.com/wan0791/harmonyos-wg-client)
- 原始作者及贡献者保留其各自代码和设计贡献。
- 本仓库所述 API 23 适配是在上述项目成果上继续完成，不代表对上游原始
  实现的重新署名或所有权主张。
- 本公共版本继续遵循仓库中的 [MIT License](LICENSE)，另见
  [NOTICE](NOTICE)。
