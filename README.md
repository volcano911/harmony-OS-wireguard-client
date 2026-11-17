# HarmonyOS WireGuard Client

面向 HarmonyOS NEXT（API 23，arm64）的 WireGuard 客户端。数据面完全跑在
C 里：Noise 握手、ChaCha20-Poly1305 加解密、重放窗口、TUN 读写、UDP 收发
都在同一个原生线程内完成，ArkTS 只负责配置、生命周期和 UI，一个数据包都
不会穿过 NAPI 边界。

当前版本：**1.3.2**（`com.lianhui.wireguard`，versionCode 1000302）

> [!IMPORTANT]
> 本项目是上游成果的继续开发，不是从零实现：
>
> - 原始作者 / 上游维护者：[wan0791](https://github.com/wan0791)
> - 原始项目：[wan0791/harmonyos-wg-client](https://github.com/wan0791/harmonyos-wg-client)
> - 本仓库的直接基线：[wumingkaiyuan/HarmonyOS-WireGuard-VPN-Client](https://github.com/wumingkaiyuan/HarmonyOS-WireGuard-VPN-Client)
>   （该仓库整理了 API 23 上的原生 TUN 读取、路由构造与 VpnExtension
>   生命周期适配）
>
> 本仓库在基线之上继续完成的工作主要是：把分散在 ArkTS 的握手/传输逻辑
> 整体下沉为 C 数据面、修复 NAT 回环（hairpin）场景下的 UDP 收包丢失、补齐
> 网络切换后的隧道自愈，并重写了配置管理与状态界面。上游的 ArkTS 密码学与
> 协议实现仍是本项目的知识来源，署名见 [NOTICE](NOTICE)。
> 全部代码以 MIT 协议发布，详见 [LICENSE](LICENSE)。

## 功能

| 功能 | 状态 | 说明 |
|---|---|---|
| WireGuard `.conf` 导入 | ✅ | 标准 `[Interface]` / `[Peer]` 段，`Address`/`DNS`/`AllowedIPs`/PSK 均支持 |
| 二维码扫描 | ✅ | 相机扫码导入，支持多份配置 |
| 多配置管理 | ✅ | 新增、重命名、删除、切换，持久化在 preferences |
| Noise IKpsk2 握手 | ✅ | X25519 + BLAKE2s + ChaCha20-Poly1305 + PSK |
| Transport 加解密 | ✅ | 含 64 位滑动重放窗口 |
| Keepalive / Rekey | ✅ | 25s 保活，120s 重协商，180s 判定会话死亡 |
| TUN ⇄ UDP 单线程数据面 | ✅ | 同一线程 `poll` 两个 fd，无跨线程队列 |
| 源地址重写与 checksum 修正 | ✅ | IPv4 + TCP/UDP/ICMP |
| AllowedIPs CIDR 分流 | ✅ | 转成 `RouteInfo[]`，字段完整才会真正生效 |
| 网络切换自愈 | ✅ | WiFi ⇄ 蜂窝切换后原地重启引擎，不重建 TUN |
| 实时速率与诊断 | ✅ | 上下行速率、握手次数、丢包、上次握手时间 |

## 版本 1.3.2 变更

### 修复：同域网关（NAT 回环）下握手永远收不到响应

这是本版本的核心修复。旧实现用的是 **connected UDP socket**
（`connect()` + `send()/recv()`）：

1. 端点填的是域名解析出的公网 IP。手机在家庭 WiFi 下时，这个公网 IP 就是
   自家路由器的 WAN 口；
2. 报文经 NAT 回环（hairpin）进入路由器上的 WireGuard 接口，服务端的回包
   **源地址是网关内网地址**，而不是手机拨出去的公网 IP；
3. connected socket 由内核按「对端地址」过滤，源地址不一致的包被直接丢弃，
   `recv()` 永远读不到；
4. 表现就是：服务端日志显示收到握手并已回包，客户端却每 5 秒重试一次，
   直到 18 次失败后报「握手超时」。切成蜂窝数据后源地址一致，于是又能连上。

现在改为 **unconnected socket + `sendto`/`recvfrom`**，并在**握手响应解密
通过之后**才把端点重钉到实际来源地址（endpoint roaming）。这样既不会被
hairpin 换源丢弃，也不会被伪造包劫持端点。

### 其他修复

- **网络切换自动恢复**：监听 `netAvailable` / `netLost` /
  `netConnectionPropertiesChange`，2 秒防抖后停引擎 → 重新解析域名 →
  `protectProcessNet()` → 复用原 TUN fd 重启，不重建 TUN、不动路由。
  出门忘关 VPN、回家自动连 WiFi 的场景不再需要手动重连。
- **保活时间戳误刷新**：`send_transport` 原来在判断发送结果之前就刷新
  `last_send_ms`，发送失败（例如切换网络后路由尚未收敛）时保活会误以为
  链路正常，空转到 180 秒才重建。现在只有发送成功才刷新。
- **「已连接」误报**：过去只要 VpnExtension 拉起成功，UI 就显示「已连接」，
  此时隧道往往还没握手。现在以握手成功为准，未完成握手显示「握手中」。
- **UI 状态机**：统计文件在引擎重建瞬间会短暂过期，旧逻辑会顺势停掉轮询、
  之后再也不刷新；UI 被系统回收重开后也认不出隧道仍在运行。均已修正。
- **电源键图形**：改用 Canvas 按实际尺寸现场计算几何，符号严格居中，直径
  占比从约 28% 提升到约 42%。

### 历史版本

| 版本 | 内容 |
|---|---|
| 1.3.0 | 数据面整体下沉到 C；修复 hairpin 丢包；修正「已连接」误报 |
| 1.3.1 | 增加网络切换自愈与 UI 状态恢复 |
| 1.3.2 | 保活时间戳修正、端点漫游加固，内部版本号与发布包对齐 |

## 架构

```text
┌─────────────────────────── ArkTS（UI 进程） ───────────────────────────┐
│  Index.ets          配置编辑 / 连接控制 / 速率与诊断展示                 │
│  ProfileStore.ets   多配置持久化（preferences）                         │
│  WgConfigParser.ets .conf 解析      QrDecoder.ets  二维码解码            │
└───────────────┬────────────────────────────────────────────────────────┘
                │ startVpnExtension(want, 配置 JSON)
┌───────────────▼──────────── ArkTS（VpnExtension 进程） ────────────────┐
│  WireGuardVpnExtAbility.ets                                            │
│    · VpnConnection.create() 建 TUN，构造完整 RouteInfo[]               │
│    · protectProcessNet() 防止自身流量被自己路由                        │
│    · connection.on(...) 监听网络变化，触发引擎原地重启                  │
│    · 周期性把统计写入 wg_stats.json 供 UI 读取                          │
└───────────────┬────────────────────────────────────────────────────────┘
                │ NAPI：传入配置，读回计数（无回调、无数据包）
┌───────────────▼────────────────── C 数据面 ────────────────────────────┐
│  wg/tunnel.c   单线程 poll(TUN, UDP) 主循环                            │
│  wg/noise.c    Noise IKpsk2 握手、会话密钥、Rekey                      │
│  wg/packet.c   IPv4 头解析、源地址重写、checksum 修正、重放窗口        │
│  wg/curve25519.c / blake2s.c / chacha20poly1305.c   密码学原语         │
└────────────────────────────────────────────────────────────────────────┘
```

### 为什么数据面放在 C

- **没有事件循环依赖**：ArkTS 侧轮询 TUN fd 会占满 VpnExtension 的 JS
  线程，UI 一卡隧道就抖。
- **零序列化**：包在 C 里从 TUN fd 直接进 AEAD，再 `sendto` 出去，不经过
  `ArrayBuffer` 往返和线程安全函数排队。
- **状态可解释**：所有计数器（收发包数、丢包、解密失败、握手次数、重放
  拒绝）都在 C 里累加，NAPI 只做读取。

### 会话定时器

| 定时器 | 间隔 | 行为 |
|---|---|---|
| Keepalive | 25 s | 无真实流量时发送空的 Transport 包，维持 NAT 映射 |
| Rekey | 120 s | 主动重握手，避开 180 s 硬上限 |
| Reject | 180 s | 超过此时长没有任何入包，判定会话死亡并重建 |
| 握手重试 | 5 s × 18 | 90 秒内对端无响应则上报超时 |

保活包不会刷新服务端的 `latest handshake`——它只是链路探测。因此服务端
`wg show` 里「上次握手」在 0–120 秒之间跳动是正常现象，不代表保活失效。

### UDP 收发模型

```text
socket(AF_INET, SOCK_DGRAM)      // 不 connect
  ├─ sendto(peer)                 // 首发指向配置里的 Endpoint
  └─ recvfrom(&src)               // 接受任意来源
       └─ 解密成功 && 是握手响应
            └─ 把 peer 重钉到 src  // endpoint roaming，此后只认这个地址
```

这样处理的两个约束：

- **不能**在收包前就按源地址过滤，否则 hairpin、双栈出口、运营商 NAT
  换源都会导致会话「单向可见」；
- **不能**无条件信任来源地址，否则任何人都能把端点劫持走。所以重钉点放在
  解密成功之后，伪造包过不了 AEAD。

## 目录结构

```text
.
├── AppScope/app.json5                     应用级配置（bundleName / 版本）
├── entry/src/main/
│   ├── cpp/
│   │   ├── CMakeLists.txt                 构建 wg_tunnel 动态库
│   │   ├── wg_napi.cpp                    NAPI 边界：start / stop / stats
│   │   └── wg/                            WireGuard 数据面（纯 C）
│   │       ├── tunnel.c                   主循环、定时器、收发
│   │       ├── noise.c / noise.h          Noise IKpsk2
│   │       ├── packet.c / packet.h        IPv4、源地址重写、checksum、重放窗口
│   │       ├── curve25519.c               X25519
│   │       ├── blake2s.c                  BLAKE2s（HMAC/HKDF/哈希）
│   │       └── chacha20poly1305.c         AEAD
│   ├── ets/
│   │   ├── pages/Index.ets                主界面（状态机、速率、诊断）
│   │   ├── pages/ScanPage.ets             扫码页
│   │   ├── utils/ProfileStore.ets         多配置持久化
│   │   ├── utils/WgConfigParser.ets       .conf 解析
│   │   └── vpnext/WireGuardVpnExtAbility.ets  VpnExtension 宿主
│   └── module.json5                       权限、ability、extension 声明
├── release/                               未签名发布包 + SHA256
├── scripts/build-official-unsigned.sh     命令行构建脚本
└── docs/harmonyos-wg-ffi-report.md        API 23 适配排查记录
```

## 构建

需要 HarmonyOS SDK **API 23** 与官方 command-line-tools。

```bash
export HARMONYOS_COMMANDLINE_HOME=/path/to/command-line-tools
./scripts/build-official-unsigned.sh
```

脚本会 `clean` 后重新构建，并校验：

- 产物里必须存在 `libs/arm64-v8a/libwg_tunnel.so`；
- 不能残留旧的 `libudp_socket.so`（历史中继实现）。

输出：`dist/harmonyos-wg-client-<version>-api23-arm64-debug-unsigned.hap`
与同名 `SHA256SUMS.txt`。

也可直接用 DevEco Studio 打开工程，配置好 SDK 后 `Build → Build Hap(s)`。
首次构建会由 `build-profile.template.json5` 生成 `build-profile.json5`；
后者含签名信息，已被 `.gitignore` 排除，不要提交。

## 签名与安装

`release/` 里的 HAP **是未签名的**，零售版 HarmonyOS 手机不会安装它
（`hdc install` 会直接报 `no signature file`）。两种用法：

1. **DevEco Studio 自动签名**（推荐）：打开工程 →
   `File → Project Structure → Signing Configs` → 勾选
   `Automatically generate signature`（需登录华为开发者账号）→
   用 IDE 直接 Run 到真机。
2. **导出签名后用 hdc 安装**：

```bash
hdc install -r your-signed.hap
```

签名材料（`.p12` / `.cer` / `.p7b` / 证书指纹）属于个人凭据，本仓库不包含，
也不接受 PR 提交。

## 使用

1. 首页「管理」→「导入 .conf 文件」或「扫描二维码」；
2. 选中配置后点中间电源键连接；
3. 状态从「握手中」变为「已连接」表示会话建立（以握手成功为准，而不是扩展
   拉起成功）；
4. 首页可展开查看上下行速率、握手次数、丢包、上次握手时间与运行日志。

配置样例（全部为占位符）：

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

## 排错

| 现象 | 优先排查 |
|---|---|
| 一直「握手中」，服务端能看到握手请求 | 同域网关 hairpin 换源；服务端是否回了 response；PSK 是否与 peer 一致 |
| 服务端 `latest handshake` 超过 25 秒没更新 | 正常，保活包不刷新握手时间；看 120 秒内是否 rekey |
| 显示「已连接」但网页打不开 | DNS 是否下发、AllowedIPs 是否覆盖目标网段、服务端 FORWARD/NAT |
| 切换 WiFi 后掉线 | 检查是否为 1.3.1 之前的版本；旧版没有网络监听 |
| `hdc install` 报 `no signature file` | HAP 未签名，见上一节 |

抓日志：

```bash
hdc shell hilog -x | grep -E "WgTunnel|WgVpnExt"
```

原生引擎的日志 tag 是 `WgTunnel`（domain `0xD001`）。

## 隐私与安全

- 仓库内**没有**任何真实服务器地址、域名、内网网段、设备序列号、私钥或
  PSK；示例一律使用占位符。
- 仓库内**没有**签名证书、Provision Profile 或已签名 HAP。
- 配置与密钥只保存在设备本地应用沙箱的 preferences 中，不上传、不同步；
  日志仅输出端点与统计，不打印密钥。
- `release/` 中的 HAP 未签名，装不上生产设备；请自行签名后再安装。

## 已知限制

- 仅处理 IPv4，未实现 IPv6 内外层与双栈端点。
- 单个 peer；不支持 AllowedIPs 之外的 peer 路由。
- 未实现 `PersistentKeepalive = 0`（关闭保活）的语义，固定 25 秒。
- 未做 UDP GRO/GSO，高带宽场景下吞吐受单线程 `poll` 限制。
- `protectProcessNet()` 的行为随系统版本有差异，不作为唯一自路由保护。
- 目标服务仍需监听对应端口，并由服务端防火墙与转发策略放行。

## 致谢与许可

- 原始作者 / 上游维护者：[wan0791](https://github.com/wan0791)，
  项目 [harmonyos-wg-client](https://github.com/wan0791/harmonyos-wg-client)；
- 直接基线：[wumingkaiyuan/HarmonyOS-WireGuard-VPN-Client](https://github.com/wumingkaiyuan/HarmonyOS-WireGuard-VPN-Client)；
- 上述作者与贡献者保留其各自代码与设计贡献。本仓库的改动是在其成果上继续
  完成，不主张对上游原始实现的重新署名。

以 [MIT License](LICENSE) 发布，署名与继续开发说明见 [NOTICE](NOTICE)。
