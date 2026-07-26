# HarmonyOS API 23 WireGuard 原生 TUN 适配说明

本文整理 HarmonyOS 6.1 / API 23 上第三方 WireGuard 客户端的数据面适配
思路。原作者/上游维护者为 [wan0791](https://github.com/wan0791)，本文及
配套实现基于其
[harmonyos-wg-client](https://github.com/wan0791/harmonyos-wg-client)
项目继续开发，不包含任何真实服务器、内网、设备或签名信息。

## 1. 问题边界

WireGuard 握手成功并不代表应用流量已经进入隧道。排查时应分层验证：

1. Noise 握手与会话密钥。
2. WireGuard Transport 加解密。
3. HarmonyOS 目标路由是否将应用数据送入 TUN。
4. 客户端能否及时读取 TUN fd。
5. SNAT、checksum、服务端 FORWARD/NAT 和目标端口。
6. 页面资源、缓存或业务重定向等应用层问题。

本次适配确认 WireGuard 协议层可工作，主要问题集中在 TUN 路由、fd 读取
方式以及 VpnExtension 的生命周期。

## 2. 将 AllowedIPs 转成 RouteInfo

WireGuard `AllowedIPs` 表示按目的 CIDR 选择隧道。客户端解析逗号分隔的
IPv4 CIDR，并为每项构造 `connection.RouteInfo`：

```ts
const route: connection.RouteInfo = {
  interface: 'vpn-tun',
  destination: {
    address: {
      address: networkAddress,
      family: 1,
      port: 0
    },
    prefixLength
  },
  gateway: {
    address: tunnelAddress,
    family: 1,
    port: 0
  },
  hasGateway: true,
  isDefaultRoute: true,
  isExcludedRoute: false
};
```

然后把所有 route 放入 `VpnConfig.routes`。不配置
`trustedApplications` 时，各应用按照目的地址与 CIDR 的匹配结果决定是否
进入 VPN。

需要注意：`VpnConnection.create()` 成功只表示 TUN 创建成功，不能单独
证明 route 已生效。必须再观察 TUN 包、服务端抓包或真实 TCP 连接。

## 3. 使用 C++ poll/read 读取 TUN

`VpnConnection.create()` 返回 TUN fd。对非阻塞 fd 直接读取，在没有数据
时返回 `EAGAIN` 属于 POSIX 正常语义；但 ArkTS 定时器轮询难以同时兼顾
就绪等待、后台生命周期和数据包顺序。

当前实现将读取移动到 C++ 独立线程：

```cpp
while (running) {
    pollfd pfd{tunFd, POLLIN, 0};
    int ready = poll(&pfd, 1, timeoutMs);
    if (ready <= 0 || !(pfd.revents & POLLIN)) {
        continue;
    }

    while (running) {
        ssize_t size = read(tunFd, buffer, sizeof(buffer));
        if (size > 0) {
            queuePacketToArkTS(buffer, size);
            continue;
        }
        if (size < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;
        }
        handleReadError();
        break;
    }
}
```

使用 `napi_threadsafe_function` 把每个完整 IP 包交给 ArkTS。ArkTS 侧使用
单消费者顺序队列完成 SNAT、加密和 UDP 发送，避免异步回调并发执行导致
TCP 包乱序。

解密后的回包使用原生 `write(tunFd, packet, length)` 写回 TUN。

## 4. 原生 UDP 数据面

WireGuard UDP Socket 在创建 TUN 前建立，避免外层 WireGuard 数据报被新建
路由重新送回 TUN。

数据发送使用原生 `sendto()`；接收使用 C++ 线程和 `recvfrom()`。握手、
Transport、Keepalive、Rekey 和 TUN 转发全部驻留在 VpnExtension 数据面，
不依赖主界面保持前台。

```text
VpnExtension
  ├─ TUN poll/read thread
  ├─ ArkTS WireGuard state machine
  ├─ native UDP sendto/recvfrom
  └─ TUN write-back

UIAbility
  └─ configuration, start/stop and diagnostics only
```

## 5. 数据包处理

出站：

1. 从 TUN 取得完整 IPv4 包。
2. 将源地址改写为 WireGuard Interface 地址。
3. 重算 IPv4 与 TCP/UDP checksum。
4. 使用当前 WireGuard 会话密钥封装 Transport Data。
5. 原生 UDP Socket 发送到配置中的 Endpoint。

入站：

1. 校验 WireGuard receiver index 和 replay window。
2. 解密 Transport Data。
3. 对返回包执行反向地址改写。
4. 重算 checksum。
5. 写回 TUN。

## 6. 验证方法

建议使用不包含真实地址的测试记录，至少确认：

| 层级 | 验证信号 |
|---|---|
| WireGuard | 握手成功，Transfer 计数增长 |
| Route | 访问 `<PRIVATE_CIDR>` 时 TUN 收到 SYN |
| Transport | 服务端能解密客户端 IP 包 |
| TCP | SYN、SYN-ACK、ACK 完整 |
| HTTP | 请求和响应均通过隧道 |
| Split tunnel | 非 `AllowedIPs` 目的地址保持原网络 |
| Lifecycle | UI 切后台后隧道继续转发 |

“VPN 已连接”、能 ping 或看到握手都不能替代真实业务端口验证。



## 8. 上游归属

本适配基于
[wan0791/harmonyos-wg-client](https://github.com/wan0791/harmonyos-wg-client)。
原作者/上游维护者为 [wan0791](https://github.com/wan0791)。
原始 WireGuard/HarmonyOS 实现与历史贡献归上游作者及贡献者所有；API 23
原生 TUN 和路由适配是在该成果上继续完成的工作，不改变上游成果的归属。
