/**
 * WireGuard VPN Extension — 完整 WireGuard 隧道
 *
 * 工作流程：
 *   启动 → onCreate → onRequest → 创建 TUN →
 *   → 初始化密钥 → Noise IK 握手 → 数据包加解密转发
 *
 * UDP 中继模式：
 *   所有 UDP 包通过 127.0.0.1:RELAY_PORT 发送到 EntryAbility 的
 *   UdpRelay 中继，由中继转发到真实的 WG 服务器。这样绕过
 *   protectProcessNet() 在 API 23 上无效的问题（loopback 流量
 *   不被 VPN TUN 路由劫持）。
 */

import { VpnExtensionAbility, vpnExtension, connection } from '@kit.NetworkKit';
import { Want } from '@kit.AbilityKit';
import { socket } from '@kit.NetworkKit';
import { BusinessError } from '@kit.BasicServicesKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { NoiseHandshake, HandshakeState, readU32, writeU32, writeBytes } from '../wireguard/tunnel/Handshake';
import { stringToBytes } from '../wireguard/Constants';
import { chacha20Poly1305Encrypt, chacha20Poly1305Decrypt } from '../wireguard/crypto/ChaCha20Poly1305';
import { blake2s256 } from '../wireguard/crypto/Blake2s';
import { base64Decode, base64Encode } from '../wireguard/crypto/Base64';
import { x25519, x25519DH } from '../wireguard/crypto/X25519';
import { hkdf } from '../wireguard/crypto/HKDF';
import {
  NativeSocket,
  nativeWriteFd,
  startNativeTunReader,
  stopNativeTunReader,
} from '../utils/NativeSocketFFI';

const DOMAIN = 0x0000;
const TAG = 'WgVpnExt';

// ═══════════════════════════════════════
// 默认配置——正式使用时请通过 .conf 配置文件导入密钥
// ═══════════════════════════════════════
// 这些只是占位值，需要替换为你的 WireGuard 服务器配置
const TEST_CLIENT_PRIVATE_KEY = '';  // 从 .conf 的 [Interface] PrivateKey
const TEST_SERVER_PUBLIC_KEY  = '';  // 从 .conf 的 [Peer] PublicKey
const TEST_CLIENT_ADDRESS    = '10.0.0.2';
const TEST_DNS              = '1.1.1.1';

export default class WireGuardVpnExtAbility extends VpnExtensionAbility {
  private vpnConnection: vpnExtension.VpnConnection | null = null;
  private udpSocket: socket.UDPSocket | null = null;
  private nativeRelaySocket: NativeSocket | null = null;
  private wgServerHost: string = '';
  private wgServerPort: number = 0;
  private isRunning: boolean = false;
  private tunFd: number = -1;
  private handshake: NoiseHandshake | null = null;
  private relayPort: number = 0;
  private vpnExtPort: number = 0;
  private clientIp: string = '';  // VPN IP，用于 SNAT
  private pendingHandshake: NoiseHandshake | null = null;
  private tunForwardingStarted: boolean = false;
  private debugTransportRxPackets: number = 0;
  private tunPacketQueue: Uint8Array[] = [];
  private tunPacketProcessing: boolean = false;
  private tunPacketCount: number = 0;
  private tunPacketDrops: number = 0;
  private debugTransportTxPackets: number = 0;
  private nativeDirectRecvStarted: boolean = false;

  onCreate(want: Want): void {
    hilog.info(DOMAIN, TAG, 'VpnExtension onCreate');
  }

  async onRequest(want: Want, startId: number): Promise<void> {
    hilog.info(DOMAIN, TAG, 'VpnExtension onRequest, startId=%{public}d', startId);

    if (this.isRunning) {
      hilog.info(DOMAIN, TAG, 'Already running, skipping onRequest');
      return;
    }

    // 读取配置
    const serverHost: string       = (want.parameters?.['serverHost'] as string) ?? '';
    const serverIP: string         = (want.parameters?.['serverIP'] as string) ?? serverHost;
    const serverPort: number       = (want.parameters?.['serverPort'] as number) ?? 0;
    const clientAddress: string    = (want.parameters?.['clientAddress'] as string) ?? TEST_CLIENT_ADDRESS;
    const dnsServer: string        = (want.parameters?.['dnsServer'] as string) ?? TEST_DNS;
    const clientPrivateKeyB64: string | undefined = want.parameters?.['clientPrivateKey'] as string;
    const serverPublicKeyB64: string | undefined  = want.parameters?.['serverPublicKey'] as string;
    this.relayPort                 = (want.parameters?.['relayPort'] as number) ?? 0;
    this.vpnExtPort                = (want.parameters?.['vpnExtPort'] as number) ?? 0;
    const presharedKeyB64: string | undefined = want.parameters?.['presharedKey'] as string;

    if (!serverHost || serverPort < 1 || serverPort > 65535) {
      hilog.error(DOMAIN, TAG, 'Invalid config: host=%{public}s port=%{public}d', serverHost, serverPort);
      return;
    }
    if (this.relayPort < 1 || this.relayPort > 65535) {
      hilog.error(DOMAIN, TAG, 'Invalid relayPort=%{public}d', this.relayPort);
      return;
    }
    if (this.vpnExtPort < 1 || this.vpnExtPort > 65535) {
      hilog.error(DOMAIN, TAG, 'Invalid vpnExtPort=%{public}d', this.vpnExtPort);
      return;
    }

    hilog.info(DOMAIN, TAG, 'Server: %{public}s:%{public}d, Relay: 127.0.0.1:%{public}d, VpnExtPort: %{public}d',
      serverHost, serverPort, this.relayPort, this.vpnExtPort);

    // 读取 AllowedIPs
    const allowedIps: string =
      (want.parameters?.['allowedIps'] as string) ?? '0.0.0.0/0';

    // 启动 VPN 隧道（传递密钥参数）
    await this.setupVpn(serverHost, serverPort, clientAddress, dnsServer,
      clientPrivateKeyB64, serverPublicKeyB64, serverIP, presharedKeyB64, allowedIps);
  }

  onDestroy(): void {
    hilog.info(DOMAIN, TAG, 'VpnExtension onDestroy');
    this.cleanup();
  }

  // ═══════════════════════════════════════
  // VPN 设置
  // ═══════════════════════════════════════

  private async setupVpn(host: string, port: number, clientIp: string, dns: string,
    clientPrivKeyB64?: string, serverPubKeyB64?: string, serverIP?: string,
    presharedKeyB64?: string, allowedIps?: string): Promise<void> {
    this.clientIp = clientIp;
    try {
      this.vpnConnection = vpnExtension.createVpnConnection(this.context);

      // ═══ 关键：在 TUN 创建前保护进程 ═══
      // protectProcessNet() 保护"后续创建的所有 Socket"。
      // 在 TUN 创建前调用，确保后续 UDP Socket 的路由不受 TUN 影响。
      const vpnConn: vpnExtension.VpnConnection = this.vpnConnection;
      try {
        await vpnConn.protectProcessNet();
        hilog.info(DOMAIN, TAG, '✅ protectProcessNet before TUN');
      } catch (e) {
        hilog.error(DOMAIN, TAG, '❌ protectProcessNet before TUN 失败: %{public}s',
          JSON.stringify(e));
      }
      // 原生 WG socket 必须在创建 TUN 前建立，并留在不会被后台冻结的
      // VpnExtension 进程中。EntryAbility 切到浏览器后会被系统挂起。
      if (!this.nativeRelaySocket) {
        const nativeRelaySocket: NativeSocket = new NativeSocket();
        const nativeRelayFd: number = nativeRelaySocket.create();
        if (nativeRelayFd < 0) {
          throw new Error('Native WireGuard socket create failed');
        }
        this.nativeRelaySocket = nativeRelaySocket;
        hilog.info(DOMAIN, TAG,
          'Native WireGuard socket created before TUN, fd=%{public}d',
          nativeRelayFd);
      }

      // AllowedIPs 是按目的地址分流的系统路由，不是应用白名单。
      // 只有匹配配置中 CIDR 的目的地址会进入 WireGuard。
      const routes: connection.RouteInfo[] =
        this.buildRoutes(allowedIps || '0.0.0.0/0', clientIp);
      const config: vpnExtension.VpnConfig = {
        addresses: [{
          address: { address: clientIp, family: 1, port: 0 },
          prefixLength: 24,
        }],
        routes,
        mtu: 1420,
        dnsAddresses: [dns],
        isIPv4Accepted: true,
        isIPv6Accepted: false,
        // readSync 轮询必须配合非阻塞 TUN；否则队列一旦排空，
        // VPN 进程会阻塞在下一次读取，后续 HTTP 请求与 ACK 无法发送。
        isBlocking: false,
      };
      hilog.info(DOMAIN, TAG,
        'VpnConfig: %{public}d destination routes + all applications + nonblocking TUN',
        routes.length);

      this.tunFd = await this.vpnConnection.create(config);
      this.isRunning = true;
      hilog.info(DOMAIN, TAG, 'TUN created, fd=%{public}d', this.tunFd);

      // 启动 WireGuard（UDP Socket 在 TUN 创建前已被保护）
      await this.startWireGuard(host, port, clientPrivKeyB64, serverPubKeyB64, serverIP,
        presharedKeyB64);
    } catch (err) {
      hilog.error(DOMAIN, TAG, 'setupVpn error: %{public}s', JSON.stringify(err));
    }
  }

  // ═══════════════════════════════════════
  // WireGuard 握手 + 数据转发
  // ═══════════════════════════════════════

  private async startWireGuard(host: string, port: number,
    clientPrivKeyB64?: string, serverPubKeyB64?: string, serverIP?: string,
    presharedKeyB64?: string): Promise<void> {
    this.wgServerHost = serverIP || host;
    this.wgServerPort = port;

    // ArkTS UDP socket（绑定到 vpnExtPort 以接收中继转发的 Response）
    if (!this.udpSocket) {
      const relaySocket: socket.UDPSocket = socket.constructUDPSocketInstance();
      this.udpSocket = relaySocket;
      // 必须绑定到 vpnExtPort，中继会向 127.0.0.1:vpnExtPort 转发 Response
      await relaySocket.bind({ address: '127.0.0.1', port: this.vpnExtPort });
      // HarmonyOS 要求先 bind 才能设置底层 fd 参数。页面资源会并发产生
      // 大量 WG 数据报，扩大 loopback 接收缓冲可减少单段丢失。
      await relaySocket.setExtraOptions({
        receiveBufferSize: 4 * 1024 * 1024,
        sendBufferSize: 1024 * 1024,
        reuseAddress: true,
      });
      hilog.info(DOMAIN, TAG, 'UDP socket bound to 127.0.0.1:%{public}d', this.vpnExtPort);
    }
    if (!this.nativeRelaySocket) {
      const nativeRelaySocket: NativeSocket = new NativeSocket();
      const nativeRelayFd: number = nativeRelaySocket.create();
      if (nativeRelayFd < 0) {
        throw new Error('Native relay socket create failed');
      }
      this.nativeRelaySocket = nativeRelaySocket;
      hilog.info(DOMAIN, TAG,
        'Native WireGuard sender created, fd=%{public}d', nativeRelayFd);
    }
    if (!this.nativeDirectRecvStarted && this.nativeRelaySocket) {
      // startRecvThread 还会绑定一个备用的本地 relay 端口；实际出站直接
      // 使用同一个原生 fd 发往 WG 服务器，回包转发到 ArkTS 接收端口。
      const auxiliaryRelayPort: number = this.vpnExtPort + 2;
      const directRecvStarted: boolean = this.nativeRelaySocket.startRecvThread(
        auxiliaryRelayPort,
        this.vpnExtPort,
        this.wgServerHost,
        this.wgServerPort,
        (rxBytes: number, rxPackets: number, txBytes: number,
          txPackets: number, lastPacketLen: number, direction: number): void => {
          hilog.info(DOMAIN, TAG,
            'Native WG direct dir=%{public}d rx=%{public}d/%{public}d tx=%{public}d/%{public}d latest=%{public}d',
            direction, rxPackets, rxBytes, txPackets, txBytes, lastPacketLen);
        });
      this.nativeDirectRecvStarted = directRecvStarted;
      hilog.info(DOMAIN, TAG,
        'Native WG direct receive started=%{public}s',
        directRecvStarted ? 'true' : 'false');
    }

    // 3. 初始化握手密钥
    this.handshake = new NoiseHandshake();

    // 优先使用配置中传入的密钥，否则回退到测试密钥
    const localPrivB64: string  = clientPrivKeyB64 || TEST_CLIENT_PRIVATE_KEY;
    const remotePubB64: string  = serverPubKeyB64 || TEST_SERVER_PUBLIC_KEY;

    // 从私钥推导公钥（X25519: pub = priv * 9）
    const localPriv: Uint8Array = base64Decode(localPrivB64);
    const basePoint: bigint = 9n;
    const localPub: Uint8Array  = x25519(localPriv, basePoint);
    const remotePub: Uint8Array = base64Decode(remotePubB64);

    const derivedLocalPubB64: string = base64Encode(localPub);

    hilog.info(DOMAIN, TAG, 'Derived public: %{public}s', derivedLocalPubB64.substring(0, 16) + '...');
    hilog.info(DOMAIN, TAG, 'Remote pubkey: %{public}s', remotePubB64.substring(0, 16) + '...');

    this.handshake.init(localPriv, localPub, remotePub);

    // Noise_IKpsk2：混合 PresharedKey
    if (presharedKeyB64) {
      const pskBytes: Uint8Array = base64Decode(presharedKeyB64);
      this.handshake.setPresharedKey(pskBytes);
      hilog.info(DOMAIN, TAG, '🔑 PresharedKey 已设置');
    }

    hilog.info(DOMAIN, TAG, 'Handshake initialized with real keys');

    // UDP 连通性测试：通过本地中继发送测试包
    try {
      const testPkt: Uint8Array = stringToBytes('PING');
      this.sendRelayDatagram(testPkt);
      hilog.info(DOMAIN, TAG, '📡 UDP test packet sent via relay (127.0.0.1:%{public}d)', this.relayPort);
    } catch (sendErr) {
      hilog.error(DOMAIN, TAG, '❌ UDP test send failed: %{public}s', JSON.stringify(sendErr));
    }

    // BLAKE2s 自检：验证核心哈希实现
    const testData: Uint8Array = stringToBytes('abc');
    const testHash: Uint8Array = blake2s256(testData);
    const testHex: string = bytesToHex(testHash);
    hilog.info(DOMAIN, TAG, 'BLAKE2s self-test: blake2s("abc")=%{public}s', testHex);
    const b2Expected: string = '508c5e8c327c14e2e1a72ba34eeb452f';
    if (testHex.startsWith(b2Expected)) {
      hilog.info(DOMAIN, TAG, '✅ BLAKE2s 3B PASS');
    } else {
      hilog.info(DOMAIN, TAG, '❌ BLAKE2s 3B FAIL (expected %{public}s)', b2Expected);
    }

    // BLAKE2s 64 字节自检（恰好一个块）
    const b64Data: Uint8Array = new Uint8Array(64);
    for (let bi: number = 0; bi < 64; bi++) b64Data[bi] = bi;
    const b64Hash: Uint8Array = blake2s256(b64Data);
    const b64Hex: string = bytesToHex(b64Hash);
    const b64Expected: string = '56f34e8b96557e90c1f24b52d0c89d51086acf1b00f634cf1dde9233b8eaaa3e';
    hilog.info(DOMAIN, TAG, 'BLAKE2s 64B: %{public}s', b64Hex);
    hilog.info(DOMAIN, TAG, 'BLAKE2s 64B: %{public}s %{public}s',
      b64Hex === b64Expected ? '✅' : '❌', b64Hex === b64Expected ? 'PASS' : 'FAIL');

    // BLAKE2s 64 零字节自检
    const b64zData: Uint8Array = new Uint8Array(64);
    const b64zHash: Uint8Array = blake2s256(b64zData);
    const b64zHex: string = bytesToHex(b64zHash);
    const b64zExpected: string = 'ae09db7cd54f42b490ef09b6bc541af688e4959bb8c53f359a6f56e38ab454a3';
    hilog.info(DOMAIN, TAG, 'BLAKE2s 64x0: %{public}s', b64zHex);
    hilog.info(DOMAIN, TAG, 'BLAKE2s 64x0: %{public}s %{public}s',
      b64zHex === b64zExpected ? '✅' : '❌', b64zHex === b64zExpected ? 'PASS' : 'FAIL');

    // BLAKE2s 65 零字节自检
    const b65zData: Uint8Array = new Uint8Array(65);
    const b65zHash: Uint8Array = blake2s256(b65zData);
    const b65zHex: string = bytesToHex(b65zHash);
    const b65zExpected: string = '857328bf990b00922782d3e81c6054c25d3375d386c7424abe3e01d79041046c';
    hilog.info(DOMAIN, TAG, 'BLAKE2s 65x0: %{public}s', b65zHex);
    hilog.info(DOMAIN, TAG, 'BLAKE2s 65x0: %{public}s %{public}s',
      b65zHex === b65zExpected ? '✅' : '❌', b65zHex === b65zExpected ? 'PASS' : 'FAIL');

    // X25519 测试向量（RFC 7748 Section 6.1 DH）
    // 私钥: 0xa546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4
    // 公钥: 0xe6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c
    // 结果: 0xc3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552
    const xTestPriv: Uint8Array = hexToBytes('a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4');
    const xTestPub: Uint8Array = hexToBytes('e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c');
    const xResult: Uint8Array = x25519DH(xTestPriv, xTestPub);
    const xResultHex: string = bytesToHex(xResult);
    const xExpected: string = 'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552';
    hilog.info(DOMAIN, TAG, 'X25519 DH test: %{public}s', xResultHex);
    if (xResultHex === xExpected) {
      hilog.info(DOMAIN, TAG, '✅ X25519 DH PASS');
    } else {
      hilog.info(DOMAIN, TAG, '❌ X25519 DH FAIL (expected %{public}s)', xExpected);
    }

    // X25519 公钥推导测试（RFC 7748 Section 6.1 Alice）
    // 私钥: 77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a
    // x25519(priv, 9) = 8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a
    const alicePriv: Uint8Array = hexToBytes('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a');
    const alicePub: Uint8Array = x25519(alicePriv, 9n);
    const alicePubHex: string = bytesToHex(alicePub);
    const aliceExpected: string = '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a';
    hilog.info(DOMAIN, TAG, 'X25519 pubkey test: %{public}s', alicePubHex);
    if (alicePubHex === aliceExpected) {
      hilog.info(DOMAIN, TAG, '✅ X25519 pubkey PASS');
    } else {
      hilog.info(DOMAIN, TAG, '❌ X25519 pubkey FAIL (expected %{public}s)', aliceExpected);
    }

    // Base64 解码器硬编码测试：+FlkM+QogHuSbKY2HLxFYJIN2iEgfepAHUb4tHkFdYc= → f8596433e428807b...
    const testB64: string = '+FlkM+QogHuSbKY2HLxFYJIN2iEgfepAHUb4tHkFdYc=';
    const testDecoded: Uint8Array = base64Decode(testB64);
    const testHexStr: string = bytesToHex(testDecoded);
    const expectedHex: string = 'f8596433e428807b926ca6361cbc4560920dda21207dea401d46f8b479057587';
    hilog.info(DOMAIN, TAG, 'Base64 test decoded: %{public}s', testHexStr);
    hilog.info(DOMAIN, TAG, 'Base64 test: %{public}s',
      testHexStr === expectedHex ? '✅ Base64 PASS' : '❌ Base64 FAIL');

    // 验证私钥 Decode → Derive 是否匹配服务器期望的公钥
    const ourPrivKey = base64Decode(clientPrivKeyB64 || '');
    if (ourPrivKey.length === 32) {
      const ourPubKey = x25519(ourPrivKey, 9n);
      const ourPubB64 = base64Encode(ourPubKey);
      hilog.info(DOMAIN, TAG, 'Our pub B64: %{public}s', ourPubB64);
      const expectedPubB64 = 'f/djvIGyvngmpfmYwlwXhVmuT8S828S53G5RqDVkFhE=';
      if (ourPubB64 === expectedPubB64) {
        hilog.info(DOMAIN, TAG, '✅ Our pubKey matches wg pubkey!');
      } else {
        hilog.info(DOMAIN, TAG, '❌ PubKey MISMATCH (expected f/djv...)');
      }
    }

    // ChaCha20Poly1305 AEAD 测试（RFC 8439 Section 2.8.2）
    const aeadKey: Uint8Array = hexToBytes('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f');
    const aeadNonce: Uint8Array = hexToBytes('070000004041424344454647');
    const aeadPlain: Uint8Array = hexToBytes('4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e');
    const aeadAad: Uint8Array = hexToBytes('50515253c0c1c2c3c4c5c6c7');
    try {
      const aeadResult = chacha20Poly1305Encrypt(aeadKey, aeadNonce, aeadPlain, aeadAad);
      const ctHex: string = bytesToHex(aeadResult.ciphertext);
      const tagHex: string = bytesToHex(aeadResult.tag);
      const expectedCT: string = 'd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116';
      const expectedTag: string = '1ae10b594f09e26a7e902ecbd0600691';
      hilog.info(DOMAIN, TAG, 'ChaCha20 test CT match=%{public}s', (ctHex === expectedCT).toString());
      hilog.info(DOMAIN, TAG, 'ChaCha20 test tag match=%{public}s', (tagHex === expectedTag).toString());
      if (ctHex === expectedCT && tagHex === expectedTag) {
        hilog.info(DOMAIN, TAG, '✅ ChaCha20Poly1305 self-test PASS');
      } else {
        hilog.info(DOMAIN, TAG, '❌ ChaCha20 FAIL ct=%{public}s', ctHex.substring(0, 32));
      }
    } catch (e) {
      hilog.error(DOMAIN, TAG, 'ChaCha20 test error: %{public}s', JSON.stringify(e));
    }

    // 5. 启动接收循环
    if (this.udpSocket) {
      this.startReceiveLoop(this.udpSocket, host, port);
    }

    // 4. 构建并发送 Initiation 消息
    const initMsg: Uint8Array = this.handshake.buildInitiation();
    hilog.info(DOMAIN, TAG, 'Initiation msg built, len=%{public}d', initMsg.length);
    // 日志前 32 字节用于调试
    const initHex: string = bytesToHex(initMsg.subarray(0, 32));
    hilog.info(DOMAIN, TAG, 'Init header: %{public}s', initHex);
    // 日志 MAC1 前 8 字节
    const mac1Hex: string = bytesToHex(initMsg.subarray(initMsg.length - 32, initMsg.length - 16));
    hilog.info(DOMAIN, TAG, 'MAC1: %{public}s', mac1Hex);

    // 通过 loopback 发送到主进程 UdpRelay（主进程 NAPI socket 直连 WG）
    if (this.nativeRelaySocket) {
      this.sendRelayDatagram(initMsg);
      hilog.info(DOMAIN, TAG, 'Initiation sent to relay');
    }

    // 握手只发一次——重试会破坏 Noise 状态（rekey 定时器负责后续重握）
  }

  /** 启动接收循环（监听 relay 转发回来的 WG 服务器响应） */
  private startReceiveLoop(udpSocket: socket.UDPSocket, host: string, port: number): void {
    udpSocket.on('message', (info: socket.SocketMessageInfo): void => {
      const bytes: Uint8Array = new Uint8Array(info.message as ArrayBuffer);
      if (bytes.length < 4) return;
      const msgType: number = readU32(bytes, 0);

      if (msgType === 2 && this.handshake) {
        hilog.info(DOMAIN, TAG, '📩 Handshake Response! (%{public}d bytes)', bytes.length);
        const receiverIdx: number = bytes.length >= 12 ? readU32(bytes, 8) : 0;
        const responseHandshake: NoiseHandshake =
          this.pendingHandshake && receiverIdx === this.pendingHandshake.localIndex
            ? this.pendingHandshake
            : this.handshake;
        const ok: boolean = responseHandshake.processResponse(bytes);
        if (ok) {
          if (responseHandshake === this.pendingHandshake) {
            this.handshake = responseHandshake;
            this.pendingHandshake = null;
            if (this.rekeyTimeout >= 0) {
              clearTimeout(this.rekeyTimeout);
              this.rekeyTimeout = -1;
            }
            hilog.info(DOMAIN, TAG, '✅ WireGuard rekey completed');
          }
          hilog.info(DOMAIN, TAG, '✅ WireGuard 握手成功！');
          if (this.handshake && this.handshake.sessionKeys) {
            hilog.info(DOMAIN, TAG, '会话密钥已建立');
          }
          this.startTunForwarding();
        } else {
          hilog.error(DOMAIN, TAG, '❌ 握手处理失败');
        }
      } else if (msgType === 4) {
        this.processTransportData(bytes);
      } else if (msgType === 3) {
        hilog.info(DOMAIN, TAG, '🍪 Cookie reply (%{public}d bytes)', bytes.length);
      } else {
        hilog.info(DOMAIN, TAG, 'Unknown type=%{public}d', msgType);
      }
    });
  }

  // ═══════════════════════════════════════
  // Transport 数据转发
  // ═══════════════════════════════════════

  /** 处理收到的 Transport data（type=4），解密后写入 TUN */
  private processTransportData(data: Uint8Array): void {
    if (!this.handshake || !this.handshake.sessionKeys) return;
    if (data.length < 32) return;

    // 反重放保护: 读取 counter (LE u64) 并检查 replay window
    const recvCounter: number = readU32(data, 8) + readU32(data, 12) * 0x100000000;
    const expected: number = this.handshake.sessionKeys.recvCounter;
    if (recvCounter < expected && expected - recvCounter > 2000) {
      return; // 重放过期包，丢弃
    }

    const recvKey: Uint8Array = this.handshake.sessionKeys.recvKey;

    // WireGuard transport nonce: 4 zero bytes + LE64 counter.
    const nonce: Uint8Array = new Uint8Array(12);
    for (let i = 0; i < 8; i++) {
      nonce[4 + i] = data[8 + i];
    }

    const ciphertextWithTag: Uint8Array = data.subarray(16);
    const plainIP: Uint8Array | null = this.transportDecrypt(recvKey, nonce, ciphertextWithTag);
    if (plainIP && plainIP.length > 0 && this.tunFd >= 0) {
      try {
        const written: number = this.writeTunPacket(plainIP);
        this.debugTransportRxPackets++;
        if (this.debugTransportRxPackets <= 200) {
          hilog.info(DOMAIN, TAG,
            'WG packet #%{public}d counter=%{public}d encrypted=%{public}d ip=%{public}d tunWrite=%{public}d',
            this.debugTransportRxPackets, recvCounter, data.length, plainIP.length, written);
        }
        if (recvCounter >= expected) {
          this.handshake.sessionKeys.recvCounter = recvCounter + 1;
        }
        this.transportRxBytes += plainIP.length;
        if (this.handshake.sessionKeys.recvCounter % 100 === 1) {
          hilog.info(DOMAIN, TAG, '📥 WG→TUN: %{public}d bytes, totalRx=%{public}d',
            plainIP.length, this.transportRxBytes);
        }
      } catch (e) {
        hilog.error(DOMAIN, TAG, 'TUN write failed: %{public}s', JSON.stringify(e));
      }
    } else if (plainIP === null) {
      hilog.error(DOMAIN, TAG, 'Transport decrypt FAILED');
    }
  }

  /** Transport 专用的 AEAD 解密（使用 12 字节 nonce） */
  private transportDecrypt(key: Uint8Array, nonce: Uint8Array, ciphertextWithTag: Uint8Array): Uint8Array | null {
    try {
      return chacha20Poly1305Decrypt(key, nonce, ciphertextWithTag, new Uint8Array(0));
    } catch (e) {
      return null;
    }
  }

  /** Transport 专用的 AEAD 加密 */
  private transportEncrypt(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array): Uint8Array {
    const result = chacha20Poly1305Encrypt(key, nonce, plaintext, new Uint8Array(0));
    const out: Uint8Array = new Uint8Array(result.ciphertext.length + result.tag.length);
    out.set(result.ciphertext);
    out.set(result.tag, result.ciphertext.length);
    return out;
  }

  /** 在 VPN 扩展进程内直接发往 WG 服务端，避免后台主进程被冻结。 */
  private sendRelayDatagram(packet: Uint8Array): number {
    if (!this.nativeRelaySocket || packet.length === 0 ||
      !this.wgServerHost || this.wgServerPort <= 0) return -1;
    const packetCopy: Uint8Array = new Uint8Array(packet.length);
    packetCopy.set(packet);
    const sent: number = this.nativeRelaySocket.sendTo(
      packetCopy.buffer as ArrayBuffer, this.wgServerHost, this.wgServerPort);
    if (sent !== packet.length) {
      hilog.error(DOMAIN, TAG,
        'Native relay short send: %{public}d/%{public}d', sent, packet.length);
    }
    return sent;
  }

  /** SNAT：将 TUN 包的源 IP 改写为 VPN IP，同时修正 IP 和 TCP/UDP checksum */
  private snatPacket(ipPacket: Uint8Array): void {
    if (ipPacket.length < 20 || !this.clientIp) return;
    const versionIhl: number = ipPacket[0];
    if ((versionIhl >> 4) !== 4) return;

    const parts: string[] = this.clientIp.split('.');
    if (parts.length !== 4) return;
    const newIp: number[] = parts.map((s: string): number => parseInt(s));

    // 保存旧源 IP（offset 12-15）
    const oldA: number = (ipPacket[12] << 8) + ipPacket[13];
    const oldB: number = (ipPacket[14] << 8) + ipPacket[15];
    const newA: number = (newIp[0] << 8) + newIp[1];
    const newB: number = (newIp[2] << 8) + newIp[3];

    // TUN 通常已经使用 VPN 地址作为源地址。此时不要重复改写或触碰校验和。
    if (oldA === newA && oldB === newB) return;

    // 改源 IP
    ipPacket[12] = newIp[0];
    ipPacket[13] = newIp[1];
    ipPacket[14] = newIp[2];
    ipPacket[15] = newIp[3];

    // 重算 IPv4 header checksum（offset 10-11，增量更新更快但重算更安全）
    ipPacket[10] = 0;
    ipPacket[11] = 0;
    const ihl: number = versionIhl & 0x0F;
    const headerLen: number = ihl * 4;
    let sum: number = 0;
    for (let i: number = 0; i < headerLen; i += 2) {
      sum += (ipPacket[i] << 8) + ipPacket[i + 1];
    }
    while (sum > 0xFFFF) sum = (sum & 0xFFFF) + (sum >>> 16);
    const csum: number = (~sum) & 0xFFFF;
    ipPacket[10] = (csum >> 8) & 0xFF;
    ipPacket[11] = csum & 0xFF;

    // 从头重算 TCP/UDP checksum，包含 IPv4 伪首部。
    const protocol: number = ipPacket[9];
    if (protocol !== 6 && protocol !== 17) return; // 仅 TCP/UDP
    const frag: number = (ipPacket[6] << 8) + ipPacket[7];
    if ((frag & 0x3FFF) !== 0) return;  // 非首分片，无传输头
    const transportOff: number = ihl * 4;
    const totalLength: number = (ipPacket[2] << 8) + ipPacket[3];
    const packetLength: number = Math.min(totalLength, ipPacket.length);
    const transportLength: number = packetLength - transportOff;
    const checksumOffset: number = protocol === 6 ? 16 : 6;
    if (transportLength <= checksumOffset + 1) return;

    ipPacket[transportOff + checksumOffset] = 0;
    ipPacket[transportOff + checksumOffset + 1] = 0;

    const dstA: number = (ipPacket[16] << 8) + ipPacket[17];
    const dstB: number = (ipPacket[18] << 8) + ipPacket[19];
    let transportSum: number =
      newA + newB + dstA + dstB + protocol + transportLength;
    for (let i: number = 0; i < transportLength; i += 2) {
      const high: number = ipPacket[transportOff + i];
      const low: number =
        i + 1 < transportLength ? ipPacket[transportOff + i + 1] : 0;
      transportSum += (high << 8) + low;
    }
    while (transportSum > 0xFFFF) {
      transportSum = (transportSum & 0xFFFF) + (transportSum >>> 16);
    }
    let transportChecksum: number = (~transportSum) & 0xFFFF;
    // IPv4 UDP 中 0 表示“未启用校验”，计算结果为 0 时应编码为 0xFFFF。
    if (protocol === 17 && transportChecksum === 0) transportChecksum = 0xFFFF;
    ipPacket[transportOff + checksumOffset] = (transportChecksum >> 8) & 0xFF;
    ipPacket[transportOff + checksumOffset + 1] = transportChecksum & 0xFF;
  }

  /** 发送 Transport 消息到 WG 服务器 */
  private async sendTransportPacket(ipPacket: Uint8Array): Promise<void> {
    if (!this.handshake || !this.handshake.sessionKeys || !this.nativeRelaySocket) return;

    // SNAT: 重写源 IP 为 VPN IP，确保 WG 服务器 AllowedIPs 匹配
    this.snatPacket(ipPacket);

    const keys = this.handshake.sessionKeys;
    const counter: number = keys.sendCounter;
    keys.sendCounter++;

    // WireGuard transport nonce: 4 zero bytes + LE64 counter.
    const nonce: Uint8Array = new Uint8Array(12);
    writeU64LE(nonce, 4, BigInt(counter));

    const encrypted: Uint8Array = this.transportEncrypt(keys.sendKey, nonce, ipPacket);

    // Build transport message: type(4) + receiver(4) + counter(8) + encrypted
    const msg: Uint8Array = new Uint8Array(16 + encrypted.length);
    let off: number = 0;
    off = writeU32(msg, off, 4); // type = transport
    off = writeU32(msg, off, this.handshake.remoteIndex); // receiver index
    off = writeU64LE(msg, off, BigInt(counter));
    off = writeBytes(msg, off, encrypted);

    try {
      const sent: number = this.sendRelayDatagram(msg);
      this.debugTransportTxPackets++;
      if (this.debugTransportTxPackets <= 200) {
        hilog.info(DOMAIN, TAG,
          'Transport native send #%{public}d counter=%{public}d ip=%{public}d wg=%{public}d sent=%{public}d',
          this.debugTransportTxPackets, counter, ipPacket.length, msg.length, sent);
      }
    } catch (e) {
      hilog.error(DOMAIN, TAG, 'Transport send error: %{public}s', JSON.stringify(e));
    }
  }

  private keepaliveTimer: number = -1;
  private rekeyTimer: number = -1;
  private rekeyTimeout: number = -1;
  private transportRxBytes: number = 0;
  private transportTxBytes: number = 0;

  private sleepMs(ms: number): Promise<void> {
    return new Promise<void>(resolve => setTimeout(resolve, ms));
  }

  /** 从 TUN 读取 IP 包并加密发送 */
  private startTunForwarding(): void {
    if (this.tunFd < 0) {
      hilog.error(DOMAIN, TAG, 'TUN fd invalid, cannot forward');
      return;
    }
    if (this.tunForwardingStarted) {
      hilog.info(DOMAIN, TAG, 'TUN forwarding continues with refreshed session keys');
      return;
    }
    this.tunForwardingStarted = true;
    hilog.info(DOMAIN, TAG, 'TUN forwarding started, fd=%{public}d', this.tunFd);

    // Keepalive: 每 10 秒发送空 transport 包维持 NAT 绑定
    this.keepaliveTimer = setInterval((): void => {
      if (this.isRunning && this.handshake?.sessionKeys) {
        this.sendKeepalive();
      }
    }, 10000);

    // WireGuard initiator 应在会话过期前重新握手。旧会话保留到新握手成功，
    // 因此 TUN 和现有 TCP 连接不需要重建。
    this.rekeyTimer = setInterval((): void => {
      if (this.isRunning && this.handshake?.sessionKeys) {
        this.doRekey();
      }
    }, 100000);

    // 与华为官方 API 23 VPN 示例一致：TUN fd 由 C++ 专用线程读取。
    // 避免 JS 定时器直接轮询非阻塞 fd 时持续遇到 EAGAIN。
    try {
      const nativeStarted: boolean = startNativeTunReader(this.tunFd,
        (data: ArrayBuffer | null, event: number, fdFlags: number,
          revents: number, errorNo: number, pollCount: number): void => {
          this.onNativeTunRead(data, event, fdFlags, revents, errorNo, pollCount);
        });
      hilog.info(DOMAIN, TAG,
        'Native TUN reader started=%{public}s', nativeStarted ? 'true' : 'false');
    } catch (e) {
      hilog.error(DOMAIN, TAG, 'Native TUN reader start failed: %{public}s',
        JSON.stringify(e));
    }
  }

  /**
   * 将标准 WireGuard AllowedIPs 转为 HarmonyOS VPN 路由。
   * 当前客户端只处理 IPv4；无效项会被忽略。
   */
  private buildRoutes(allowedIps: string, clientIp: string): connection.RouteInfo[] {
    const routes: connection.RouteInfo[] = [];
    const entries: string[] = allowedIps.split(',');
    for (const raw of entries) {
      const cidr: string = raw.trim();
      if (!cidr || cidr.includes(':')) continue;
      const parts: string[] = cidr.split('/');
      const address: string = parts[0]?.trim() || '';
      const prefixLength: number = parts.length > 1 ? parseInt(parts[1]) : 32;
      if (!this.isValidIpv4(address) || isNaN(prefixLength) ||
        prefixLength < 0 || prefixLength > 32) {
        hilog.warn(DOMAIN, TAG, 'Ignoring invalid AllowedIP route');
        continue;
      }
      routes.push({
        // Match Huawei's API 23 VPN sample exactly: routes use the local TUN
        // address as gateway and set both route flags. Previous builds used a
        // 0.0.0.0 gateway with hasGateway/isDefaultRoute false.
        interface: 'vpn-tun',
        destination: {
          address: { address, family: 1, port: 0 },
          prefixLength,
        },
        gateway: { address: clientIp, family: 1, port: 0 },
        hasGateway: true,
        isDefaultRoute: true,
        isExcludedRoute: false,
      });
    }
    return routes;
  }

  private isValidIpv4(value: string): boolean {
    const octets: string[] = value.split('.');
    if (octets.length !== 4) return false;
    for (const octet of octets) {
      if (octet === '' || !/^\d+$/.test(octet)) return false;
      const numberValue: number = parseInt(octet);
      if (numberValue < 0 || numberValue > 255) return false;
    }
    return true;
  }

  /** 发送 keepalive 空包 */
  private async sendKeepalive(): Promise<void> {
    if (!this.handshake?.sessionKeys || !this.nativeRelaySocket) return;
    const keys = this.handshake.sessionKeys;
    try {
      const counter: number = keys.sendCounter;
      keys.sendCounter++;
      const nonce: Uint8Array = new Uint8Array(12);
      writeU64LE(nonce, 4, BigInt(counter));
      const encrypted: Uint8Array = this.transportEncrypt(keys.sendKey, nonce, new Uint8Array(0));
      const msg: Uint8Array = new Uint8Array(16 + encrypted.length);
      let off: number = 0;
      off = writeU32(msg, off, 4);
      off = writeU32(msg, off, this.handshake.remoteIndex);
      off = writeU64LE(msg, off, BigInt(counter));
      off = writeBytes(msg, off, encrypted);
      this.sendRelayDatagram(msg);
    } catch (e) {
      // ignore
    }
  }

  /** 触发无缝 rekey：新握手成功前继续使用现有会话密钥。 */
  private async doRekey(): Promise<void> {
    if (!this.handshake || !this.nativeRelaySocket) return;
    if (this.pendingHandshake) return;
    const activeHandshake: NoiseHandshake = this.handshake;
    const nextHandshake: NoiseHandshake = new NoiseHandshake();
    try {
      nextHandshake.init(
        activeHandshake.localStaticPrivate,
        activeHandshake.localStaticPublic,
        activeHandshake.remoteStaticPublic);
      nextHandshake.setPresharedKey(activeHandshake.presharedKey);
      const initMsg: Uint8Array = nextHandshake.buildInitiation();
      this.pendingHandshake = nextHandshake;
      this.sendRelayDatagram(initMsg);
      hilog.info(DOMAIN, TAG, 'Rekey sent');
      this.rekeyTimeout = setTimeout((): void => {
        if (this.pendingHandshake === nextHandshake) {
          this.pendingHandshake = null;
          hilog.warn(DOMAIN, TAG, 'Rekey response timeout; keeping active session');
        }
        this.rekeyTimeout = -1;
      }, 10000);
    } catch (e) {
      if (this.pendingHandshake === nextHandshake) this.pendingHandshake = null;
      hilog.error(DOMAIN, TAG, 'Rekey failed');
    }
  }

  private onNativeTunRead(data: ArrayBuffer | null, event: number,
    fdFlags: number, revents: number, errorNo: number, pollCount: number): void {
    if (event === 0) {
      hilog.info(DOMAIN, TAG,
        'Native TUN thread active: flags=%{public}d poll=%{public}d',
        fdFlags, pollCount);
      return;
    }
    if (event === 2) {
      hilog.info(DOMAIN, TAG,
        'Native TUN poll timeout: flags=%{public}d poll=%{public}d',
        fdFlags, pollCount);
      return;
    }
    if (event === 3 || event === 4 || event === 5) {
      hilog.warn(DOMAIN, TAG,
        'Native TUN event=%{public}d flags=%{public}d revents=%{public}d errno=%{public}d poll=%{public}d',
        event, fdFlags, revents, errorNo, pollCount);
      return;
    }
    if (event !== 1 || !data || !this.isRunning) return;

    if (this.tunPacketQueue.length >= 256) {
      this.tunPacketDrops++;
      if (this.tunPacketDrops <= 10 || this.tunPacketDrops % 100 === 0) {
        hilog.warn(DOMAIN, TAG,
          'Native TUN queue full, drops=%{public}d', this.tunPacketDrops);
      }
      return;
    }
    this.tunPacketQueue.push(new Uint8Array(data));
    this.processTunPacketQueue();
  }

  private async processTunPacketQueue(): Promise<void> {
    if (this.tunPacketProcessing) return;
    this.tunPacketProcessing = true;
    try {
      while (this.isRunning && this.tunPacketQueue.length > 0) {
        const ipPacket: Uint8Array | undefined = this.tunPacketQueue.shift();
        if (!ipPacket || ipPacket.length < 20) continue;

        // 丢弃非 IPv4 包（IPv6 源 IP 为 ::，WG 服务器 AllowedIPs 不匹配）
        const version: number = ipPacket[0] >> 4;
        if (version !== 4) continue;

        this.tunPacketCount++;
        if (this.tunPacketCount <= 200 || this.tunPacketCount % 100 === 1) {
          hilog.info(DOMAIN, TAG,
            '📤 TUN→WG native-thread #%{public}d: %{public}d bytes, totalTx=%{public}d',
            this.tunPacketCount, ipPacket.length, this.transportTxBytes);
        }
        this.transportTxBytes += ipPacket.length;
        await this.sendTransportPacket(ipPacket);
      }
    } finally {
      this.tunPacketProcessing = false;
    }
  }

  /** 同步写入，保持解密后的 IP 包顺序且避免异步写队列淹没 TUN。 */
  private writeTunPacket(ipPacket: Uint8Array): number {
    if (this.tunFd < 0 || ipPacket.length === 0) return 0;
    try {
      // 解密结果可能是更大 ArrayBuffer 的视图；只写当前 IP 包的有效区间。
      const packetCopy: Uint8Array = new Uint8Array(ipPacket.length);
      packetCopy.set(ipPacket);
      return nativeWriteFd(this.tunFd, packetCopy.buffer as ArrayBuffer);
    } catch (e) {
      hilog.error(DOMAIN, TAG, 'writeTunPacket error: %{public}s', JSON.stringify(e));
      return 0;
    }
  }

  // ═══════════════════════════════════════
  // 清理
  // ═══════════════════════════════════════

  private cleanup(): void {
    this.isRunning = false;
    try { stopNativeTunReader(); } catch (e) { /* ignore */ }
    this.tunPacketQueue = [];
    this.tunPacketProcessing = false;
    if (this.keepaliveTimer >= 0) { clearInterval(this.keepaliveTimer); this.keepaliveTimer = -1; }
    if (this.rekeyTimer >= 0) { clearInterval(this.rekeyTimer); this.rekeyTimer = -1; }
    if (this.rekeyTimeout >= 0) { clearTimeout(this.rekeyTimeout); this.rekeyTimeout = -1; }
    if (this.udpSocket) {
      try { this.udpSocket.close(); } catch (e) { /* ignore */ }
      this.udpSocket = null;
    }
    if (this.nativeRelaySocket) {
      try { this.nativeRelaySocket.close(); } catch (e) { /* ignore */ }
      this.nativeRelaySocket = null;
    }
    this.nativeDirectRecvStarted = false;
    if (this.vpnConnection) {
      try { this.vpnConnection.destroy(); } catch (e) { /* ignore */ }
      this.vpnConnection = null;
    }
    this.tunFd = -1;
    this.handshake = null;
    this.pendingHandshake = null;
    this.tunForwardingStarted = false;
    hilog.info(DOMAIN, TAG, 'Cleanup complete');
  }
}

// ── 工具 ──
function writeU64LE(buf: Uint8Array, off: number, val: bigint): number {
  for (let i = 0; i < 8; i++) {
    buf[off + i] = Number((val >> BigInt(i * 8)) & 0xFFn);
  }
  return off + 8;
}

function bytesToHex(bytes: Uint8Array): string {
  const hex: string = '0123456789abcdef';
  let result: string = '';
  for (let i = 0; i < bytes.length; i++) {
    result += hex[(bytes[i] >> 4) & 0xF] + hex[bytes[i] & 0xF];
  }
  return result;
}

function hexToBytes(hex: string): Uint8Array {
  const bytes: Uint8Array = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
