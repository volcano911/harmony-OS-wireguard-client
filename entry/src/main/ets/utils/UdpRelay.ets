/**
 * UDP 中继 — 绕过 VpnExtensionAbility 的 TUN 路由劫持
 *
 * 消息类型路由：
 *   类型 1 (Initiation)  → VpnExt → 中继 → WG 服务器
 *   类型 4 (Transport)   → VpnExt → 中继 → WG 服务器
 *   类型 2 (Response)    → WG 服务器 → 中继 → VpnExt (127.0.0.1:vpnExtPort)
 *   类型 3 (Cookie Reply) → WG 服务器 → 中继 → VpnExt (127.0.0.1:vpnExtPort)
 */

import { socket } from '@kit.NetworkKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { NativeSocket } from './NativeSocketFFI';
import { readU32 } from '../wireguard/tunnel/Handshake';
import { stringToBytes } from '../wireguard/Constants';

const DOMAIN = 0x0000;
const TAG = 'UdpRelay';

const MSG_TYPE_INITIATION: number = 1;
const MSG_TYPE_RESPONSE: number = 2;
const MSG_TYPE_COOKIE_REPLY: number = 3;
const MSG_TYPE_TRANSPORT: number = 4;

let instance: UdpRelay | null = null;

export function getRelay(): UdpRelay {
  if (!instance) {
    instance = new UdpRelay();
  }
  return instance;
}

export class UdpRelay {
  private sock: socket.UDPSocket | null = null;
  private nativeSock: NativeSocket | null = null;  // NAPI 原生 socket（主进程不受 TUN 影响）
  private remoteHost: string = '';
  private remotePort: number = 0;
  private relayPort: number = 0;
  private vpnExtPort: number = 0;
  private running: boolean = false;
  // 统计
  txBytes: number = 0;
  rxBytes: number = 0;
  private relayTxPackets: number = 0;
  private relayRxPackets: number = 0;

  /** 设置 NAPI 原生 socket（主进程不受 TUN 影响） */
  setNativeSocket(ns: NativeSocket): void {
    this.nativeSock = ns;
  }

  /** 启动中继 */
  async start(remoteHost: string, remotePort: number,
    relayPort: number, vpnExtPort: number): Promise<void> {
    if (this.running) return;
    this.remoteHost = remoteHost;
    this.remotePort = remotePort;
    this.relayPort = relayPort;
    this.vpnExtPort = vpnExtPort;

    // 数据端口由 NAPI C 线程绑定并双向转发，ArkTS 不再逐包接收。
    this.running = true;
    hilog.info(DOMAIN, TAG, 'C 双向中继已配置 relay=%{public}d vpnExt=%{public}d',
      this.relayPort, this.vpnExtPort);
  }

  getPort(): number {
    return this.relayPort;
  }

  async stop(): Promise<void> {
    this.running = false;
    if (this.nativeSock) {
      this.nativeSock.stopRecvThread();
    }
    if (this.sock) {
      try { this.sock.off('message'); await this.sock.close(); } catch (e) { }
      this.sock = null;
    }
    hilog.info(DOMAIN, TAG, '中继已停止');
  }

  // ── 内部 ──

  private onMessage(info: socket.SocketMessageInfo): void {
    if (!this.running || !this.sock) {
      hilog.warn(DOMAIN, TAG, 'onMessage: 中继未运行');
      return;
    }

    const bytes: Uint8Array = new Uint8Array(info.message);
    if (bytes.length < 4) {
      hilog.warn(DOMAIN, TAG, 'onMessage: 数据过短');
      return;
    }
    const msgType: number = readU32(bytes, 0);

    if (msgType === MSG_TYPE_INITIATION) {
      hilog.info(DOMAIN, TAG, '→ 类型1 Initiation, 转发到服务器');
      this.forwardToServer(bytes);
    } else if (msgType === MSG_TYPE_TRANSPORT) {
      this.relayTxPackets++;
      const sent: number = this.forwardToServer(bytes);
      if (this.relayTxPackets <= 200 || this.relayTxPackets % 100 === 1) {
        hilog.info(DOMAIN, TAG,
          'Transport tx #%{public}d wgLen=%{public}d nativeSent=%{public}d',
          this.relayTxPackets, bytes.length, sent);
      }
    } else if (msgType === MSG_TYPE_RESPONSE) {
      hilog.info(DOMAIN, TAG, '→ 类型2 Response, 转发回 VpnExt');
      this.forwardToVpnExt(bytes);
    } else if (msgType === MSG_TYPE_COOKIE_REPLY) {
      hilog.info(DOMAIN, TAG, '→ 类型3 Cookie, 转发回 VpnExt');
      this.forwardToVpnExt(bytes);
    } else {
      hilog.info(DOMAIN, TAG, '→ 未知类型 %{public}d, 丢弃', msgType);
    }
  }

  private forwardToServer(data: Uint8Array): number {
    // 纯 NAPI 直连——不依赖任何服务端 relay
    if (!this.nativeSock) return -1;
    try {
      const buf: ArrayBuffer = data.buffer.slice(0, data.byteLength) as ArrayBuffer;
      const sent: number = this.nativeSock.sendTo(buf, this.remoteHost, this.remotePort);
      if (sent === data.byteLength) {
        this.txBytes += data.byteLength;
      }
      return sent;
    } catch (e) {
      return -1;
    }
  }

  private forwardToVpnExtNative(data: Uint8Array): void {
    if (!this.nativeSock) return;
    try {
      const buf: ArrayBuffer = data.buffer.slice(0, data.byteLength) as ArrayBuffer;
      const sent: number = this.nativeSock.sendTo(buf, '127.0.0.1', this.vpnExtPort);
      if (sent !== data.byteLength) {
        hilog.error(DOMAIN, TAG, 'Native →VpnExt short send: %{public}d/%{public}d',
          sent, data.byteLength);
      }
    } catch (err) {
      hilog.error(DOMAIN, TAG, 'Native →VpnExt失败: %{public}s', JSON.stringify(err));
    }
  }

  private async forwardToVpnExt(data: Uint8Array): Promise<void> {
    try {
      const buf: ArrayBuffer = data.buffer.slice(0, data.byteLength) as ArrayBuffer;
      await this.sock!.send({
        data: buf,
        address: { address: '127.0.0.1', port: this.vpnExtPort },
      });
      hilog.info(DOMAIN, TAG, '✅ 已转发到 VpnExt:%{public}d (%{public}d 字节)',
        this.vpnExtPort, data.byteLength);
    } catch (err) {
      hilog.error(DOMAIN, TAG, '→VpnExt失败: %{public}s', JSON.stringify(err));
    }
  }

  /** 启动 C 层 pthread 收包线程（不依赖 JS 定时器） */
  startNativeRecvLoop(): void {
    if (!this.nativeSock) return;
    hilog.info(DOMAIN, TAG, 'Starting C direct-forward thread...');
    const ok: boolean = this.nativeSock.startRecvThread(
      this.relayPort,
      this.vpnExtPort,
      this.remoteHost,
      this.remotePort,
      (rxBytes: number, rxPackets: number, txBytes: number,
        txPackets: number, lastPacketLen: number, direction: number): void => {
        if (!this.running) return;
        this.rxBytes = rxBytes;
        this.relayRxPackets = rxPackets;
        this.txBytes = txBytes;
        this.relayTxPackets = txPackets;
        hilog.info(DOMAIN, TAG,
          'Native direct dir=%{public}d rx=%{public}d/%{public}d tx=%{public}d/%{public}d latest=%{public}d',
          direction, rxPackets, rxBytes, txPackets, txBytes, lastPacketLen);
      }
    );
    hilog.info(DOMAIN, TAG, 'C direct-forward thread started: %{public}s',
      ok ? 'true' : 'false');
  }

}
