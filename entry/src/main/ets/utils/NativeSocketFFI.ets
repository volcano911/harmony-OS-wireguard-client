/**
 * 原生 UDP Socket（NAPI C 模块 + pthread 收包线程）
 *
 * 使用 CMake 编译的 libudp_socket.so：
 *   - createUdpSocket(): 创建 socket，返回 fd
 *   - udpSendTo(): 发送 UDP 数据
 *   - startRecvThread(...): C 层双向转发 WG 服务器与 VpnExtension，
 *     ArkTS 只接收低频累计统计
 *   - stopRecvThread(): 停止收包线程
 */

import nativeModule from 'libudp_socket.so';

export type NativeTunReadCallback = (
  data: ArrayBuffer | null,
  event: number,
  fdFlags: number,
  revents: number,
  errorNo: number,
  pollCount: number
) => void;

/** TUN fd 非阻塞读取；空闲时返回 null，不触发 CoreFileKit 的 EAGAIN 错误日志。 */
export function nativeReadFd(fd: number, maxLength: number): ArrayBuffer | null {
  return nativeModule.readFd(fd, maxLength) as ArrayBuffer | null;
}

/** 在 C++ 专用线程中 poll/read TUN，并按顺序把完整 IP 包交回 ArkTS。 */
export function startNativeTunReader(
  fd: number, callback: NativeTunReadCallback): boolean {
  return nativeModule.startTunReadThread(fd, callback) as boolean;
}

/** 停止并回收 C++ TUN 读取线程。 */
export function stopNativeTunReader(): void {
  nativeModule.stopTunReadThread();
}

/** 将完整 IP 包写回 TUN。 */
export function nativeWriteFd(fd: number, data: ArrayBuffer): number {
  return nativeModule.writeFd(fd, data) as number;
}

export class NativeSocket {
  private fd: number = -1;

  create(): number {
    this.fd = nativeModule.createUdpSocket();
    return this.fd;
  }

  getFd(): number { return this.fd; }

  /** 发送数据，返回发送字节数 */
  sendTo(data: ArrayBuffer, host: string, port: number): number {
    if (this.fd < 0) return -1;
    return nativeModule.udpSendTo(this.fd, data, host, port);
  }

  /** 启动 C 层双向直转线程。direction: 0=服务器回包，1=客户端发包。 */
  startRecvThread(relayPort: number, forwardPort: number,
    remoteHost: string, remotePort: number,
    onStats: (rxBytes: number, rxPackets: number, txBytes: number,
      txPackets: number, lastPacketLen: number, direction: number) => void): boolean {
    if (this.fd < 0) return false;
    return nativeModule.startRecvThread(this.fd, relayPort, forwardPort,
      remoteHost, remotePort, onStats) as boolean;
  }

  /** 停止收包线程 */
  stopRecvThread(): void {
    if (this.fd >= 0) {
      nativeModule.stopRecvThread();
    }
  }

  close(): void {
    this.stopRecvThread();
    if (this.fd >= 0) {
      nativeModule.closeUdpSocket(this.fd);
      this.fd = -1;
    }
  }
}
