/**
 * HarmonyOS VPN extension — configuration only.
 *
 * The packet path lives entirely in native code (libwg_tunnel.so): the Noise
 * handshake, ChaCha20-Poly1305, the replay window, SNAT and the TUN/UDP poll
 * loop all run in one C thread inside this process. This file does four
 * things and nothing else:
 *
 *   1. parse the connection parameters handed over by the UI
 *   2. protect the process network, then create the TUN device
 *   3. hand the fd plus keys to the native engine
 *   4. publish counters to a file the UI can poll
 *
 * There is no UDP relay, no EntryAbility involvement, and no ArkTS code on the
 * per-packet path.
 */

import { VpnExtensionAbility, vpnExtension, connection } from '@kit.NetworkKit';
import { Want } from '@kit.AbilityKit';
import { BusinessError } from '@kit.BasicServicesKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { fileIo as fs } from '@kit.CoreFileKit';
import { base64Decode } from '../wireguard/crypto/Base64';
import wgTunnel from 'libwg_tunnel.so';

const DOMAIN: number = 0x0000;
const TAG: string = 'WgVpnExt';

const DEFAULT_MTU: number = 1420;
const DEFAULT_ALLOWED_IPS: string = '0.0.0.0/0';
const STATS_FILE: string = 'wg_stats.json';
const STATS_INTERVAL_MS: number = 1000;

interface NativeStartConfig {
  tunFd: number;
  serverIp: string;
  serverPort: number;
  clientPriv: Uint8Array;
  serverPub: Uint8Array;
  psk: Uint8Array;
  clientIp: string;
  mtu: number;
}

interface NativeStats {
  txPackets: number;
  txBytes: number;
  rxPackets: number;
  rxBytes: number;
  txDrops: number;
  rxDrops: number;
  decryptErrors: number;
  handshakes: number;
  handshakeFailures: number;
  rekeys: number;
  uptimeMs: number;
  lastHandshakeAgeMs: number;
  localIndex: number;
  remoteIndex: number;
  connected: boolean;
  running: boolean;
}

interface TunAddress {
  ip: string;
  prefix: number;
}

/** What the UI reads back from wg_stats.json. */
interface StatsPayload {
  connected: boolean;
  running: boolean;
  txPackets: number;
  txBytes: number;
  rxPackets: number;
  rxBytes: number;
  txDrops: number;
  rxDrops: number;
  decryptErrors: number;
  handshakes: number;
  handshakeFailures: number;
  rekeys: number;
  uptimeMs: number;
  lastHandshakeAgeMs: number;
  updatedAt: number;
}

export default class WireGuardVpnExtAbility extends VpnExtensionAbility {
  private vpnConnection: vpnExtension.VpnConnection | null = null;
  private tunFd: number = -1;
  private statsTimer: number = -1;
  private statsPath: string = '';
  private started: boolean = false;

  // ── 网络切换自动恢复 ──
  // WiFi ↔ 蜂窝切换后，native 那只 UDP socket 还绑在上一个物理网络上，
  // 包发不出去，表现就是「回家忘了关，显示已连接却上不了网」。
  private netConn: connection.NetConnection | null = null;
  private lastCfg: NativeStartConfig | null = null;
  private cfgHost: string = '';
  private restarting: boolean = false;
  private lastRestartAt: number = 0;

  onCreate(want: Want): void {
    hilog.info(DOMAIN, TAG, 'VpnExtension created');
  }

  async onRequest(want: Want, startId: number): Promise<void> {
    if (this.started) {
      hilog.warn(DOMAIN, TAG, 'already running, ignoring duplicate start');
      return;
    }

    const params: Record<string, Object> | undefined = want.parameters;
    const serverHost: string = (params?.['serverHost'] as string) ?? '';
    const serverIP: string = (params?.['serverIP'] as string) ?? serverHost;
    const serverPort: number = Number(params?.['serverPort'] as string ?? 0);
    const clientAddress: string = (params?.['clientAddress'] as string) ?? '';
    const dnsServer: string = (params?.['dnsServer'] as string) ?? '';
    const allowedIps: string =
      (params?.['allowedIps'] as string) ?? DEFAULT_ALLOWED_IPS;
    const clientPrivB64: string = (params?.['clientPrivateKey'] as string) ?? '';
    const serverPubB64: string = (params?.['serverPublicKey'] as string) ?? '';
    const pskB64: string = (params?.['presharedKey'] as string) ?? '';

    if (!serverIP || serverPort < 1 || serverPort > 65535) {
      hilog.error(DOMAIN, TAG, 'invalid server %{public}s:%{public}d', serverIP, serverPort);
      return;
    }
    const tun: TunAddress = this.parseCidr(clientAddress);
    if (!tun.ip) {
      hilog.error(DOMAIN, TAG, 'invalid client address %{public}s', clientAddress);
      return;
    }

    try {
      await this.bringUp(serverIP, serverPort, tun, dnsServer, allowedIps,
        clientPrivB64, serverPubB64, pskB64);
      this.started = true;
      this.cfgHost = serverHost;
      this.startStatsWriter();
      this.watchNetwork();
    } catch (err) {
      hilog.error(DOMAIN, TAG, 'bring-up failed: %{public}s', JSON.stringify(err));
      await this.tearDown();
    }
  }

  onDestroy(): void {
    hilog.info(DOMAIN, TAG, 'VpnExtension destroying');
    this.tearDown();
  }

  // ── bring-up ──

  private async bringUp(serverIp: string, serverPort: number, tun: TunAddress,
    dns: string, allowedIps: string, clientPrivB64: string,
    serverPubB64: string, pskB64: string): Promise<void> {
    const clientPriv: Uint8Array = base64Decode(clientPrivB64);
    const serverPub: Uint8Array = base64Decode(serverPubB64);
    if (clientPriv.length !== 32 || serverPub.length !== 32) {
      throw new Error('private/public key must decode to 32 bytes');
    }
    let psk: Uint8Array = new Uint8Array(32);
    if (pskB64) {
      const decoded: Uint8Array = base64Decode(pskB64);
      if (decoded.length !== 32) {
        throw new Error('preshared key must decode to 32 bytes');
      }
      psk = decoded;
    }

    this.vpnConnection = vpnExtension.createVpnConnection(this.context);

    /*
     * Must happen before the TUN exists and before the native socket is
     * created: everything this process opens from now on bypasses the tunnel,
     * so the WireGuard datagrams reach the physical interface instead of
     * disappearing into our own 0.0.0.0/0 route.
     */
    await this.vpnConnection.protectProcessNet();
    hilog.info(DOMAIN, TAG, 'process network protected');

    const config: vpnExtension.VpnConfig = {
      addresses: [{
        address: { address: tun.ip, family: 1, port: 0 },
        prefixLength: tun.prefix,
      }],
      routes: this.buildRoutes(allowedIps, tun.ip),
      dnsAddresses: dns ? [dns] : [],
      mtu: DEFAULT_MTU,
      isIPv4Accepted: true,
      isIPv6Accepted: false,
      // The engine polls, so the TUN must not block when the queue drains.
      isBlocking: false,
    };

    this.tunFd = await this.vpnConnection.create(config);
    hilog.info(DOMAIN, TAG, 'tun created, fd=%{public}d', this.tunFd);

    const native: NativeStartConfig = {
      tunFd: this.tunFd,
      serverIp: serverIp,
      serverPort: serverPort,
      clientPriv: clientPriv,
      serverPub: serverPub,
      psk: psk,
      clientIp: tun.ip,
      mtu: DEFAULT_MTU,
    };

    const rc: number = wgTunnel.start(native) as number;
    if (rc !== 0) {
      throw new Error('native engine refused to start: ' + rc);
    }
    // 留一份配置，网络切换时用它原地重启引擎（TUN 不用动）
    this.lastCfg = native;
    hilog.info(DOMAIN, TAG, 'native engine started');
  }

  // ── 网络切换：原地重启引擎，不重建 TUN ──

  private watchNetwork(): void {
    try {
      const nc: connection.NetConnection = connection.createNetConnection();
      nc.on('netAvailable', (data: connection.NetHandle) => {
        this.onNetworkChanged('netAvailable');
      });
      nc.on('netLost', (data: connection.NetHandle) => {
        this.onNetworkChanged('netLost');
      });
      nc.on('netConnectionPropertiesChange', (data: connection.NetConnectionPropertyInfo) => {
        this.onNetworkChanged('properties');
      });
      nc.register((err: BusinessError) => {
        if (err) {
          hilog.warn(DOMAIN, TAG, 'net watch register failed: %{public}s', err.message);
        }
      });
      this.netConn = nc;
      hilog.info(DOMAIN, TAG, 'watching network changes');
    } catch (err) {
      hilog.warn(DOMAIN, TAG, 'cannot watch network: %{public}s', JSON.stringify(err));
    }
  }

  private unwatchNetwork(): void {
    if (this.netConn === null) {
      return;
    }
    try {
      this.netConn.unregister((err: BusinessError) => {
        if (err) {
          hilog.warn(DOMAIN, TAG, 'net watch unregister: %{public}s', err.message);
        }
      });
    } catch (err) {
      hilog.warn(DOMAIN, TAG, 'unregister threw: %{public}s', JSON.stringify(err));
    }
    this.netConn = null;
  }

  /**
   * 物理网络变了（出 WiFi 进蜂窝，或反过来）→ 旧 socket 已经绑死在上一张网卡上，
   * 继续用它只会一直超时。这里停掉 native 引擎、按新网络重新保护进程、重新解析
   * 域名，再用同一个 TUN fd 起回来。TUN 和路由都不动，所以 UI 上不会闪断。
   */
  private async onNetworkChanged(why: string): Promise<void> {
    const cfg: NativeStartConfig | null = this.lastCfg;
    if (!this.started || this.restarting || cfg === null) {
      return;
    }
    const now: number = Date.now();
    // WiFi 信号抖动会连着报好几次，只认第一次
    if (now - this.lastRestartAt < 2000) {
      return;
    }
    this.lastRestartAt = now;
    this.restarting = true;
    hilog.info(DOMAIN, TAG, 'network changed (%{public}s), restarting engine', why);

    try {
      wgTunnel.stop();

      let ip: string = cfg.serverIp;
      if (this.cfgHost !== '' && this.cfgHost !== ip) {
        try {
          const addrs: connection.NetAddress[] =
            await connection.getAddressesByName(this.cfgHost);
          if (addrs && addrs.length > 0) {
            ip = addrs[0].address;
          }
        } catch (err) {
          hilog.warn(DOMAIN, TAG, 're-resolve %{public}s failed, reusing %{public}s',
            this.cfgHost, ip);
        }
      }

      if (this.vpnConnection !== null) {
        try {
          await this.vpnConnection.protectProcessNet();
        } catch (err) {
          hilog.warn(DOMAIN, TAG, 're-protect failed: %{public}s', JSON.stringify(err));
        }
      }

      cfg.serverIp = ip;
      const rc: number = wgTunnel.start(cfg) as number;
      hilog.info(DOMAIN, TAG, 'engine restarted on %{public}s rc=%{public}d', ip, rc);
    } catch (err) {
      hilog.error(DOMAIN, TAG, 'restart on network change failed: %{public}s',
        JSON.stringify(err));
    }
    this.restarting = false;
  }

  private async tearDown(): Promise<void> {
    this.unwatchNetwork();
    this.lastCfg = null;
    if (this.statsTimer >= 0) {
      clearInterval(this.statsTimer);
      this.statsTimer = -1;
    }
    try {
      if (wgTunnel.isRunning() as boolean) {
        wgTunnel.stop();
      }
    } catch (err) {
      hilog.warn(DOMAIN, TAG, 'native stop failed: %{public}s', JSON.stringify(err));
    }
    this.started = false;
    this.tunFd = -1;

    if (this.vpnConnection) {
      try {
        await this.vpnConnection.destroy();
      } catch (err) {
        hilog.warn(DOMAIN, TAG, 'destroy failed: %{public}s', JSON.stringify(err));
      }
      this.vpnConnection = null;
    }
    this.writeStats(true);
  }

  // ── configuration helpers ──

  private buildRoutes(allowedIps: string, clientIp: string): connection.RouteInfo[] {
    const routes: connection.RouteInfo[] = [];
    const entries: string[] = allowedIps.split(',');

    for (const raw of entries) {
      const cidr: string = raw.trim();
      if (!cidr || cidr.includes(':')) continue; // IPv6 is not accepted

      const parts: string[] = cidr.split('/');
      const address: string = parts[0]?.trim() ?? '';
      const prefix: number = parts.length > 1 ? parseInt(parts[1]) : 32;

      if (!this.isIPv4(address) || isNaN(prefix) || prefix < 0 || prefix > 32) {
        hilog.warn(DOMAIN, TAG, 'skipping invalid route %{public}s', cidr);
        continue;
      }

      routes.push({
        interface: 'vpn-tun',
        destination: {
          address: { address: address, family: 1, port: 0 },
          prefixLength: prefix,
        },
        gateway: { address: clientIp, family: 1, port: 0 },
        hasGateway: true,
        isDefaultRoute: true,
        isExcludedRoute: false,
      });
    }
    return routes;
  }

  private parseCidr(text: string): TunAddress {
    const parts: string[] = (text || '').split('/');
    const ip: string = parts[0]?.trim() ?? '';
    let prefix: number = parts.length > 1 ? parseInt(parts[1]) : 32;
    if (isNaN(prefix) || prefix < 0 || prefix > 32) prefix = 32;
    if (!this.isIPv4(ip)) return { ip: '', prefix: prefix };
    return { ip: ip, prefix: prefix };
  }

  private isIPv4(text: string): boolean {
    const parts: string[] = text.split('.');
    if (parts.length !== 4) return false;
    for (const part of parts) {
      const n: number = Number(part);
      if (!Number.isInteger(n) || n < 0 || n > 255 || part === '') return false;
    }
    return true;
  }

  // ── telemetry for the UI ──

  private startStatsWriter(): void {
    /*
     * Application-level directory, not the module one: the UI ability runs in
     * a different process and must resolve the exact same path.
     */
    this.statsPath =
      this.context.getApplicationContext().filesDir + '/' + STATS_FILE;
    this.writeStats(false);
    this.statsTimer = setInterval((): void => {
      this.writeStats(false);
    }, STATS_INTERVAL_MS);
  }

  private writeStats(stopped: boolean): void {
    if (!this.statsPath) return;

    let payload: string;
    try {
      const st: NativeStats = wgTunnel.getStats() as NativeStats;
      const snapshot: StatsPayload = {
        connected: stopped ? false : st.connected,
        running: stopped ? false : st.running,
        txPackets: st.txPackets,
        txBytes: st.txBytes,
        rxPackets: st.rxPackets,
        rxBytes: st.rxBytes,
        txDrops: st.txDrops,
        rxDrops: st.rxDrops,
        decryptErrors: st.decryptErrors,
        handshakes: st.handshakes,
        handshakeFailures: st.handshakeFailures,
        rekeys: st.rekeys,
        uptimeMs: st.uptimeMs,
        lastHandshakeAgeMs: st.lastHandshakeAgeMs,
        updatedAt: Date.now(),
      };
      payload = JSON.stringify(snapshot);
    } catch (err) {
      return;
    }

    try {
      const file = fs.openSync(this.statsPath,
        fs.OpenMode.CREATE | fs.OpenMode.READ_WRITE | fs.OpenMode.TRUNC);
      fs.writeSync(file.fd, payload);
      fs.closeSync(file);
    } catch (err) {
      hilog.warn(DOMAIN, TAG, 'cannot write stats file: %{public}s',
        JSON.stringify(err));
    }
  }
}
