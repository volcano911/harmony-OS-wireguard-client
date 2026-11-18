/**
 * 多配置文件存储
 *
 * 以前的实现把一套配置拆成 serverHost / clientAddress / privateKey … 等
 * 八个 preferences 键，天生只能存一份。这里改成：
 *
 *   profiles_v1   → 整个 WgProfile 数组的 JSON 字符串
 *   activeProfileId → 当前选中的配置文件 id
 *
 * 首次启动时会做一次迁移：如果存在旧版的单套配置键，就把它包装成
 * 一个名为「默认配置」的 profile，旧键保持原样不删（回滚友好）。
 */

import { preferences } from '@kit.ArkData';
import { common } from '@kit.AbilityKit';

export interface WgProfile {
  id: string;
  /** 展示名，默认取 Endpoint 主机名 */
  name: string;
  serverHost: string;
  serverPort: string;
  clientAddress: string;
  dnsServer: string;
  clientPrivateKey: string;
  serverPublicKey: string;
  presharedKey: string;
  allowedIps: string;
  updatedAt: number;
}

export interface ProfileSnapshot {
  profiles: WgProfile[];
  activeId: string;
}

const PREFS_NAME: string = 'wg_config';
const KEY_PROFILES: string = 'profiles_v1';
const KEY_ACTIVE: string = 'activeProfileId';

/** 旧版单配置使用的键，仅用于一次性迁移 */
const LEGACY_KEYS: string[] = [
  'serverHost', 'serverPort', 'clientAddress', 'dnsServer',
  'clientPrivateKey', 'serverPublicKey', 'presharedKey', 'allowedIps',
];

export function newProfileId(): string {
  const stamp: string = Date.now().toString(36);
  const salt: string = Math.floor(Math.random() * 1679616).toString(36);
  return stamp + '-' + salt;
}

/**
 * 一张白纸：除了 id 和名字，其它字段一律为空。
 *
 * 这里刻意不预填 51820 / 1.1.1.1 / 0.0.0.0/0 这类「常见值」。它们看起来贴心，
 * 实际会让用户以为这些是自己配置里的数据；一旦和真实服务端不一致，排查半天
 * 才发现是程序自己填的。配置只该来自配置文件本身。
 */
export function emptyProfile(name: string): WgProfile {
  return {
    id: newProfileId(),
    name: name,
    serverHost: '',
    serverPort: '',
    clientAddress: '',
    dnsServer: '',
    clientPrivateKey: '',
    serverPublicKey: '',
    presharedKey: '',
    allowedIps: '',
    updatedAt: Date.now(),
  };
}

/**
 * 读取存储里的对象。只补 id 和名字（没有它们没法索引），
 * 其余字段原样返回：存的是什么就读出什么，缺字段就是空，绝不代填。
 */
function normalize(raw: WgProfile): WgProfile {
  const p: WgProfile = emptyProfile('');
  p.id = (raw.id || '') !== '' ? raw.id : newProfileId();
  p.name = (raw.name || '') !== '' ? raw.name : '未命名配置';
  p.serverHost = raw.serverHost || '';
  p.serverPort = raw.serverPort || '';
  p.clientAddress = raw.clientAddress || '';
  p.dnsServer = raw.dnsServer || '';
  p.clientPrivateKey = raw.clientPrivateKey || '';
  p.serverPublicKey = raw.serverPublicKey || '';
  p.presharedKey = raw.presharedKey || '';
  p.allowedIps = raw.allowedIps || '';
  p.updatedAt = raw.updatedAt > 0 ? raw.updatedAt : Date.now();
  return p;
}

export class ProfileStore {
  private context: common.Context;
  private prefs: preferences.Preferences | null = null;

  constructor(context: common.Context) {
    this.context = context;
  }

  private async getPrefs(): Promise<preferences.Preferences> {
    if (this.prefs === null) {
      this.prefs = await preferences.getPreferences(this.context, PREFS_NAME);
    }
    return this.prefs;
  }

  async load(): Promise<ProfileSnapshot> {
    const prefs: preferences.Preferences = await this.getPrefs();
    const raw: string = (await prefs.get(KEY_PROFILES, '')) as string;
    let profiles: WgProfile[] = raw !== '' ? this.decode(raw) : [];
    let activeId: string = (await prefs.get(KEY_ACTIVE, '')) as string;

    if (profiles.length === 0) {
      const legacy: WgProfile | null = await this.migrateLegacy(prefs);
      if (legacy !== null) {
        profiles = [legacy];
        activeId = legacy.id;
      }
    }

    if (profiles.length > 0 && !ProfileStore.has(profiles, activeId)) {
      activeId = profiles[0].id;
    }
    if (profiles.length === 0) {
      activeId = '';
    }
    return { profiles: profiles, activeId: activeId };
  }

  async save(profiles: WgProfile[], activeId: string): Promise<void> {
    const prefs: preferences.Preferences = await this.getPrefs();
    await prefs.put(KEY_PROFILES, JSON.stringify(profiles));
    await prefs.put(KEY_ACTIVE, activeId);
    await prefs.flush();
  }

  private decode(raw: string): WgProfile[] {
    const out: WgProfile[] = [];
    try {
      const parsed: WgProfile[] = JSON.parse(raw) as WgProfile[];
      for (let i = 0; i < parsed.length; i++) {
        const item: WgProfile = parsed[i];
        if (item !== null && item !== undefined) {
          out.push(normalize(item));
        }
      }
    } catch (e) {
      // 存储损坏时退化为空列表，界面会重新建一套空白配置
    }
    return out;
  }

  private async migrateLegacy(prefs: preferences.Preferences): Promise<WgProfile | null> {
    const host: string = (await prefs.get('serverHost', '')) as string;
    if (host === '') {
      return null;
    }
    const p: WgProfile = emptyProfile('默认配置');
    p.serverHost = host;
    p.serverPort = (await prefs.get('serverPort', '')) as string;
    p.clientAddress = (await prefs.get('clientAddress', '')) as string;
    p.dnsServer = (await prefs.get('dnsServer', '')) as string;
    p.clientPrivateKey = (await prefs.get('clientPrivateKey', '')) as string;
    p.serverPublicKey = (await prefs.get('serverPublicKey', '')) as string;
    p.presharedKey = (await prefs.get('presharedKey', '')) as string;
    p.allowedIps = (await prefs.get('allowedIps', '')) as string;
    p.updatedAt = Date.now();
    return p;
  }

  private static has(profiles: WgProfile[], id: string): boolean {
    for (let i = 0; i < profiles.length; i++) {
      if (profiles[i].id === id) {
        return true;
      }
    }
    return false;
  }

  /** 供界面提示用的旧键名（避免编译器把常量判为未使用） */
  static legacyKeyCount(): number {
    return LEGACY_KEYS.length;
  }
}
