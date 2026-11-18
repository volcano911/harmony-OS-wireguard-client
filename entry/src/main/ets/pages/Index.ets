/**
 * WireGuard VPN Client for HarmonyOS —— 浅色 iOS 风格 v2
 *
 * 本次重写修掉的三类问题：
 *   1. 电源按钮背后露「白色方块」：旧实现给 Circle 绘制组件挂 .shadow()，
 *      ArkUI 对绘制组件的阴影按组件矩形边界渲染，圆按钮得到的是方形阴影。
 *      v2 改用「圆形容器 + radialGradient 径向渐变光晕」，彻底没有方形底。
 *   2. 配置管理面板「完成」和「×」并存：bindSheet 的 showClose 默认为 true，
 *      系统会在右上角自绘一个 × 关闭按钮，与自定义「完成」叠在一起。
 *      v2 显式 showClose: false，只保留「完成」。
 *   3. 运行统计不刷新：带参数的 @Builder 按值传参，状态变化不会刷新 UI
 *      （官方文档明确的行为），旧版下行/上行/握手行是冻住的。v2 把所有
 *      依赖状态的行内联到无参 @Builder 里，随 2s 轮询实时刷新。
 *
 * 设计要点：
 *   - 上行/下行「实时速率」放在首屏电源按钮正下方——全页最醒目的位置，
 *     大号数字（26vp 粗体）+ 累计流量，速率由轮询增量平滑计算。
 *   - 三档断点：紧凑（Pura X 外屏）/ 直板（常规手机）/ 展开（折叠屏内屏、平板）。
 *   - 全部浅色：系统分组底色 + 白色圆角卡片 + 发丝分割线，无渐变横幅、无霓虹。
 */

import { Want, common, bundleManager } from '@kit.AbilityKit';
import { connection, vpnExtension } from '@kit.NetworkKit';
import { picker, fileIo } from '@kit.CoreFileKit';
import { router, mediaquery } from '@kit.ArkUI';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { parseWgConfig, WgParsedConfig } from '../utils/WgConfigParser';
import { ProfileStore, ProfileSnapshot, WgProfile, emptyProfile } from '../utils/ProfileStore';

const DOMAIN = 0x0000;
const TAG = 'WgImport';

/** The extension publishes tunnel counters here; the UI polls it. */
const STATS_FILE_NAME: string = 'wg_stats.json';

/** 紧凑模式：Pura X 外屏约 330vp 高，直板机约 800vp，内屏展开约 700vp */
const COMPACT_HEIGHT_VP: number = 560;
/** 展开模式：折叠屏内屏横屏 / 平板 */
const WIDE_WIDTH_VP: number = 600;
/** 统计文件超过这个时间没更新，视为扩展已退出 */
const STATS_STALE_MS: number = 6000;
/** 判断「这份统计是本轮写的」时允许的时钟抖动 */
const STATS_CLOCK_SLACK_MS: number = 1000;
/** 点连接后等扩展写出第一份统计的宽限期，超时才认定扩展没起来 */
const CONNECT_GRACE_MS: number = 20000;

// ── 配色（iOS 浅色系统色）──
const C_BG: string = '#F2F2F7';        // systemGroupedBackground
const C_CARD: string = '#FFFFFF';      // 卡片
const C_FILL: string = '#F4F4F7';      // 卡片内的凹陷块
const C_HAIR: string = '#E4E4E9';      // 发丝分割线
const C_TEXT: string = '#111114';      // label
const C_SUB: string = '#8A8A8E';      // secondaryLabel
const C_DIM: string = '#C3C3C8';       // placeholder
const C_BLUE: string = '#007AFF';     // systemBlue
const C_BLUE_SOFT: string = '#EAF2FF'; // 蓝色浅底
const C_GREEN: string = '#34C759';     // systemGreen
const C_RED: string = '#FF3B30';      // systemRed

/** Mirrors wg_tunnel_stats as written by the VPN extension. */
interface TunnelStats {
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

/** 简单判断字符串是否为 IP 地址（非域名） */
function isIP(s: string): boolean {
  const parts: string[] = s.split('.');
  if (parts.length !== 4) return false;
  for (let i: number = 0; i < parts.length; i++) {
    const n: number = parseInt(parts[i]);
    if (isNaN(n) || n < 0 || n > 255) return false;
  }
  return true;
}

/**
 * 电源符号：圆环留出顶部缺口 + 一根竖线。
 *
 * 旧实现是固定 52×52 的 Path 再 .scale() 缩放，有两个无法回避的问题：
 *   1. scale 只做视觉变换、锚点与布局框不一致，符号被整体带向左上，看起来没居中；
 *   2. 路径图形本身只占 52 画布的 73%，再乘缩放比，实际笔画只有目标尺寸的七成多，
 *      放在按钮里显得又小又细。
 * 改为 Canvas 按 glyphSize 现场计算几何：圆心恒为 (size/2, size/2)，笔画宽度随
 * 尺寸等比放大，任何挡位下都严格居中且大小可控。
 * @Watch 保证折叠屏展开 / 外屏切换时重新按新尺寸绘制。
 */
@Component
struct PowerGlyph {
  @Prop @Watch('refreshGlyph') glyphSize: number = 52;
  @Prop @Watch('refreshGlyph') glyphColor: string = '#FFFFFF';
  private settings: RenderingContextSettings = new RenderingContextSettings(true);
  private ctx: CanvasRenderingContext2D = new CanvasRenderingContext2D(this.settings);
  private ready: boolean = false;

  private refreshGlyph(): void {
    if (this.ready) {
      this.draw();
    }
  }

  private draw(): void {
    const s: number = this.glyphSize;
    const cx: number = s / 2;
    const cy: number = s / 2;
    const r: number = s * 0.36;          // 圆环半径
    const w: number = s * 0.115;         // 笔画宽度（比旧版粗一档，按钮里更清楚）
    const half: number = Math.PI / 6;    // 顶部缺口半角 30°

    this.ctx.clearRect(0, 0, s, s);
    this.ctx.strokeStyle = this.glyphColor;
    this.ctx.lineWidth = w;
    this.ctx.lineCap = 'round';

    // 圆环：从缺口右侧顺时针绕一整圈回到缺口左侧
    this.ctx.beginPath();
    this.ctx.arc(cx, cy, r, -Math.PI / 2 + half, -Math.PI / 2 - half + Math.PI * 2, false);
    this.ctx.stroke();

    // 竖线：顶端与圆环外径齐平，上下笔画因此完全对称，视觉重心落在圆心
    this.ctx.beginPath();
    this.ctx.moveTo(cx, cy - r);
    this.ctx.lineTo(cx, cy - r * 0.12);
    this.ctx.stroke();
  }

  build() {
    Canvas(this.ctx)
      .width(this.glyphSize)
      .height(this.glyphSize)
      .onReady(() => {
        this.ready = true;
        this.draw();
      })
  }
}

/**
 * iOS 风格表单行：左标签 + 右对齐输入，无边框、无底色，靠发丝线分隔。
 * value 用 @Link，输入内容双向同步。
 */
@Component
struct FieldRow {
  label: string = '';
  hint: string = '';
  password: boolean = false;
  numeric: boolean = false;
  last: boolean = false;
  @Link value: string;
  /** 内容变了就通知外面存盘。以前只有「保存修改」按钮会存，改了不点就白改。 */
  onEdited: () => void = () => {};

  build() {
    Row() {
      Text(this.label)
        .fontSize(15)
        .fontColor(C_TEXT)
        .width(92)
      TextInput({ placeholder: this.hint, text: this.value })
        .layoutWeight(1)
        .height(46)
        .fontSize(15)
        .fontColor(C_TEXT)
        .textAlign(TextAlign.End)
        .placeholderColor(C_DIM)
        .placeholderFont({ size: 15 })
        .backgroundColor(Color.Transparent)
        .padding({ left: 0, right: 0 })
        .borderRadius(0)
        .type(this.password ? InputType.Password :
          (this.numeric ? InputType.Number : InputType.Normal))
        .showPasswordIcon(false)
        .onChange((v: string) => {
          this.value = v;
          this.onEdited();
        })
    }
    .width('100%')
    .height(46)
    .padding({ left: 16, right: 16 })
    .borderWidth({ bottom: this.last ? 0 : 0.5 })
    .borderColor(C_HAIR)
  }
}

@Entry
@Component
struct Index {
  // ── 当前编辑中的配置字段（镜像当前 profile，改动后写回） ──
  @State serverHost: string = '';
  @State serverPort: string = '51820';
  @State clientAddress: string = '';
  @State dnsServer: string = '1.1.1.1';
  @State clientPrivateKey: string = '';
  @State serverPublicKey: string = '';
  @State presharedKey: string = '';
  @State allowedIps: string = '0.0.0.0/0';

  // ── 多配置 ──
  @State profiles: WgProfile[] = [];
  @State activeId: string = '';
  @State showSheet: boolean = false;
  @State editingId: string = '';
  @State editingName: string = '';

  // ── 运行态 ──
  @State isConnected: boolean = false;
  @State busy: boolean = false;
  @State statusText: string = '就绪';
  @State statusLog: string = '';
  @State diagText: string = '';
  @State txBytes: number = 0;
  @State rxBytes: number = 0;
  @State handshakes: number = 0;
  @State rekeys: number = 0;
  // 实时速率（B/s），由统计轮询的增量平滑得出
  @State rxSpeed: number = 0;
  @State txSpeed: number = 0;

  // ── 布局 ──
  @State isCompact: boolean = false;
  @State isWide: boolean = false;
  @State showParams: boolean = true;
  @State showDiag: boolean = false;
  @State versionName: string = '1.1.0';

  private diagTimer: number = -1;
  /** 表单自动保存的防抖定时器 */
  private saveTimer: number = -1;
  private store: ProfileStore | null = null;
  /**
   * 配置是否已从 preferences 读回来。没读完时表单里全是初始值，
   * 这时候任何 saveCurrent 都会把空表单当成「用户改过的配置」写回去。
   */
  private profilesLoaded: boolean = false;
  /** 打开/切换配置时的快照，「还原」恢复到它 */
  private baseline: WgProfile | null = null;
  /**
   * 本次点击「连接」的时刻。扩展冷启动要 1~3 秒，这段时间统计文件里还是上一轮
   * 的内容，直接采信会让按钮先亮「已连接」再掉回去。只有 updatedAt 不早于它
   * 的统计才算本轮的。纯显示用途，不参与任何隧道逻辑。
   */
  private connectAt: number = 0;
  private compactL: mediaquery.MediaQueryListener | null = null;
  private wideL: mediaquery.MediaQueryListener | null = null;
  // 上一次速率采样的计数与时间，用于差分
  private prevRx: number = 0;
  private prevTx: number = 0;
  private prevAt: number = 0;

  async aboutToAppear(): Promise<void> {
    this.readVersion();
    this.setupMedia();
    await this.loadProfiles();
    this.checkScanResult();
    // true：顺带校准连接状态——UI 被系统回收重开后，隧道其实可能还在跑
    this.refreshStats(true);
    if (this.isConnected) {
      this.startDiagTimer();
    }
  }

  aboutToDisappear(): void {
    this.stopDiagTimer();
    this.releaseMedia();
    if (this.saveTimer >= 0) {
      clearTimeout(this.saveTimer);
      this.saveTimer = -1;
    }
    this.saveCurrent();
  }

  onPageShow(): void {
    this.checkScanResult();
    this.refreshStats(true);
    if (this.isConnected) {
      this.startDiagTimer();
    }
  }

  onPageHide(): void {
    this.saveCurrent();
  }

  private readVersion(): void {
    try {
      const info: bundleManager.BundleInfo =
        bundleManager.getBundleInfoForSelfSync(bundleManager.BundleFlag.GET_BUNDLE_INFO_DEFAULT);
      if (info.versionName !== '') {
        this.versionName = info.versionName;
      }
    } catch (e) {
      // 取不到就沿用默认值，只是个脚注
    }
  }

  // ── 响应式 ──

  private setupMedia(): void {
    this.compactL = mediaquery.matchMediaSync('(height<=' + COMPACT_HEIGHT_VP + 'vp)');
    this.isCompact = this.compactL.matches as boolean;
    this.compactL.on('change', (r: mediaquery.MediaQueryResult) => {
      this.isCompact = r.matches as boolean;
    });

    this.wideL = mediaquery.matchMediaSync('(width>=' + WIDE_WIDTH_VP + 'vp)');
    this.isWide = this.wideL.matches as boolean;
    this.wideL.on('change', (r: mediaquery.MediaQueryResult) => {
      this.isWide = r.matches as boolean;
    });

    // 矮屏默认收起参数，把空间留给电源键和速率
    this.showParams = !this.isCompact;
  }

  private releaseMedia(): void {
    if (this.compactL !== null) {
      this.compactL.off('change');
      this.compactL = null;
    }
    if (this.wideL !== null) {
      this.wideL.off('change');
      this.wideL = null;
    }
  }

  private hPad(): number {
    if (this.isCompact) return 14;
    return this.isWide ? 26 : 18;
  }

  private maxW(): number {
    return this.isWide ? 700 : 620;
  }

  /** 电源键外径 */
  private powerD(): number {
    if (this.isCompact) return 92;
    return this.isWide ? 140 : 124;
  }

  /** 电源键光晕外径（径向渐变圆容器的直径） */
  private haloD(): number {
    return this.powerD() + (this.isCompact ? 26 : 32);
  }

  /** 电源符号画布边长：取按钮直径的 ~0.5，Canvas 内笔画实际占 0.835，
   *  即符号视觉宽约为圆直径的 42%，比旧版（约 28%）明显一档。 */
  private glyphD(): number {
    if (this.isCompact) return 48;
    return this.isWide ? 72 : 64;
  }

  // ── 视图 ──

  build() {
    Column() {
      this.topBar()

      Scroll() {
        Column() {
          this.heroCard()
          this.profileSection()
          this.paramSection()
          this.statusSection()

          Text('WireGuard · HarmonyOS · v' + this.versionName)
            .fontSize(11)
            .fontColor(C_DIM)
            .width('100%')
            .textAlign(TextAlign.Center)
            .margin({ top: 20, bottom: 24 })
        }
        .width('100%')
        .constraintSize({ maxWidth: this.maxW() })
      }
      .layoutWeight(1)
      .scrollBar(BarState.Off)
      .edgeEffect(EdgeEffect.Spring)
      .align(Alignment.Top)
    }
    .width('100%')
    .height('100%')
    .alignItems(HorizontalAlign.Center)
    .padding({ left: this.hPad(), right: this.hPad() })
    .backgroundColor(C_BG)
    .bindSheet($$this.showSheet, this.profileSheet(), {
      height: SheetSize.LARGE,
      dragBar: true,
      // 关键修复：关掉系统自绘的右上角 × 关闭按钮，只保留自定义「完成」
      showClose: false,
      backgroundColor: C_BG,
      onDisappear: () => { this.showSheet = false; },
    })
  }

  // ── 顶部标题栏 ──

  @Builder topBar() {
    Row() {
      Column() {
        Text('WireGuard')
          .fontSize(this.isCompact ? 26 : 32)
          .fontWeight(700)
          .fontColor(C_TEXT)
          .letterSpacing(-0.6)
        if (!this.isCompact) {
          Text(this.isConnected ? '已连接 · ' + this.activeName() : '未连接')
            .fontSize(12)
            .fontColor(this.isConnected ? C_GREEN : C_SUB)
            .margin({ top: 2 })
            .maxLines(1)
            .textOverflow({ overflow: TextOverflow.Ellipsis })
        }
      }
      .alignItems(HorizontalAlign.Start)
      .layoutWeight(1)

      // 圆形入口：配置管理（三个圆点用 Circle 绘制，避免字体符号基线偏移）
      Stack() {
        Row({ space: 4 }) {
          Circle().width(4.5).height(4.5).fill('#54545C')
          Circle().width(4.5).height(4.5).fill('#54545C')
          Circle().width(4.5).height(4.5).fill('#54545C')
        }
      }
      .width(38)
      .height(38)
      .backgroundColor(C_CARD)
      .borderRadius(19)
      .shadow({ radius: 8, color: '#12000000', offsetX: 0, offsetY: 2 })
      .onClick(() => { this.showSheet = true; })
    }
    .width('100%')
    .constraintSize({ maxWidth: this.maxW() })
    .padding({ top: this.isCompact ? 10 : 16, bottom: this.isCompact ? 8 : 12 })
  }

  // ── 首屏：电源键 + 实时速率 ──

  @Builder heroCard() {
    Column() {
      // 电源按钮：光晕 = 圆角容器 + 径向渐变（不会出现方形阴影底）
      Stack() {
        Column()
          .width(this.haloD())
          .height(this.haloD())
          .borderRadius(this.haloD() / 2)
          .radialGradient({
            center: [this.haloD() / 2, this.haloD() / 2],
            radius: this.haloD() / 2,
            colors: this.glowColors(),
          })

        Circle()
          .width(this.powerD())
          .height(this.powerD())
          .fill(this.mainFill())

        if (this.busy) {
          LoadingProgress()
            .width(this.glyphD() * 0.8)
            .height(this.glyphD() * 0.8)
            .color('#FFFFFF')
        } else {
          PowerGlyph({ glyphSize: this.glyphD(), glyphColor: '#FFFFFF' })
        }
      }
      .width(this.haloD())
      .height(this.haloD())
      // 显式居中：光晕、圆形底、电源符号三者圆心重合
      .alignContent(Alignment.Center)
      .onClick(() => { this.toggleVpn(); })

      Text(this.headline())
        .fontSize(this.isCompact ? 16 : 18)
        .fontWeight(600)
        .fontColor(this.isConnected ? C_GREEN : C_TEXT)
        .margin({ top: this.isCompact ? 6 : 10 })

      Text(this.subline())
        .fontSize(12)
        .fontColor(C_SUB)
        .margin({ top: 3 })
        .maxLines(1)
        .textOverflow({ overflow: TextOverflow.Ellipsis })
        .padding({ left: 12, right: 12 })

      // ── 上行 / 下行实时速率：全页最醒目的数据区 ──
      Row()
        .width('100%')
        .height(0.5)
        .backgroundColor(C_HAIR)
        .margin({ top: this.isCompact ? 12 : 16 })

      Row() {
        // 下行
        Column() {
          Row() {
            Text('↓')
              .fontSize(14)
              .fontWeight(700)
              .fontColor(this.speedAccent(true))
            Text('下行')
              .fontSize(12)
              .fontColor(C_SUB)
              .margin({ left: 3 })
          }
          Text(this.fmtSpeed(this.rxSpeed))
            .fontSize(this.isCompact ? 21 : 26)
            .fontWeight(700)
            .fontColor(this.isConnected ? C_TEXT : C_DIM)
            .maxLines(1)
            .margin({ top: 3 })
          Text('共 ' + this.fmtBytes(this.rxBytes))
            .fontSize(11)
            .fontColor(C_SUB)
            .margin({ top: 2 })
        }
        .layoutWeight(1)
        .alignItems(HorizontalAlign.Center)

        // 竖向发丝线
        Column()
          .width(0.5)
          .height(this.isCompact ? 40 : 48)
          .backgroundColor(C_HAIR)

        // 上行
        Column() {
          Row() {
            Text('↑')
              .fontSize(14)
              .fontWeight(700)
              .fontColor(this.speedAccent(false))
            Text('上行')
              .fontSize(12)
              .fontColor(C_SUB)
              .margin({ left: 3 })
          }
          Text(this.fmtSpeed(this.txSpeed))
            .fontSize(this.isCompact ? 21 : 26)
            .fontWeight(700)
            .fontColor(this.isConnected ? C_TEXT : C_DIM)
            .maxLines(1)
            .margin({ top: 3 })
          Text('共 ' + this.fmtBytes(this.txBytes))
            .fontSize(11)
            .fontColor(C_SUB)
            .margin({ top: 2 })
        }
        .layoutWeight(1)
        .alignItems(HorizontalAlign.Center)
      }
      .width('100%')
      .margin({ top: this.isCompact ? 10 : 12 })
    }
    .width('100%')
    .padding({
      top: this.isCompact ? 12 : 20,
      bottom: this.isCompact ? 12 : 16,
    })
    .backgroundColor(C_CARD)
    .borderRadius(this.isCompact ? 20 : 26)
    .shadow({ radius: 16, color: '#0D000000', offsetX: 0, offsetY: 3 })
    .margin({ bottom: this.isCompact ? 12 : 18 })
  }

  /** 光晕渐变色：中心最实，按钮边缘剩淡淡一圈，向外完全透明 */
  private glowColors(): Array<[ResourceColor, number]> {
    const hex: string = this.busy ? '8E8E93' : (this.isConnected ? '34C759' : '007AFF');
    const edge: number = this.powerD() / this.haloD();
    const stops: Array<[ResourceColor, number]> = [
      ['#3D' + hex, 0.0],
      ['#14' + hex, edge],
      ['#00' + hex, 1.0],
    ];
    return stops;
  }

  /** 速率箭头颜色：连接后下行蓝、上行绿；未连接灰色 */
  private speedAccent(isDown: boolean): string {
    if (!this.isConnected) {
      return C_DIM;
    }
    return isDown ? C_BLUE : C_GREEN;
  }

  private mainFill(): string {
    if (this.busy) return C_DIM;
    return this.isConnected ? C_GREEN : C_BLUE;
  }

  private headline(): string {
    if (this.busy) {
      return this.statusText;
    }
    if (!this.isConnected) {
      return '未连接';
    }
    // 扩展起来了但还没握手成功：别急着报「已连接」
    if (this.handshakes <= 0) {
      return '握手中';
    }
    return '已连接';
  }

  private subline(): string {
    if (this.busy) {
      return '请稍候';
    }
    const ep: string = this.endpointText();
    if (this.isConnected) {
      return this.activeName() + ' · ' + ep;
    }
    return this.profiles.length > 0 ? '轻点上方按钮连接 · ' + this.activeName() : '先添加一份配置文件';
  }

  // ── 配置文件 ──

  @Builder sectionTitle(title: string, action: string, onAction: () => void) {
    Row() {
      Text(title)
        .fontSize(13)
        .fontColor(C_SUB)
        .layoutWeight(1)
      if (action !== '') {
        Text(action)
          .fontSize(13)
          .fontColor(C_BLUE)
          .onClick(onAction)
      }
    }
    .width('100%')
    .padding({ left: 4, right: 4, bottom: 7 })
  }

  @Builder profileSection() {
    Column() {
      this.sectionTitle('配置文件', '管理', () => { this.showSheet = true; })

      Column() {
        if (this.profiles.length === 0) {
          Row() {
            Text('尚未添加配置')
              .fontSize(15)
              .fontColor(C_SUB)
              .layoutWeight(1)
            Text('添加')
              .fontSize(15)
              .fontColor(C_BLUE)
          }
          .width('100%')
          .height(52)
          .padding({ left: 16, right: 16 })
          .onClick(() => { this.showSheet = true; })
        } else {
          ForEach(this.profiles, (p: WgProfile, idx: number) => {
            this.profileRow(p, idx === this.profiles.length - 1)
          }, (p: WgProfile) => p.id)
        }
      }
      .width('100%')
      .backgroundColor(C_CARD)
      .borderRadius(16)
      .clip(true)
      .shadow({ radius: 12, color: '#0A000000', offsetX: 0, offsetY: 2 })
    }
    .width('100%')
    .margin({ bottom: this.isCompact ? 12 : 18 })
  }

  @Builder profileRow(p: WgProfile, last: boolean) {
    Row() {
      Column() {
        Text(p.name)
          .fontSize(15)
          .fontWeight(500)
          .fontColor(C_TEXT)
          .maxLines(1)
          .textOverflow({ overflow: TextOverflow.Ellipsis })
        Text(p.serverHost !== '' ? p.serverHost + ':' + p.serverPort : '未填写地址')
          .fontSize(12)
          .fontColor(C_SUB)
          .margin({ top: 2 })
          .maxLines(1)
          .textOverflow({ overflow: TextOverflow.Ellipsis })
      }
      .alignItems(HorizontalAlign.Start)
      .layoutWeight(1)

      if (p.id === this.activeId) {
        Text('✓')
          .fontSize(17)
          .fontWeight(600)
          .fontColor(C_BLUE)
          .margin({ left: 8 })
      }
    }
    .width('100%')
    .constraintSize({ minHeight: 56 })
    .padding({ left: 16, right: 16, top: 9, bottom: 9 })
    .borderWidth({ bottom: last ? 0 : 0.5 })
    .borderColor(C_HAIR)
    .onClick(() => { this.switchTo(p.id); })
  }

  // ── 连接参数 ──

  @Builder paramSection() {
    Column() {
      Row() {
        Text('连接参数')
          .fontSize(13)
          .fontColor(C_SUB)
          .layoutWeight(1)
        Text(this.showParams ? '收起' : '展开')
          .fontSize(13)
          .fontColor(C_BLUE)
          .onClick(() => { this.showParams = !this.showParams; })
      }
      .width('100%')
      .padding({ left: 4, right: 4, bottom: 7 })

      Column() {
        Row() {
          Text('当前编辑')
            .fontSize(12)
            .fontColor(C_SUB)
            .layoutWeight(1)
          Text(this.activeName())
            .fontSize(12)
            .fontColor(C_TEXT)
            .maxLines(1)
            .textOverflow({ overflow: TextOverflow.Ellipsis })
            .constraintSize({ maxWidth: 200 })
        }
        .width('100%')
        .padding({ left: 16, right: 16, top: 11, bottom: 11 })
        .borderWidth({ bottom: this.showParams ? 0.5 : 0 })
        .borderColor(C_HAIR)

        if (this.showParams) {
          FieldRow({ label: '服务端地址', hint: 'IP 或域名', value: $serverHost,
            onEdited: () => { this.scheduleSave(); } })
          FieldRow({ label: '端口', hint: '如 51820', value: $serverPort, numeric: true,
            onEdited: () => { this.scheduleSave(); } })
          FieldRow({ label: '虚拟 IP', hint: '如 10.77.0.5', value: $clientAddress,
            onEdited: () => { this.scheduleSave(); } })
          FieldRow({ label: 'DNS', hint: '如 1.1.1.1', value: $dnsServer,
            onEdited: () => { this.scheduleSave(); } })
          FieldRow({ label: '分流网段', hint: '如 0.0.0.0/0', value: $allowedIps,
            onEdited: () => { this.scheduleSave(); } })
          FieldRow({ label: '客户端私钥', hint: 'Base64', value: $clientPrivateKey, password: true,
            onEdited: () => { this.scheduleSave(); } })
          FieldRow({ label: '服务端公钥', hint: 'Base64', value: $serverPublicKey,
            onEdited: () => { this.scheduleSave(); } })
          FieldRow({ label: '预共享密钥', hint: '可留空', value: $presharedKey, password: true, last: true,
            onEdited: () => { this.scheduleSave(); } })

          Row() {
            Button('保存修改')
              .layoutWeight(1)
              .height(44)
              .fontSize(15)
              .fontWeight(500)
              .fontColor('#FFFFFF')
              .backgroundColor(C_BLUE)
              .borderRadius(12)
              .onClick(() => { this.saveFromButton(); })
            Button('还原')
              .height(44)
              .width(88)
              .fontSize(15)
              .fontColor(C_TEXT)
              .backgroundColor(C_FILL)
              .borderRadius(12)
              .margin({ left: 10 })
              .onClick(() => { this.resetForm(); })
          }
          .width('100%')
          .padding({ left: 16, right: 16, top: 14, bottom: 16 })
        }
      }
      .width('100%')
      .backgroundColor(C_CARD)
      .borderRadius(16)
      .clip(true)
      .shadow({ radius: 12, color: '#0A000000', offsetX: 0, offsetY: 2 })
    }
    .width('100%')
    .margin({ bottom: this.isCompact ? 12 : 18 })
  }

  // ── 运行状态（行内直接引用 @State，保证 2s 轮询能刷新） ──

  @Builder statusSection() {
    Column() {
      Row() {
        Text('运行状态')
          .fontSize(13)
          .fontColor(C_SUB)
          .layoutWeight(1)
        Text(this.showDiag ? '收起' : '展开')
          .fontSize(13)
          .fontColor(C_BLUE)
          .onClick(() => { this.showDiag = !this.showDiag; })
      }
      .width('100%')
      .padding({ left: 4, right: 4, bottom: 7 })

      Column() {
        Row() {
          Text('握手次数')
            .fontSize(15)
            .fontColor(C_TEXT)
            .layoutWeight(1)
          Text('' + this.handshakes)
            .fontSize(15)
            .fontColor(C_SUB)
        }
        .width('100%')
        .height(44)
        .padding({ left: 16, right: 16 })
        .borderWidth({ bottom: this.showDiag ? 0.5 : 0 })
        .borderColor(C_HAIR)

        if (this.showDiag) {
          Row() {
            Text('重协商')
              .fontSize(15)
              .fontColor(C_TEXT)
              .layoutWeight(1)
            Text('' + this.rekeys)
              .fontSize(15)
              .fontColor(C_SUB)
          }
          .width('100%')
          .height(44)
          .padding({ left: 16, right: 16 })
          .borderWidth({ bottom: 0.5 })
          .borderColor(C_HAIR)

          Row() {
            Text('握手详情')
              .fontSize(15)
              .fontColor(C_TEXT)
              .layoutWeight(1)
            Text(this.diagText !== '' ? this.diagText : '暂无统计')
              .fontSize(11)
              .fontColor(C_SUB)
              .textAlign(TextAlign.End)
              .maxLines(2)
              .textOverflow({ overflow: TextOverflow.Ellipsis })
              .constraintSize({ maxWidth: '62%' })
          }
          .width('100%')
          .constraintSize({ minHeight: 44 })
          .padding({ left: 16, right: 16, top: 10, bottom: 10 })
          .borderWidth({ bottom: 0.5 })
          .borderColor(C_HAIR)

          Column() {
            Text(this.statusLog !== '' ? this.statusLog : '暂无日志')
              .fontSize(11.5)
              .fontColor(C_SUB)
              .width('100%')
              .height(this.isCompact ? 100 : 150)
              .textAlign(TextAlign.Start)
          }
          .width('100%')
          .padding(12)
          .backgroundColor(C_FILL)
          .borderRadius(12)
          .margin({ left: 16, right: 16, top: 10, bottom: 16 })
        } else {
          Row().height(6).width('100%')
        }
      }
      .width('100%')
      .backgroundColor(C_CARD)
      .borderRadius(16)
      .clip(true)
      .shadow({ radius: 12, color: '#0A000000', offsetX: 0, offsetY: 2 })
    }
    .width('100%')
  }

  // ── 配置管理面板 ──

  @Builder profileSheet() {
    Column() {
      Row() {
        Text('配置文件')
          .fontSize(20)
          .fontWeight(700)
          .fontColor(C_TEXT)
          .layoutWeight(1)
        Text('完成')
          .fontSize(15)
          .fontWeight(600)
          .fontColor(C_BLUE)
          .padding({ left: 8, top: 4, bottom: 4 })
          .onClick(() => { this.showSheet = false; })
      }
      .width('100%')
      .padding({ left: 20, right: 20, top: 4, bottom: 14 })

      Scroll() {
        Column() {
          // 操作
          Column() {
            this.sheetAction('导入 .conf 文件', () => { this.importConfig(); }, false)
            this.sheetAction('扫描二维码', () => { this.handleScanClick(); }, false)
            this.sheetAction('新建空白配置', () => { this.createBlankProfile(); }, true)
          }
          .width('100%')
          .backgroundColor(C_CARD)
          .borderRadius(16)
          .clip(true)
          .margin({ bottom: 18 })

          Text('全部配置')
            .fontSize(13)
            .fontColor(C_SUB)
            .width('100%')
            .padding({ left: 4, bottom: 7 })

          Column() {
            if (this.profiles.length === 0) {
              Text('还没有配置')
                .fontSize(15)
                .fontColor(C_SUB)
                .width('100%')
                .padding({ left: 16, right: 16, top: 16, bottom: 16 })
            }
            ForEach(this.profiles, (p: WgProfile, idx: number) => {
              this.sheetProfileRow(p, idx === this.profiles.length - 1)
            }, (p: WgProfile) => p.id)
          }
          .width('100%')
          .backgroundColor(C_CARD)
          .borderRadius(16)
          .clip(true)
          .padding({ bottom: 0 })
        }
        .width('100%')
        .padding({ left: 18, right: 18, bottom: 40 })
      }
      .layoutWeight(1)
      .scrollBar(BarState.Off)
      .align(Alignment.Top)
    }
    .width('100%')
    .height('100%')
    .padding({ top: 6 })
    .backgroundColor(C_BG)
  }

  @Builder sheetAction(label: string, action: () => void, last: boolean) {
    Row() {
      Text(label)
        .fontSize(16)
        .fontColor(C_BLUE)
        .layoutWeight(1)
      Text('›')
        .fontSize(17)
        .fontColor(C_DIM)
    }
    .width('100%')
    .height(50)
    .padding({ left: 16, right: 14 })
    .borderWidth({ bottom: last ? 0 : 0.5 })
    .borderColor(C_HAIR)
    .onClick(action)
  }

  @Builder sheetProfileRow(p: WgProfile, last: boolean) {
    Column() {
      if (this.editingId === p.id) {
        Row() {
          TextInput({ text: this.editingName, placeholder: '配置名称' })
            .layoutWeight(1)
            .height(38)
            .fontSize(15)
            .fontColor(C_TEXT)
            .placeholderColor(C_DIM)
            .backgroundColor(C_FILL)
            .borderRadius(9)
            .padding({ left: 10, right: 10 })
            .onChange((v: string) => { this.editingName = v; })
          Text('确定')
            .fontSize(14)
            .fontWeight(500)
            .fontColor(C_BLUE)
            .margin({ left: 12 })
            .onClick(() => { this.commitRename(p.id); })
        }
        .width('100%')
        .padding({ left: 16, right: 16, top: 8, bottom: 8 })
      } else {
        Row() {
          Column() {
            Row() {
              Text(p.name)
                .fontSize(16)
                .fontWeight(p.id === this.activeId ? 600 : 400)
                .fontColor(C_TEXT)
                .maxLines(1)
                .textOverflow({ overflow: TextOverflow.Ellipsis })
                .constraintSize({ maxWidth: 140 })
              if (p.id === this.activeId) {
                Text('使用中')
                  .fontSize(10)
                  .fontColor(C_BLUE)
                  .padding({ left: 7, right: 7, top: 2, bottom: 2 })
                  .backgroundColor(C_BLUE_SOFT)
                  .borderRadius(9)
                  .margin({ left: 7 })
              }
            }
            Text(p.serverHost !== '' ? p.serverHost + ':' + p.serverPort : '（未填写地址）')
              .fontSize(12)
              .fontColor(C_SUB)
              .maxLines(1)
              .textOverflow({ overflow: TextOverflow.Ellipsis })
              .margin({ top: 2 })
          }
          .alignItems(HorizontalAlign.Start)
          .layoutWeight(1)

          Text('改名')
            .fontSize(13)
            .fontColor(C_BLUE)
            .padding({ left: 8, right: 8, top: 6, bottom: 6 })
            .onClick(() => {
              this.editingId = p.id;
              this.editingName = p.name;
            })
          Text('删除')
            .fontSize(13)
            .fontColor(C_RED)
            .padding({ left: 6, right: 0, top: 6, bottom: 6 })
            .onClick(() => { this.confirmDelete(p); })
        }
        .width('100%')
        .padding({ left: 16, right: 16, top: 10, bottom: 10 })
        .onClick(() => {
          if (this.editingId !== p.id) {
            this.switchTo(p.id);
          }
        })
      }
    }
    .width('100%')
    .borderWidth({ bottom: last ? 0 : 0.5 })
    .borderColor(C_HAIR)
  }

  // ── 配置逻辑 ──

  private async getStore(): Promise<ProfileStore> {
    if (this.store === null) {
      const ctx: common.UIAbilityContext = getContext(this) as common.UIAbilityContext;
      this.store = new ProfileStore(ctx);
    }
    return this.store;
  }

  private async loadProfiles(): Promise<void> {
    try {
      const store: ProfileStore = await this.getStore();
      const snap: ProfileSnapshot = await store.load();
      this.profiles = snap.profiles;
      this.activeId = snap.activeId;

      if (this.profiles.length === 0) {
        const p: WgProfile = emptyProfile('我的配置');
        this.profiles = [p];
        this.activeId = p.id;
        await store.save(this.profiles, this.activeId);
        this.applyProfile(p);
      } else {
        this.applyProfile(this.findProfile(this.activeId));
        this.appendLog('已加载 ' + this.profiles.length + ' 份配置 · 虚拟 IP ' +
          (this.clientAddress !== '' ? this.clientAddress : '（空）'));
      }
      // 从这里开始表单内容才是真实配置，允许写回
      this.profilesLoaded = true;
    } catch (e) {
      hilog.error(DOMAIN, TAG, 'load profiles failed: %{public}s', JSON.stringify(e));
    }
  }

  private findProfile(id: string): WgProfile {
    for (let i: number = 0; i < this.profiles.length; i++) {
      if (this.profiles[i].id === id) {
        return this.profiles[i];
      }
    }
    return this.profiles.length > 0 ? this.profiles[0] : emptyProfile('我的配置');
  }

  private activeIndex(): number {
    for (let i: number = 0; i < this.profiles.length; i++) {
      if (this.profiles[i].id === this.activeId) {
        return i;
      }
    }
    return -1;
  }

  private activeName(): string {
    const idx: number = this.activeIndex();
    return idx >= 0 ? this.profiles[idx].name : '未选择配置';
  }

  private endpointText(): string {
    if (this.serverHost === '') {
      return '未填写地址';
    }
    return this.serverHost + ':' + this.serverPort;
  }

  private applyProfile(p: WgProfile): void {
    this.serverHost = p.serverHost;
    this.serverPort = p.serverPort;
    this.clientAddress = p.clientAddress;
    this.dnsServer = p.dnsServer;
    this.clientPrivateKey = p.clientPrivateKey;
    this.serverPublicKey = p.serverPublicKey;
    this.presharedKey = p.presharedKey;
    this.allowedIps = p.allowedIps;
    // 留一份「这次打开时的样子」，自动保存之后再点还原还能退回去
    this.baseline = this.cloneProfile(p);
  }

  private cloneProfile(p: WgProfile): WgProfile {
    return {
      id: p.id,
      name: p.name,
      serverHost: p.serverHost,
      serverPort: p.serverPort,
      clientAddress: p.clientAddress,
      dnsServer: p.dnsServer,
      clientPrivateKey: p.clientPrivateKey,
      serverPublicKey: p.serverPublicKey,
      presharedKey: p.presharedKey,
      allowedIps: p.allowedIps,
      updatedAt: p.updatedAt,
    };
  }

  private async persist(): Promise<void> {
    try {
      const store: ProfileStore = await this.getStore();
      await store.save(this.profiles, this.activeId);
    } catch (e) {
      // 以前这里只写 hilog，界面上看不出来：用户以为改了、连上也正常
      // （连接用的是内存里的表单值），可存储里还是旧值，重装/重启就打回原形。
      hilog.error(DOMAIN, TAG, 'persist failed: %{public}s', JSON.stringify(e));
      this.appendLog('保存失败：' + JSON.stringify(e));
    }
  }

  /** 把表单内容写回当前 profile */
  private async saveCurrent(): Promise<void> {
    // 配置还没加载完就写回，等于拿界面初始值覆盖真实配置（覆盖安装后
    // 首次启动、页面被系统重建都会走到这里）。等加载完再保存。
    if (!this.profilesLoaded) {
      return;
    }
    const idx: number = this.activeIndex();
    if (idx < 0) {
      return;
    }
    const p: WgProfile = this.profiles[idx];
    p.serverHost = this.serverHost.trim();
    p.serverPort = this.serverPort;
    // 虚拟 IP 不接受空值覆盖：表单还没渲染出真实地址时写回，会把
    // 10.77.0.5 这种真实地址换成空串，读回时又补成 10.0.0.2，于是
    // 服务端按 allowed-ips 把这个 peer 的包全丢了。
    const addr: string = this.clientAddress.trim();
    if (addr !== '') {
      p.clientAddress = addr;
    }
    p.dnsServer = this.dnsServer;
    p.clientPrivateKey = this.clientPrivateKey;
    p.serverPublicKey = this.serverPublicKey;
    p.presharedKey = this.presharedKey;
    p.allowedIps = this.allowedIps;
    p.updatedAt = Date.now();
    const next: WgProfile[] = this.profiles.slice();
    next[idx] = p;
    this.profiles = next;
    await this.persist();
  }

  /** 「保存修改」按钮：保存后给条回执，点了没反应最容易导致「以为存上了」 */
  private async saveFromButton(): Promise<void> {
    await this.saveCurrent();
    const p: WgProfile = this.findProfile(this.activeId);
    this.appendLog('已保存「' + p.name + '」虚拟 IP ' + (p.clientAddress !== '' ? p.clientAddress : '未填'));
  }

  /**
   * 改完就存（防抖 600ms），不再依赖用户记得点「保存修改」。
   * 以前改完直接退出、或者直接覆盖安装，进程一被杀这次修改就没了，
   * 存储里留着的还是旧值 —— 下次启动自然又回到 10.0.0.2。
   */
  private scheduleSave(): void {
    if (!this.profilesLoaded) {
      return;
    }
    if (this.saveTimer >= 0) {
      clearTimeout(this.saveTimer);
    }
    this.saveTimer = setTimeout(() => {
      this.saveTimer = -1;
      this.saveCurrent();
    }, 600);
  }

  private async switchTo(id: string): Promise<void> {
    if (id === this.activeId) {
      this.showSheet = false;
      return;
    }
    await this.saveCurrent();
    const p: WgProfile = this.findProfile(id);
    this.activeId = p.id;
    this.applyProfile(p);
    await this.persist();
    this.showSheet = false;
    this.appendLog('切换配置：' + p.name);
    if (this.isConnected) {
      this.appendLog('提示：当前隧道仍使用旧参数，需重新连接');
    }
  }

  private async addProfile(p: WgProfile): Promise<void> {
    await this.saveCurrent();
    this.profiles = this.profiles.concat([p]);
    this.activeId = p.id;
    this.applyProfile(p);
    await this.persist();
  }

  private async createBlankProfile(): Promise<void> {
    const p: WgProfile = emptyProfile(this.uniqueName('新配置'));
    await this.addProfile(p);
    this.showSheet = false;
    this.showParams = true;
    this.appendLog('已新建空白配置：' + p.name);
  }

  private uniqueName(base: string): string {
    let name: string = base;
    let n: number = 2;
    while (true) {
      let dup: boolean = false;
      for (let i: number = 0; i < this.profiles.length; i++) {
        if (this.profiles[i].name === name) {
          dup = true;
          break;
        }
      }
      if (!dup) {
        return name;
      }
      name = base + ' ' + n;
      n++;
    }
  }

  private commitRename(id: string): void {
    const name: string = this.editingName.trim();
    if (name === '') {
      this.editingId = '';
      return;
    }
    for (let i: number = 0; i < this.profiles.length; i++) {
      if (this.profiles[i].id === id) {
        const next: WgProfile[] = this.profiles.slice();
        const p: WgProfile = next[i];
        p.name = name;
        p.updatedAt = Date.now();
        next[i] = p;
        this.profiles = next;
        break;
      }
    }
    this.editingId = '';
    this.persist();
  }

  private confirmDelete(p: WgProfile): void {
    AlertDialog.show({
      title: '删除配置',
      message: '确定删除「' + p.name + '」？该操作不可撤销。',
      autoCancel: true,
      primaryButton: {
        value: '取消',
        action: () => {},
      },
      secondaryButton: {
        value: '删除',
        fontColor: C_RED,
        action: () => { this.deleteProfile(p.id); },
      },
    });
  }

  private async deleteProfile(id: string): Promise<void> {
    const kept: WgProfile[] = [];
    for (let i: number = 0; i < this.profiles.length; i++) {
      if (this.profiles[i].id !== id) {
        kept.push(this.profiles[i]);
      }
    }
    this.profiles = kept;
    if (this.activeId === id) {
      if (kept.length > 0) {
        this.activeId = kept[0].id;
        this.applyProfile(kept[0]);
      } else {
        const p: WgProfile = emptyProfile('我的配置');
        this.profiles = [p];
        this.activeId = p.id;
        this.applyProfile(p);
      }
    }
    await this.persist();
    this.appendLog('已删除配置');
  }

  private async resetForm(): Promise<void> {
    const idx: number = this.activeIndex();
    if (idx < 0) {
      return;
    }
    // 现在改动会自动存盘，「还原」得同时把基线写回去才算真的撤销
    if (this.baseline !== null) {
      this.applyProfile(this.baseline);
    } else {
      this.applyProfile(this.profiles[idx]);
    }
    await this.saveCurrent();
    this.appendLog('已还原到本次打开时的配置');
  }

  // ── 连接 / 断开 ──

  private async toggleVpn(): Promise<void> {
    if (this.busy) {
      return;
    }
    if (this.isConnected) {
      await this.disconnectVpn();
    } else {
      await this.connectVpn();
    }
  }

  private async connectVpn(): Promise<void> {
    if (!this.serverHost) {
      this.appendLog('错误：请输入服务端地址');
      this.statusText = '缺少服务端地址';
      this.showParams = true;
      return;
    }
    // 虚拟 IP 必须来自配置本身：它要和服务器上这个 peer 的 AllowedIPs 一致，
    // 空着就连接只会得到「握手成功但一个字节都进不来」，不如在这里拦住。
    if (this.clientAddress.trim() === '') {
      this.appendLog('错误：请填写虚拟 IP（要和服务器上该 peer 的 AllowedIPs 一致）');
      this.statusText = '缺少虚拟 IP';
      this.showParams = true;
      return;
    }
    if (this.allowedIps.trim() === '') {
      this.appendLog('错误：请填写分流网段（AllowedIPs），例如 0.0.0.0/0');
      this.statusText = '缺少分流网段';
      this.showParams = true;
      return;
    }
    const port: number = parseInt(this.serverPort);
    if (isNaN(port) || port < 1 || port > 65535) {
      this.appendLog('错误：端口号无效（1-65535）');
      this.statusText = '端口无效';
      this.showParams = true;
      return;
    }

    this.busy = true;
    this.statusText = '正在连接…';
    this.connectAt = Date.now();
    this.appendLog('连接 ' + this.serverHost + ':' + this.serverPort +
      '（' + this.activeName() + '）');
    await this.saveCurrent();

    try {
      let serverIP: string = this.serverHost;
      if (this.serverHost.indexOf('.') >= 0 && !isIP(this.serverHost)) {
        try {
          const addrs: connection.NetAddress[] = await connection.getAddressesByName(this.serverHost);
          if (addrs && addrs.length > 0) {
            serverIP = addrs[0].address;
            this.appendLog('域名解析：' + this.serverHost + ' → ' + serverIP);
          }
        } catch (dnsErr) {
          this.appendLog('DNS 解析失败，使用原始域名');
        }
      }

      const want: Want = {
        deviceId: '',
        bundleName: 'com.lianhui.wireguard',
        abilityName: 'WireGuardVpnExt',
        parameters: {
          'serverHost': this.serverHost,
          'serverIP': serverIP,
          'serverPort': port,
          'clientAddress': this.clientAddress,
          'dnsServer': this.dnsServer,
        },
      };
      if (this.clientPrivateKey) {
        want.parameters!['clientPrivateKey'] = this.clientPrivateKey;
      }
      if (this.serverPublicKey) {
        want.parameters!['serverPublicKey'] = this.serverPublicKey;
      }
      if (this.presharedKey) {
        want.parameters!['presharedKey'] = this.presharedKey;
      }
      if (this.allowedIps) {
        want.parameters!['allowedIps'] = this.allowedIps;
      }

      await vpnExtension.startVpnExtensionAbility(want);
      // 扩展被拉起 ≠ 隧道已通。这里只把按钮切成「已激活」，真正的状态由
      // refreshStats 从统计文件回填（handshakes>0 才算真的连上），
      // 否则会出现「显示已连接但上不了网」的假象。
      this.isConnected = true;
      this.statusText = '握手中…';
      this.handshakes = 0;
      this.appendLog('VPN 扩展已启动，等待握手');
      // 速率采样从连接成功那一刻重新开始
      this.rxSpeed = 0;
      this.txSpeed = 0;
      this.prevRx = 0;
      this.prevTx = 0;
      this.prevAt = 0;
      this.startDiagTimer();
      this.refreshStats(false);
    } catch (e) {
      this.statusText = '连接失败';
      this.appendLog('启动失败：' + JSON.stringify(e));
    } finally {
      this.busy = false;
    }
  }

  private async disconnectVpn(): Promise<void> {
    this.busy = true;
    this.statusText = '正在断开…';
    this.appendLog('正在停止 VPN…');
    try {
      const want: Want = {
        deviceId: '',
        bundleName: 'com.lianhui.wireguard',
        abilityName: 'WireGuardVpnExt',
      };
      await vpnExtension.stopVpnExtensionAbility(want);
      this.connectAt = 0;
      this.isConnected = false;
      this.statusText = '已断开';
      this.appendLog('VPN 已停止');
      this.stopDiagTimer();
      this.resetSpeeds();
    } catch (e) {
      this.appendLog('停止失败：' + JSON.stringify(e));
      this.statusText = '断开失败';
    } finally {
      this.busy = false;
    }
  }

  // ── 统计 / 诊断 ──

  private startDiagTimer(): void {
    if (this.diagTimer >= 0) {
      return;
    }
    this.diagTimer = setInterval((): void => {
      this.refreshStats(true);
    }, 2000);
  }

  private stopDiagTimer(): void {
    if (this.diagTimer >= 0) {
      clearInterval(this.diagTimer);
      this.diagTimer = -1;
    }
  }

  private resetSpeeds(): void {
    this.rxSpeed = 0;
    this.txSpeed = 0;
    this.prevRx = 0;
    this.prevTx = 0;
    this.prevAt = 0;
  }

  private statsPath(): string {
    const ctx: common.UIAbilityContext = getContext(this) as common.UIAbilityContext;
    return ctx.getApplicationContext().filesDir + '/' + STATS_FILE_NAME;
  }

  /**
   * 读扩展写的统计文件。
   * reconcile=true 时顺带校准连接状态（扩展被杀掉时按钮要能自己弹回「连接」）。
   * 速率 = 相邻两次采样的字节差 / 时间差，再做一次指数平滑避免读数跳动。
   */
  private refreshStats(reconcile: boolean): void {
    let st: TunnelStats;
    try {
      const path: string = this.statsPath();
      if (!fileIo.accessSync(path)) {
        return;
      }
      st = JSON.parse(fileIo.readTextSync(path)) as TunnelStats;
    } catch (e) {
      return;
    }

    /*
     * 只认本轮的统计。上一轮断开时留下的那份，时间戳早于 connectAt，里面的
     * handshakes 是上一次的旧值——回填进来就会让按钮先亮「已连接」，等宽限期
     * 过了又被打回「未连接」，再等扩展真正写出统计才又变「已连接」。这就是
     * 「已连接 → 未连接 → 已连接」三连闪的来源，所以旧统计一个字段都不采信。
     */
    if (!this.isOwnStats(st)) {
      // 宽限期内安静等扩展起身（启动慢时不闪），超时才认定这次没起来
      if (reconcile && this.connectAt > 0 &&
        Date.now() - this.connectAt > CONNECT_GRACE_MS) {
        this.isConnected = false;
        this.statusText = '未连接';
        this.handshakes = 0;
        this.resetSpeeds();
        this.connectAt = 0;
      }
      return;
    }

    this.txBytes = st.txBytes;
    this.rxBytes = st.rxBytes;
    this.handshakes = st.handshakes;
    this.rekeys = st.rekeys;

    // 速率采样
    const now: number = Date.now();
    if (this.prevAt > 0 && now > this.prevAt) {
      const dt: number = (now - this.prevAt) / 1000;
      if (dt >= 0.5) {
        const instRx: number = Math.max(0, (st.rxBytes - this.prevRx) / dt);
        const instTx: number = Math.max(0, (st.txBytes - this.prevTx) / dt);
        this.rxSpeed = this.rxSpeed * 0.4 + instRx * 0.6;
        this.txSpeed = this.txSpeed * 0.4 + instTx * 0.6;
      }
    }
    this.prevRx = st.rxBytes;
    this.prevTx = st.txBytes;
    this.prevAt = now;

    const age: number = Date.now() - st.updatedAt;
    const fresh: boolean = st.updatedAt > 0 && age < STATS_STALE_MS;

    const lines: string[] = [];
    lines.push(st.connected ? '隧道已建立' : '握手中');
    lines.push('丢包 ' + (st.txDrops + st.rxDrops) + ' / 解密错误 ' + st.decryptErrors);
    lines.push('运行 ' + this.fmtDuration(st.uptimeMs));
    if (st.handshakes > 0 && st.lastHandshakeAgeMs >= 0) {
      lines.push('上次握手 ' + this.fmtDuration(st.lastHandshakeAgeMs) + '前');
    }
    this.diagText = lines.join(' · ');

    if (!reconcile) {
      return;
    }
    if (fresh && st.running) {
      this.isConnected = true;
      this.statusText = st.connected ? '已连接' : '握手中';
    } else if (this.connectAt > 0 && Date.now() - this.connectAt < CONNECT_GRACE_MS) {
      // 本轮统计已写出但刚过期：多半是扩展正好在重启引擎/写盘撞车。
      // 宽限期内保持「握手中」等下一拍，别在这一瞬间把按钮打回「未连接」。
      this.isConnected = true;
      this.statusText = '握手中';
    } else {
      this.isConnected = false;
      this.statusText = '未连接';
      this.connectAt = 0;
      this.resetSpeeds();
      // 不停轮询：网络切换时扩展会原地重启引擎，统计文件有 1-2 秒过期，
      // 停了轮询就再也回不到「已连接」。用户主动断开时才 stopDiagTimer。
    }
  }

  /**
   * 这份统计是不是「本轮」写的。
   * 冷启动（connectAt=0）没有本轮可言，按文件内容判断隧道是否还在跑。
   */
  private isOwnStats(st: TunnelStats): boolean {
    if (this.connectAt <= 0) {
      return true;
    }
    if (!Number.isFinite(st.updatedAt) || st.updatedAt <= 0) {
      return false;
    }
    return st.updatedAt + STATS_CLOCK_SLACK_MS >= this.connectAt;
  }

  /** 秒 → 「x分x秒」/「x秒」 */
  private fmtDuration(ms: number): string {
    const s: number = Math.floor(ms / 1000);
    if (s < 60) {
      return s + 's';
    }
    const m: number = Math.floor(s / 60);
    return m + '分' + (s % 60) + 's';
  }

  private fmtBytes(n: number): string {
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    if (n < 1024 * 1024 * 1024) return (n / 1024 / 1024).toFixed(2) + ' MB';
    return (n / 1024 / 1024 / 1024).toFixed(2) + ' GB';
  }

  private fmtSpeed(n: number): string {
    if (n <= 0) return '0 KB/s';
    if (n < 1024) return Math.round(n) + ' B/s';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB/s';
    return (n / 1024 / 1024).toFixed(2) + ' MB/s';
  }

  // ── 日志 ──

  private appendLog(msg: string): void {
    const now = new Date();
    const time = now.getHours().toString().padStart(2, '0') + ':' +
      now.getMinutes().toString().padStart(2, '0') + ':' +
      now.getSeconds().toString().padStart(2, '0');
    this.statusLog = '[' + time + '] ' + msg + '\n' + this.statusLog;
    if (this.statusLog.length > 2000) {
      this.statusLog = this.statusLog.substring(0, 2000);
    }
  }

  // ── 导入 / 扫码 ──

  private async importConfig(): Promise<void> {
    try {
      const context: common.UIAbilityContext = getContext(this) as common.UIAbilityContext;
      const documentPicker: picker.DocumentViewPicker = new picker.DocumentViewPicker(context);

      // 允许一次选多份 .conf，每份都存成独立配置
      const options: picker.DocumentSelectOptions = {
        fileSuffixFilters: ['.conf', '.wg', '.txt'],
        maxSelectNumber: 10,
      };

      const uris: string[] = await documentPicker.select(options);
      if (!uris || uris.length === 0) {
        this.appendLog('已取消选择文件');
        return;
      }

      let imported: number = 0;
      for (let i: number = 0; i < uris.length; i++) {
        const uri: string = uris[i];
        try {
          const content: string = await this.readUriText(uri);
          if (content.trim() === '') {
            continue;
          }
          const config: WgParsedConfig = parseWgConfig(content);
          if (!config.serverHost) {
            this.appendLog('跳过（无 Endpoint）：' + this.baseName(uri));
            continue;
          }
          const name: string = this.uniqueName(this.nameFor(config, this.baseName(uri)));
          const p: WgProfile = emptyProfile(name);
          p.serverHost = config.serverHost;
          p.serverPort = config.serverPort;
          p.clientAddress = config.clientAddress;
          p.dnsServer = config.dnsServer;
          p.clientPrivateKey = config.privateKey || '';
          p.serverPublicKey = config.publicKey || '';
          p.presharedKey = config.presharedKey || '';
          p.allowedIps = config.allowedIPs !== undefined ? config.allowedIPs : '';
          await this.addProfile(p);
          imported++;
          this.appendLog('已导入「' + name + '」 ' + p.serverHost + ':' + p.serverPort);
          if (p.clientAddress === '') {
            this.appendLog('注意：「' + name + '」的配置文件里没有 Address，请在「虚拟 IP」里填服务端分配给它的地址');
          }
        } catch (fileErr) {
          this.appendLog('读取失败：' + this.baseName(uri));
        }
      }

      if (imported > 0) {
        this.showSheet = false;
        this.statusText = '已导入 ' + imported + ' 份配置';
      }
    } catch (e) {
      const errMsg: string = JSON.stringify(e);
      this.appendLog('导入失败：' + errMsg);
      hilog.error(DOMAIN, TAG, '导入失败: %{public}s', errMsg);
    }
  }

  private async readUriText(uri: string): Promise<string> {
    const file: fileIo.File = await fileIo.open(uri, fileIo.OpenMode.READ_ONLY);
    const chunks: string[] = [];
    const buf: ArrayBuffer = new ArrayBuffer(8192);
    try {
      while (true) {
        const n: number = await fileIo.read(file.fd, buf);
        if (n <= 0) {
          break;
        }
        const bytes: Uint8Array = new Uint8Array(buf.slice(0, n));
        let s: string = '';
        for (let i: number = 0; i < bytes.length; i++) {
          s += String.fromCharCode(bytes[i]);
        }
        chunks.push(s);
      }
    } finally {
      fileIo.closeSync(file);
    }
    return chunks.join('');
  }

  private baseName(uri: string): string {
    const slash: number = uri.lastIndexOf('/');
    const raw: string = slash >= 0 ? uri.substring(slash + 1) : uri;
    const dot: number = raw.lastIndexOf('.');
    return dot > 0 ? raw.substring(0, dot) : raw;
  }

  private nameFor(config: WgParsedConfig, fallback: string): string {
    if (config.serverHost !== '') {
      return config.serverHost;
    }
    return fallback !== '' ? fallback : '导入的配置';
  }

  private handleScanClick(): void {
    try {
      this.showSheet = false;
      router.pushUrl({ url: 'pages/ScanPage' });
    } catch (e) {
      this.appendLog('扫码页面跳转失败：' + JSON.stringify(e));
    }
  }

  private checkScanResult(): void {
    const scanResult: string | undefined = AppStorage.Get<string>('scanResult');
    if (scanResult) {
      this.applyScanResult(scanResult);
      AppStorage.Delete('scanResult');
    }
  }

  private async applyScanResult(text: string): Promise<void> {
    let content: string = text;
    if (text.startsWith('wireguard://')) {
      const encoded: string = text.substring('wireguard://'.length);
      try {
        content = decodeURIComponent(encoded);
      } catch (e) {
        content = text;
      }
    }
    const config: WgParsedConfig = parseWgConfig(content);
    if (!config.serverHost) {
      this.appendLog('扫码内容不是有效的 WireGuard 配置');
      return;
    }
    const name: string = this.uniqueName(this.nameFor(config, '扫码配置'));
    const p: WgProfile = emptyProfile(name);
    p.serverHost = config.serverHost;
    p.serverPort = config.serverPort;
    p.clientAddress = config.clientAddress;
    p.dnsServer = config.dnsServer;
    p.clientPrivateKey = config.privateKey || '';
    p.serverPublicKey = config.publicKey || '';
    p.presharedKey = config.presharedKey || '';
    p.allowedIps = config.allowedIPs !== undefined ? config.allowedIPs : '';
    await this.addProfile(p);
    this.appendLog('扫码已新增配置「' + name + '」');
    if (p.clientAddress === '') {
      this.appendLog('注意：扫码内容里没有 Address，请在「虚拟 IP」里填服务端分配给它的地址');
    }
  }
}
