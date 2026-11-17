/**
 * QR 码扫描页面 —— 浅色 iOS 风格
 * - 系统原生相机扫码（ScanKit startScanForResult）
 * - 相册选图扫码
 */

import { common } from '@kit.AbilityKit';
import { image } from '@kit.ImageKit';
import { picker } from '@kit.CoreFileKit';
import { router } from '@kit.ArkUI';
import { scanBarcode, scanCore } from '@kit.ScanKit';
import { decodeQrCode, PixelData } from '../utils/QrDecoder';
import { BusinessError, pasteboard as pasteboardNs } from '@kit.BasicServicesKit';

const C_BG: string = '#F2F2F7';
const C_CARD: string = '#FFFFFF';
const C_FILL: string = '#EFEFF4';
const C_HAIR: string = '#E4E4E9';
const C_TEXT: string = '#111114';
const C_SUB: string = '#8A8A8E';
const C_DIM: string = '#C3C3C8';
const C_BLUE: string = '#007AFF';
const C_BLUE_SOFT: string = '#EAF2FF';
const C_GREEN: string = '#34C759';

@Entry
@Component
struct ScanPage {
  @State statusMsg: string = '选择扫码方式';
  @State scanResult: string = '';
  @State decoded: boolean = false;

  private scanOptions: scanBarcode.ScanOptions = {
    scanTypes: [scanCore.ScanType.ALL],
    enableMultiMode: false,
    enableAlbum: false,
  };

  build() {
    Column() {
      // 导航栏
      Row() {
        Text('返回')
          .fontSize(16)
          .fontColor(C_BLUE)
          .padding({ right: 12, top: 6, bottom: 6 })
          .onClick(() => { router.back(); })
        Blank()
        Text('扫码导入')
          .fontSize(17)
          .fontWeight(600)
          .fontColor(C_TEXT)
        Blank()
        Text('返回')
          .fontSize(16)
          .fontColor(Color.Transparent)
          .padding({ left: 12, top: 6, bottom: 6 })
      }
      .width('100%')
      .padding({ top: 8, bottom: 8, left: 16, right: 16 })

      Scroll() {
        Column() {
          // 取景框
          Column() {
            Stack() {
              Column()
                .width(196)
                .height(196)
                .backgroundColor(this.decoded ? '#EAF9EE' : C_BLUE_SOFT)
                .borderRadius(22)
                .border({ width: 2, color: this.decoded ? C_GREEN : C_BLUE })

              // 四角标记，比整圈描边更像取景器
              Text(this.decoded ? '✓' : '⌗')
                .fontSize(this.decoded ? 62 : 44)
                .fontWeight(300)
                .fontColor(this.decoded ? C_GREEN : C_BLUE)
            }
            .width(196)
            .height(196)

            Text(this.statusMsg)
              .fontSize(14)
              .fontColor(C_SUB)
              .margin({ top: 18 })
              .textAlign(TextAlign.Center)

            Text('把二维码放进框内，或直接从相册选一张')
              .fontSize(12)
              .fontColor(C_DIM)
              .margin({ top: 6 })
              .textAlign(TextAlign.Center)
          }
          .width('100%')
          .padding({ top: 34, bottom: 30 })
          .backgroundColor(C_CARD)
          .borderRadius(24)
          .shadow({ radius: 14, color: '#0D000000', offsetX: 0, offsetY: 3 })

          // 解码结果
          if (this.scanResult) {
            Column() {
              Row() {
                Text('已识别')
                  .fontSize(13)
                  .fontWeight(500)
                  .fontColor(C_GREEN)
                  .layoutWeight(1)
                Text('复制')
                  .fontSize(13)
                  .fontColor(C_BLUE)
                  .onClick(() => { this.copyConfig(); })
              }
              .width('100%')
              .margin({ bottom: 8 })

              Text(this.scanResult)
                .fontSize(12)
                .fontColor(C_SUB)
                .width('100%')
                .maxLines(8)
                .textOverflow({ overflow: TextOverflow.Ellipsis })
            }
            .width('100%')
            .padding(14)
            .backgroundColor(C_CARD)
            .borderRadius(16)
            .margin({ top: 14 })
            .shadow({ radius: 10, color: '#0A000000', offsetX: 0, offsetY: 2 })
          }
        }
        .width('100%')
        .constraintSize({ maxWidth: 620 })
      }
      .layoutWeight(1)
      .scrollBar(BarState.Off)
      .align(Alignment.Top)

      // 底部操作
      Column() {
        Button('相机扫码')
          .width('100%')
          .height(50)
          .fontSize(16)
          .fontWeight(600)
          .fontColor('#FFFFFF')
          .backgroundColor(C_BLUE)
          .borderRadius(14)
          .onClick(() => { this.startScan(); })

        Button('从相册选择')
          .width('100%')
          .height(50)
          .fontSize(16)
          .fontColor(C_BLUE)
          .backgroundColor(C_CARD)
          .borderRadius(14)
          .margin({ top: 10 })
          .onClick(() => { this.pickFromAlbum(); })

        if (this.scanResult) {
          Button('使用此配置')
            .width('100%')
            .height(50)
            .fontSize(16)
            .fontWeight(600)
            .fontColor('#FFFFFF')
            .backgroundColor(C_GREEN)
            .borderRadius(14)
            .margin({ top: 10 })
            .onClick(() => {
              AppStorage.setOrCreate<string>('scanResult', this.scanResult);
              router.back();
            })
        }
      }
      .width('100%')
      .constraintSize({ maxWidth: 620 })
      .padding({ left: 18, right: 18, top: 10, bottom: 20 })
    }
    .width('100%')
    .height('100%')
    .alignItems(HorizontalAlign.Center)
    .backgroundColor(C_BG)
  }

  private copyConfig(): void {
    try {
      const pasteboard = pasteboardNs.getSystemPasteboard();
      const data = pasteboardNs.createData(pasteboardNs.MIMETYPE_TEXT_PLAIN, this.scanResult);
      pasteboard.setData(data).then(() => {
        this.statusMsg = '配置已复制到剪贴板';
      }).catch(() => {});
    } catch (e) {
      // 复制失败不影响主流程
    }
  }

  // ── 系统原生相机扫码 ──

  private async startScan(): Promise<void> {
    try {
      this.statusMsg = '正在打开扫码...';
      const context: common.UIAbilityContext = getContext(this) as common.UIAbilityContext;
      const result: scanBarcode.ScanResult =
        await scanBarcode.startScanForResult(context, this.scanOptions);

      this.scanResult = result.originalValue;
      this.statusMsg = '扫码成功';
      this.decoded = true;
    } catch (err) {
      const bizErr: BusinessError = err as BusinessError;
      if (bizErr.code === 1000500002) {
        this.statusMsg = '扫码已取消';
      } else {
        this.statusMsg = '扫码失败，请用相册选图';
      }
    }
  }

  // ── 相册选图扫码 ──

  private async pickFromAlbum(): Promise<void> {
    try {
      const context: common.UIAbilityContext = getContext(this) as common.UIAbilityContext;
      const docPicker: picker.DocumentViewPicker = new picker.DocumentViewPicker(context);
      const uris: string[] = await docPicker.select({
        fileSuffixFilters: ['.jpg', '.jpeg', '.png', '.bmp'],
        maxSelectNumber: 1,
      });

      if (!uris || uris.length === 0) {
        this.statusMsg = '已取消选择';
        return;
      }

      this.statusMsg = '正在解码...';
      await this.decodeImage(uris[0]);
    } catch (err) {
      this.statusMsg = '选图失败';
    }
  }

  private async decodeImage(uri: string): Promise<void> {
    try {
      const imageSource: image.ImageSource = image.createImageSource(uri);
      const pixelMap: image.PixelMap = await imageSource.createPixelMap({
        desiredPixelFormat: image.PixelMapFormat.RGBA_8888,
        desiredSize: { width: 800, height: 800 },
      });

      const info: image.ImageInfo = await pixelMap.getImageInfo();
      const bufferSize: number = info.size.width * info.size.height * 4;
      const dst: ArrayBuffer = new ArrayBuffer(bufferSize);
      await pixelMap.readPixelsToBuffer(dst);

      const pixelData: PixelData = {
        width: info.size.width,
        height: info.size.height,
        data: new Uint8Array(dst),
      };

      const qrResult = decodeQrCode(pixelData);
      pixelMap.release();
      imageSource.release();

      if (qrResult.success) {
        this.scanResult = qrResult.text;
        this.statusMsg = 'QR 码解码成功';
        this.decoded = true;
      } else {
        this.statusMsg = qrResult.error || '未找到有效 QR 码';
      }
    } catch (err) {
      this.statusMsg = '解码失败';
    }
  }
}
