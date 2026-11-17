import { AbilityConstant, UIAbility, Want } from '@kit.AbilityKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { window } from '@kit.ArkUI';

const DOMAIN = 0x0000;

export default class EntryAbility extends UIAbility {
  onCreate(want: Want, launchParam: AbilityConstant.LaunchParam): void {
    hilog.info(DOMAIN, 'WgClient', 'Ability onCreate');
  }

  onDestroy(): void {
    hilog.info(DOMAIN, 'WgClient', 'Ability onDestroy');
  }

  onWindowStageCreate(windowStage: window.WindowStage): void {
    hilog.info(DOMAIN, 'WgClient', 'Ability onWindowStageCreate');
    windowStage.loadContent('pages/Index');

    // 状态栏 / 导航栏跟随浅色分组底色，深色图标，避免顶部出现一块系统灰
    try {
      const win: window.Window = windowStage.getMainWindowSync();
      win.setWindowSystemBarProperties({
        statusBarColor: '#F2F2F7',
        statusBarContentColor: '#000000',
        navigationBarColor: '#F2F2F7',
        navigationBarContentColor: '#000000',
      });
    } catch (err) {
      hilog.warn(DOMAIN, 'WgClient', 'setWindowSystemBarProperties failed: %{public}s',
        JSON.stringify(err));
    }
  }

  onWindowStageDestroy(): void {
    hilog.info(DOMAIN, 'WgClient', 'Ability onWindowStageDestroy');
  }

  onForeground(): void {
    hilog.info(DOMAIN, 'WgClient', 'Ability onForeground');
  }

  onBackground(): void {
    hilog.info(DOMAIN, 'WgClient', 'Ability onBackground');
  }
}
