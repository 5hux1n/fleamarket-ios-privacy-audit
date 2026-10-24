# 闲鱼 iOS 客户端 URL Scheme 扫描完整对照清单

> 这是 `Info.plist` 白名单与运行时实测的完整对照。冷启动无交互时段的 75ms 突发探测窗口内，App 对其中绝大部分（共 50 个）Scheme 依次进行了批量探测。

## 探测概览

* **Info.plist 白名单总数**：50 个
* **运行时实测探测总数**：50 个
* **实测重合率**：100%

---

## 详细分类清单

### 1. 短视频 / 内容与资讯平台 (10 个)

| Scheme | 对应 App / SDK | 运行时实测 | 探测时序偏移 (ms) |
| :--- | :--- | :---: | :--- |
| `snssdk141://` | 今日头条 (Toutiao) | ✓ | +0 |
| `snssdk35://` | 西瓜视频 (Xigua Video) | ✓ | +4 |
| `baiduboxapp://` | 百度 App (Baidu) | ✓ | +9 |
| `imrocketshare://` | 多闪 (Duoshan) | ✓ | +16 |
| `feiliao1394://` | 飞聊 (Feiliao) | ✓ | +18 |
| `douyinopensdk://` | 抖音开放平台 SDK | ✓ | +67 |
| `douyinliteopensdk://` | 抖音极速版 SDK | ✓ | +68 |
| `douyinsharesdk://` | 抖音分享 SDK | ✓ | +69 |
| `snssdk1128://` | 抖音 (Douyin) | ✓ | +70 |
| `xhsdiscover://` | 小红书 (Xiaohongshu) | ✓ | +71 |

### 2. 社交平台与即时通讯 (17 个)

| Scheme | 对应 App / SDK | 运行时实测 | 探测时序偏移 (ms) |
| :--- | :--- | :---: | :--- |
| `weixin://` | 微信 (WeChat) | ✓ | +33 |
| `weixinULAPI://` | 微信 Universal Links API | ✓ | +35 |
| `weixinURLParamsAPI://` | 微信 URL 参数 API | ✓ | +36 |
| `mqq://` | 手机 QQ | ✓ | +38 |
| `mqzone://` | QQ 空间 (Qzone) | ✓ | +40 |
| `mqqopensdkapiV2://` | QQ 开放平台 SDK V2 | ✓ | +41 |
| `mqqopensdkapiV4://` | QQ 开放平台 SDK V4 | ✓ | +43 |
| `mqqapi://` | QQ API 通讯协议 | ✓ | +44 |
| `laiwangsso://` | 来往 (Laiwang) SSO | ✓ | +46 |
| `sina://` | 新浪客户端 | ✓ | +47 |
| `sinaweibo://` | 新浪微博 (Weibo) | ✓ | +47 |
| `sinaweibohd://` | 新浪微博 HD | ✓ | +48 |
| `sinaweibosso://` | 新浪微博 SSO 登录 | ✓ | +50 |
| `weibosdk://` | 微博 SDK | ✓ | +51 |
| `weibosdk2.5://` | 微博 SDK 2.5 | ✓ | +52 |
| `dingtalk://` | 钉钉 (DingTalk) | ✓ | +60 |
| `dingtalk-open://` | 钉钉开放平台 | ✓ | +61 |

### 3. 电商与生活服务 (13 个)

| Scheme | 对应 App / SDK | 运行时实测 | 探测时序偏移 (ms) |
| :--- | :--- | :---: | :--- |
| `taobaoliveshare://` | 淘宝直播分享 | ✓ | +15 |
| `tbopen://` | 淘宝开放平台 (TBOpen) | ✓ | +21 |
| `tmall://` | 手机天猫 (Tmall) | ✓ | +25 |
| `jhs://` | 聚划算 | ✓ | +27 |
| `tbmovie://` | 淘票票 (Tao Piao Piao) | ✓ | +28 |
| `xiami://` | 虾米音乐 (Xiami) | ✓ | +30 |
| `taobao://` | 手机淘宝 (Taobao) | ✓ | +57 |
| `taobaosso2016://` | 淘宝 SSO 登录协议 | ✓ | +59 |
| `taobaotravel://` | 飞猪旅行 (Fliggy) | ✓ | +63 |
| `koubei://` | 口碑 (Koubei) | ✓ | +64 |
| `eleme://` | 饿了么 (Ele.me) | ✓ | +72 |
| `tongyi://` | 通义千问 (Tongyi AI) | ✓ | +73 |
| `wireless1688://` | 阿里巴巴 1688 | ✓ | +75 |

### 4. 支付与网络身份认证 (6 个)

| Scheme | 对应 App / SDK | 运行时实测 | 探测时序偏移 (ms) |
| :--- | :--- | :---: | :--- |
| `cyberidentity://` | 网络电子身份认证 (CTID) | ✓ | +13 |
| `alicertpay://` | 支付宝证书支付 | ✓ | +31 (及启动初期) |
| `alipay://` | 支付宝 (Alipay) | ✓ | +53 (及启动初期) |
| `alipays://` | 支付宝安全协议 | ✓ | +55 |
| `alipayauthtb://` | 支付宝淘宝免密授权 | ✓ | +56 |
| `alipayshare://` | 支付宝社交分享 | ✓ | +58 |

### 5. 地图导航 (3 个)

| Scheme | 对应 App / SDK | 运行时实测 | 探测时序偏移 (ms) |
| :--- | :--- | :---: | :--- |
| `iosamap://` | 高德地图 (AMap) | ✓ | +23 |
| `baidumap://` | 百度地图 (Baidu Map) | ✓ | +65 |
| `qqmap://` | 腾讯地图 (Tencent Map) | ✓ | +66 |

### 6. 系统与应用分发 (1 个)

| Scheme | 对应 App / SDK | 运行时实测 | 探测时序偏移 (ms) |
| :--- | :--- | :---: | :--- |
| `itmss://` | Apple iTunes Store / itms-services | ✓ | +62 |
