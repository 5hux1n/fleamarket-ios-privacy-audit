# 敏感与特征文件路径审计清单

> 说明：本清单基于动态插桩工具捕获的 `fm_audit.json` 中 `jailbreak`、`file_write`、`file_read` 调用记录筛选整理。
> 过滤常规静态资源（如 `ImageLibCache` 图片缓存、常规系统框架动态库读取），仅保留具备明确安全、隐私或设备指纹分析价值的特征路径。
> 路径中的真实沙盒容器 UUID 均已脱敏统一替换为 `<UUID>`。

---

## 1. 越狱与运行环境探测路径

App 通过底层 `stat` / `access` / `open` 系统调用主动探测以下系统敏感路径是否存在，用于评估设备越狱状态与环境可信度：

| 探测路径 | 命中次数 | 检测方式 | 性质说明 |
| :--- | :---: | :--- | :--- |
| `/bin/ssh` | 12 | 文件存在性检测 | 探测 OpenSSH 守护进程/客户端是否存在 |
| `/Applications/Cydia.app` | 4 | 目录存在性检测 | 探测经典 Cydia 越狱包管理器主应用 |
| `/private/var/lib/apt/` | 4 | 目录存在性检测 | 探测 Debian APT 高级包管理器数据库目录 |
| `Applications/Cydia.app` | 4 | 相对路径探测 | 针对无根（Rootless）或 chroot 隔离环境的变体探测 |

---

## 2. 向沙盒外尝试写入 (越狱探测)

| 目标文件路径 | 命中次数 | 操作类型 | 性质说明 |
| :--- | :---: | :--- | :--- |
| `/private/umTest_Jailbreak.txt` | 2 | `open` (O_CREAT / O_RDWR) | **越狱探测手段**：友盟 SDK 尝试向沙盒外的系统保护目录 `/private/` 写入测试文件。未越狱环境下该调用会被内核直接拦截（EPERM）；若写入成功，则判定系统沙盒限制已失效（即设备处于越狱状态）。 |

---

## 3. 关键敏感持久化与框架数据读写

| 目标数据路径 (脱敏) | 命中次数 | 归属组件 | 性质说明 |
| :--- | :---: | :--- | :--- |
| `Keychain: vimei / vimsi / udid` | 6+ | 闲鱼自建虚拟指纹 | 存入系统 Keychain 隔离区，持久化 15 位伪随机设备串号，供跨安装追踪使用。 |
| `/private/var/mobile/Containers/Data/Application/<UUID>/Documents/MNNRTModels/...` | 498 | 阿里 MNN 端侧推理引擎 | 包含 `idlefish_feeds_root_trigger_feature` 等端侧机器学习模型与条件规则库，用于本地用户行为分析与实时特征抽取。 |
| `/private/var/mobile/Containers/Data/Application/<UUID>/Documents/SGDocuments/...` | 50+ | 阿里无线安全保镖 (AliSecGuard) | 包含 `.istbg_7.28.60` 等加密缓存与风控环境标记文件。 |
| `/private/var/mobile/Containers/Data/Application/<UUID>/Library/Caches/MQP_DIR/mqpsdklog_*.log` | 2 | 支付宝移动支付组件 (MQP) | 支付宝客户端加密交易与收银台会话诊断日志。 |
| `/private/var/mobile/Containers/Data/Application/<UUID>/Library/Caches/UMSocial/Statistics/` | 5 | 友盟社交 SDK (UMSocial) | 社交分享与第三方登录的离线事件统计缓存。 |
| `/private/var/mobile/Containers/Data/Application/<UUID>/Documents/SafeMode/AppCrashTrace.plist` | 3 | 安全模式容灾组件 | 记录异常退出标记与 Crash 追踪堆栈，用于连续崩溃防护。 |
| `/private/var/mobile/Containers/Data/Application/<UUID>/Documents/AVFSStorage/...` | 40+ | 阿里虚拟文件系统 (AVFS) | 包含 Spotlight 模块索引与离线键值持久化数据库。 |

> 注：其余为常规图片缓存（如 `ImageLibCache`）与应用常规配置（如 `wpkConfig`、`com.apple.SystemConfiguration.plist` 等），从略。
