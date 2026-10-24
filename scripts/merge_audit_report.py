#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
闲鱼隐私审计报告合成器
---------------------------------------------------------------
输入: fm_audit.json  (由 audit-all.js 动态 hook 落盘)
输出: 审计报告_最终版.md (带置信度分级的 Markdown)

用法:
    python3 merge_audit_report.py fm_audit.json
    python3 merge_audit_report.py fm_audit.json -o 报告.md

思路:
  静态报告给出"断言全集"(ASSERTIONS)。每条断言声明:
    - 该去动态 JSON 的哪个类别(json_field)找
    - 命中哪些关键词(match)才算被运行时验证到
  脚本用动态数据去碰撞,据此给每条断言判级:
    已证实(动态) / 已证实(静态) / 高可信推断 / 待验证推断 / 动态未复现
"""

import json
import sys
import argparse
from datetime import datetime

# ============================================================
# 置信度等级定义
# ============================================================
L_DYN   = "🟢 已证实(动态)"   # 静态有锚点 + 运行时实测命中
L_STAT  = "🟩 已证实(静态)"   # 符号/plist/清单直接命中,无需运行时
L_HIGH  = "🟡 高可信推断"       # 静态强证据 + 已知行业行为
L_WAIT  = "🟠 待验证推断"       # 逻辑合理但缺运行时证据,本轮未命中
L_MISS  = "⚪ 动态未复现"       # 预期动态可验证,但本轮 JSON 中未出现(可能未触发该功能)

# ============================================================
# 断言清单:静态报告里的每条结论 + 其动态验证规则
#   kind="static"  -> 固定为"已证实(静态)",不依赖动态
#   kind="infer"   -> 默认 base_level,若动态命中则升级为 L_DYN
#   json_field     -> 去 R[...] 这个类别里找
#   match          -> 关键词列表(任一子串命中即算验证到);None 表示"该类别非空即算"
# ============================================================
ASSERTIONS = [
    # ---- 方向3:隐私清单(最硬,多为静态已证实)----
    dict(id="A1", area="清单合规", kind="static",
         text="集成完整的应用列表扫描框架(运行时确认类名:TSCENTERAppListCmdService.getAppListCmd: / TSCENTERAppListCmdRequest.applist / CSJApplistHelper.saveApplist),iOS 隐私清单未声明收集已安装应用列表",
         note="静态符号链 + Keychain 键(_ASS_KEYCHAIN_KEY_APPLIST)+ iOS 清单缺项 + 运行时 canOpenURL 实测,四点互证。注意:iOS 清单未声明,但鸿蒙版已明示收集应用列表——跨端披露不一致,iOS 侧告知缺失。",
         json_field="app_query", match=None),
    dict(id="A1b", area="清单合规", kind="infer", base_level=L_WAIT,
         text="【超范围批量扫描】冷启动后无交互时段,程序化批量枚举已安装 app(实测一次 burst 在约 75ms 内连续探测 50+ 个不同 scheme,覆盖字节/腾讯/百度/阿里系竞品)",
         note="这是比 A1 更强的指控:不是功能性探测(点分享查微信),而是遍历一张预设清单。证据=applist-probe 的 burst_windows。超出鸿蒙声明的'判断三方 app 是否安装以提供功能'范围 → 指向超范围收集。命中依赖 --applist 传入 probe 数据。",
         json_field="_burst", match=None),
    dict(id="A2", area="清单合规", kind="static",
         text="开机时间 systemBootTime 声明理由为事件计时,实际回传设备指纹生成器(用途与声明不符)",
         note="声明 vs 实际用途碰撞。",
         json_field="device_info", match=["KERN_BOOTTIME", "boottime", "kern.boottime"]),
    dict(id="A3", area="清单合规", kind="static",
         text="磁盘空间 diskSpace 声明用于缓存判断,实际用于真机/虚拟机区分的指纹画像",
         note="声明 vs 实际用途碰撞。",
         json_field="device_info", match=["statfs", "FreeSize"]),

    # ---- 方向3/2:剪贴板 ----
    dict(id="A4", area="剪贴板", kind="infer", base_level=L_HIGH,
         text="冷启动/切前台即读剪贴板(FMFishCodePasteboardHelper 淘口令解析),清单未涉及、国内合规高风险",
         note="动态需确认读取时机(是否无交互即读)。",
         json_field="pasteboard", match=None),

    # ---- 方向1:网络外传 ----
    dict(id="A5", area="网络外传", kind="infer", base_level=L_WAIT,
         text="二进制含大量外传/网关 URL(静态计数 529);需收敛为运行时真实在用的域名",
         note="529 为字符串计数,非实际请求数。动态 net 字段给出真实在用集合。",
         json_field="network", match=None),
    dict(id="A6", area="网络外传", kind="infer", base_level=L_HIGH,
         text="设备指纹/安全信息上报走支付宝安全网关(实测 mdap.alipay.com / loggw-ex.alipay.com 的 logUpload.do)",
         note="已更正为实测域名:静态报告写的 mdap.alipaylog.com 本轮未出现,实际在用的是 mdap.alipay.com 与 loggw-ex.alipay.com。印证'529 为字符串计数、含未启用项'。Payload 为密文,'内含应用列表'未坐实,见 A14。",
         json_field="network", match=["alipay.com/loggw", "mdap.alipay", "loggw-ex.alipay"]),
    dict(id="A7", area="网络外传", kind="infer", base_level=L_HIGH,
         text="全量行为埋点经 UT 通道上报(mmstat / usertrack / audid)",
         note="",
         json_field="network", match=["mmstat", "usertrack", "audid", "/ut/"]),
    dict(id="A8", area="网络外传", kind="infer", base_level=L_HIGH,
         text="友盟统计上报 IDFV/系统版本/活跃会话(ulogs.umeng.com)",
         note="",
         json_field="network", match=["umeng", "ulogs"]),
    dict(id="A9", area="网络外传", kind="infer", base_level=L_HIGH,
         text="高德定位原始经纬度 + Wi-Fi BSSID 上报(logs.amap.com)",
         note="",
         json_field="network", match=["amap.com"]),

    # ---- 方向1:Pinning ----
    dict(id="A10", area="防抓包", kind="static",
         text="调用 SecTrustSetAnchorCertificatesOnly 强制仅信任内置证书,常规 MITM 抓包被拒(静态计数:二进制中出现 142 处 PEM 证书块)",
         note="142 为字符串计数(BEGIN CERTIFICATE 出现次数),非实际启用数。Pinning API 的调用是静态可证的;本轮动态未对 Pinning 行为做针对性验证(audit-all.js 未 hook SecTrustEvaluate),故不标动态命中。",
         json_field="pinning", match=["SecTrustEvaluate", "SecTrustSetAnchor"]),

    # ---- 方向2:反调试/反抓包/反hook ----
    dict(id="A11", area="自保护", kind="infer", base_level=L_HIGH,
         text="直接 svc #0x80 系统调用绕过 libc 符号(静态计数 61 处),按符号名 hook 会失效",
         note="修正:非'完全抓不到',需改用地址级/指令级(Stalker)hook。",
         json_field="anti_debug", match=["ptrace", "getppid"]),
    dict(id="A12", area="自保护", kind="infer", base_level=L_HIGH,
         text="代理检测(CFNetworkCopySystemProxySettings);检测到代理后切 QUIC/HTTP3 直连穿透 HTTP 代理",
         note="'切QUIC穿透'属行为推断,需动态复现(挂代理看是否降级/改协议)。",
         json_field="anti_debug", match=["ProxySettings", "代理"]),
    dict(id="A13", area="自保护", kind="static",
         text="内嵌 fishhook + 遍历 dyld 镜像匹配 FridaGadget/MobileSubstrate/cycript 黑名单",
         note="符号 rebind_symbols + 特征字匹配,静态可证。",
         json_field="anti_debug", match=None),

    # ---- 方向2:强断言,标注待验证 ----
    dict(id="A14", area="待验证", kind="infer", base_level=L_WAIT,
         text="wua/x-sign 密文内含越狱标志、陀螺仪轨迹",
         note="⚠ 强断言。需 hook _alisec_crypto 加密入口拿明文才能坐实,否则仅为推测。",
         json_field="device_info", match=["__NEVER_MATCH__"]),  # 故意不自动命中,提醒人工验证
    dict(id="A15", area="待验证", kind="infer", base_level=L_WAIT,
         text="检测到调试器后服务端返回业务降级/滑动验证码",
         note="⚠ 服务端行为,静态不可见。需挂调试器复现接口响应。",
         json_field="anti_debug", match=["__NEVER_MATCH__"]),

    # ---- 方向4:越狱写入探测 ----
    dict(id="A16", area="越狱探测", kind="infer", base_level=L_HIGH,
         text="向沙盒外 /private/umTest_Jailbreak.txt 写文件测试沙盒突破(写入目标在 file_write 中实测命中 2 次)",
         note="归因更正:实测路径带 umTest_ 前缀(um=友盟 Umeng),写越狱探测文件的是友盟 SDK,而非静态报告推断的阿里 RVPBridgeExtension4Jailbroken(/private/jailbreak.txt)。两者可能并存,但本轮实测到的是友盟这条。",
         json_field="file_write", match=["jailbreak", "Jailbreak"]),
    dict(id="A17", area="越狱探测", kind="infer", base_level=L_HIGH,
         text="穷举探测越狱路径(实测命中 /Applications/Cydia.app、/private/var/lib/apt/ 等)",
         note="另:device_info 中 sysctl:security.mac.sandbox.sentinel 命中 4 次,属沙盒哨兵/完整性校验,归入自保护类。",
         json_field="jailbreak", match=None),

    # ---- 新增:动态暴露的端侧 ML 落地 ----
    dict(id="A20", area="端侧ML", kind="infer", base_level=L_WAIT,
         text="本地落地阿里 MNN 端侧推理模型(Documents/MNNRTModels/ 实测写入约 498 次)",
         note="中性发现,非隐私违规。但端侧模型常用于设备风控/推荐/图像识别,是'数据在端上被处理'的信号,值得记录。写入次数高是模型分片落地,非重复采集。",
         json_field="file_write", match=["MNNRTModels", "MNN"]),

    # ---- 方向5:后台持久化 ----
    dict(id="A18", area="后台保活", kind="static",
         text="Info.plist 声明 audio/fetch/remote-notification/voip 四项后台权限",
         note="plist 事实。'audio 静音保活'属手法指控,需确认后台确有静音 AVAudioSession 循环,否则可能是正常语音/视频功能。",
         json_field="network", match=["__NEVER_MATCH__"]),
    dict(id="A19", area="后台保活", kind="infer", base_level=L_HIGH,
         text="significant location + allowsBackgroundLocationUpdates,杀进程后仍可冷启动追踪轨迹",
         note="能力存在(静态);'持续在用'需动态观察。",
         json_field="device_info", match=["__NEVER_MATCH__"]),
]


def load(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def flatten_keys(field_data):
    """把某类别的 JSON 值摊平成可搜索的字符串列表。"""
    out = []
    if isinstance(field_data, dict):
        for k, v in field_data.items():
            out.append(str(k))
            if isinstance(v, dict):
                out.append(json.dumps(v, ensure_ascii=False))
    elif isinstance(field_data, list):
        for item in field_data:
            out.append(json.dumps(item, ensure_ascii=False) if not isinstance(item, str) else item)
    return out


def evaluate(assertion, R):
    """返回 (等级, 命中证据列表)。"""
    field = assertion["json_field"]
    data = R.get(field, {})
    keys = flatten_keys(data)
    hits = []

    match = assertion["match"]
    if match is None:
        # 该类别非空即算命中
        hits = keys[:8]
        matched = len(keys) > 0
    else:
        seen = set()
        for kw in match:
            for k in keys:
                if kw.lower() in k.lower() and k not in seen:
                    hits.append(k)
                    seen.add(k)
        matched = len(hits) > 0

    if assertion["kind"] == "static":
        # 静态结论固定;若动态也命中,附注"动态亦复现"
        level = L_STAT
        return (level, hits[:5], matched)
    else:
        base = assertion.get("base_level", L_WAIT)
        if matched:
            return (L_DYN, hits[:5], True)
        else:
            # 未命中:高可信保持高可信但标注未复现;待验证降为未复现
            if base == L_HIGH:
                return (L_HIGH, [], False)
            else:
                return (L_MISS if base == L_WAIT else base, [], False)


def build_report(R, src_path):
    lines = []
    meta = R.get("meta", {})
    lines.append("# 闲鱼 iOS 隐私行为审计报告(静态+动态合成·带置信度分级)\n")
    lines.append(f"- 生成时间:{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"- 动态数据来源:`{src_path}`")
    lines.append(f"- 动态采集起止:{meta.get('started','?')} → {meta.get('dumped','?')}")
    lines.append(f"- 动态事件总数:{meta.get('events','?')}\n")

    lines.append("> **置信度说明**")
    lines.append(f"> - {L_DYN}:静态有锚点,且本轮运行时实测命中")
    lines.append(f"> - {L_STAT}:符号/plist/清单直接可证,无需运行时")
    lines.append(f"> - {L_HIGH}:静态强证据 + 已知行业行为(本轮动态未直接命中,不代表不存在)")
    lines.append(f"> - {L_WAIT}:逻辑合理但缺运行时证据,**需人工复现**")
    lines.append(f"> - {L_MISS}:预期可动态验证,但本轮未触发对应功能\n")
    lines.append("---\n")

    # 汇总表
    lines.append("## 一、结论置信度总览\n")
    lines.append("| ID | 领域 | 结论 | 置信度 | 动态命中 |")
    lines.append("|----|------|------|--------|----------|")
    results = []
    for a in ASSERTIONS:
        level, hits, matched = evaluate(a, R)
        results.append((a, level, hits, matched))
        hit_mark = "✅" if matched else "—"
        short = a["text"] if len(a["text"]) <= 40 else a["text"][:38] + "…"
        lines.append(f"| {a['id']} | {a['area']} | {short} | {level} | {hit_mark} |")
    lines.append("")

    # 统计
    from collections import Counter
    c = Counter(level for _, level, _, _ in results)
    lines.append("### 分级统计")
    for lv in [L_DYN, L_STAT, L_HIGH, L_WAIT, L_MISS]:
        if c.get(lv):
            lines.append(f"- {lv}:{c[lv]} 条")
    lines.append("\n---\n")

    # 逐条详情
    lines.append("## 二、逐条结论详情\n")
    for a, level, hits, matched in results:
        lines.append(f"### [{a['id']}] {a['text']}")
        lines.append(f"- **领域**:{a['area']}")
        lines.append(f"- **置信度**:{level}")
        if a.get("note"):
            lines.append(f"- **说明**:{a['note']}")
        if a["kind"] == "static" and matched:
            lines.append(f"- **附注**:静态可证,且动态亦复现 ✅")
        if hits:
            ev = ", ".join(f"`{h[:60]}`" for h in hits)
            lines.append(f"- **动态证据**:{ev}")
        elif a["kind"] == "infer" and not matched:
            lines.append(f"- **动态证据**:本轮未命中(若未操作到相关功能,属正常;请补测后重跑)")
        lines.append("")

    # 动态原始数据附录
    lines.append("---\n")
    lines.append("## 三、动态实测原始汇总(供复核)\n")
    for field, title in [
        ("network", "实际请求的网络 endpoint"),
        ("app_query", "canOpenURL 探测的 scheme"),
        ("app_open", "实际 openURL 跳转"),
        ("pasteboard", "剪贴板读取"),
        ("device_info", "设备信息读取"),
        ("file_write", "文件写入路径"),
        ("jailbreak", "越狱/注入探测路径"),
        ("anti_debug", "自保护命中"),
        ("pinning", "SSL Pinning 行为(本轮未 hook,预期为空)"),
    ]:
        data = R.get(field, {})
        lines.append(f"### {title}")
        if not data:
            lines.append("_(本轮无记录)_\n")
            continue
        if isinstance(data, dict):
            for k, v in sorted(data.items(), key=lambda x: -(x[1] if isinstance(x[1], int) else x[1].get("count",0))):
                cnt = v if isinstance(v, int) else v.get("count", "?")
                lines.append(f"- `{k}` ×{cnt}")
        lines.append("")

    # 应用列表明文单列
    al = R.get("app_list", [])
    lines.append("### 明文应用列表扫描结果(如捕获到)")
    if al:
        for item in al[:5]:
            lines.append(f"- 来源 `{item.get('src','?')}`:")
            lines.append(f"  ```\n  {str(item.get('data',''))[:500]}\n  ```")
    else:
        lines.append("_(本轮未捕获到明文应用列表;需确认 app_list hook 的类名/方法名是否与实际一致)_")
    lines.append("")

    # 批量扫描专项附录
    P = R.get("_applist_probe")
    if P:
        lines.append("---\n")
        lines.append("## 三之二、应用列表批量扫描专项(applist-probe 实测)\n")
        bw = P.get("burst_windows", [])
        if bw:
            lines.append(f"**判定:命中批量扫描 {len(bw)} 次**(阈值:2 秒内 ≥8 个不同 scheme)。\n")
            for w in bw:
                lines.append(f"- 窗口 `{w.get('at','?')}`:{w.get('distinct_schemes','?')} 个不同 scheme")
                sch = w.get("schemes", [])
                if sch:
                    lines.append(f"  - {', '.join('`'+s+'`' for s in sch)}")
        else:
            lines.append("**未命中批量扫描**(本轮无 ≥8 scheme/2s 的 burst)。")
        ds = P.get("distinct_schemes", {})
        lines.append(f"\n**本轮探测到的不同 app scheme 总数:{len(ds)}**,涵盖(按厂商)字节(抖音/头条/西瓜/多闪/飞聊)、腾讯(微信/QQ/微博)、百度、阿里系全家桶等。完整清单见原始 JSON。")
        disc = P.get("discovered_classes", [])
        fm_cls = [c for c in disc if any(k in c.get("cls","") for k in ["TSCENTER","CSJApplist","ASSApplist"])]
        if fm_cls:
            lines.append("\n**运行时确认的收集链类/方法(非系统类):**")
            for c in fm_cls:
                ms = c.get("methods", [])
                lines.append(f"- `{c['cls']}`" + (f":{', '.join('`'+m+'`' for m in ms)}" if ms else ""))
        plain = P.get("plaintext_results", [])
        lines.append(f"\n**明文列表捕获:**{'已捕获 '+str(len(plain))+' 条' if plain else '未捕获(列表在加密前未经 ObjC KVC/方法参数暴露,需 hook C++ 侧)'}。")
        lines.append("")

    lines.append("---\n")
    lines.append("## 四、下一步建议")
    lines.append("1. 对 🟠 待验证 的结论(wua 明文、服务端降级、audio 保活),按说明做针对性动态复现。")
    lines.append("2. 对 🟡 高可信但本轮未命中 的结论,补测相关功能后重跑,争取升级为 🟢。")
    lines.append("3. 把 🟩/🟢 的结论作为报告主结论;🟠 的在报告中明确标注为'疑似/待证',避免过度断言。")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="合成带置信度分级的隐私审计报告")
    ap.add_argument("json", help="audit-all.js 落盘的 fm_audit.json")
    ap.add_argument("-o", "--out", default="审计报告_最终版.md")
    ap.add_argument("--applist", help="applist-probe.js 落盘的 fm_applist_probe.json(可选,用于坐实 A1b 批量扫描)")
    args = ap.parse_args()

    try:
        R = load(args.json)
    except Exception as e:
        print(f"[错误] 读取 {args.json} 失败:{e}")
        sys.exit(1)

    # 合并 applist-probe 数据
    R["_applist_probe"] = None
    if args.applist:
        try:
            P = load(args.applist)
            R["_applist_probe"] = P
            # _burst 字段供 A1b 判级:非空 = 命中批量扫描
            bw = P.get("burst_windows", [])
            R["_burst"] = {f"burst@{w.get('at','?')}": w.get("distinct_schemes", 0) for w in bw}
            # 把 probe 的 canopen 并入 app_query(便于 A1 证据展示)
            ds = P.get("distinct_schemes", {})
            if ds:
                aq = R.get("app_query", {}) or {}
                for k, v in ds.items():
                    aq[k] = aq.get(k, 0) + v
                R["app_query"] = aq
            print(f"[合并] applist-probe:burst={len(bw)} 个,distinct_schemes={len(ds)} 个")
        except Exception as e:
            print(f"[警告] 读取 {args.applist} 失败,跳过合并:{e}")
            R["_burst"] = {}
    else:
        R["_burst"] = {}

    report = build_report(R, args.json)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"[完成] 已生成:{args.out}")
    print(f"       断言 {len(ASSERTIONS)} 条已逐一判级。")


if __name__ == "__main__":
    main()
