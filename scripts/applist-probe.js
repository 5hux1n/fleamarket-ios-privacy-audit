/* ============================================================
   闲鱼 应用列表收集 — 专项动态验证补丁 (applist-probe.js)
   目的:坐实 A1(应用列表批量扫描),把它从「🟩 静态」升到「🟢 动态」。
   与 audit-all.js 并行加载:
     frida -U -n 闲鱼 -l audit-all.js -l applist-probe.js
   或单独跑:
     frida -U -n 闲鱼 -l applist-probe.js

   本补丁做三件 audit-all.js 没做到位的事:
   1) 自动发现真实类名(不靠猜),把 AppList 相关类/方法全列出来;
   2) canOpenURL: 全量记录 + 判定「是否批量扫描」(短时间内探测很多不同 scheme);
   3) 直接 hook _applist 属性的 setter 与 scanResult 方法,抢在加密前拿明文列表。
   ============================================================ */

var APPLIST = {
  discovered_classes: [],   // 运行时发现的相关类/方法
  canopen_calls: [],        // 每次 canOpenURL 的 {ts, scheme}
  distinct_schemes: {},     // scheme -> 次数
  burst_windows: [],        // 判定为"批量扫描"的时间窗
  plaintext_results: []     // 抢到的明文应用列表
};

function nowISO(){ return new Date().toISOString(); }
function toStr(a){ try { return new ObjC.Object(a).toString(); } catch(e){ return "?"; } }

if (!ObjC.available) {
  console.log("[applist] ObjC 运行时不可用,退出");
} else {

  // ---------------------------------------------------------
  // 1) 自动发现真实类名 —— 解决"类名猜错导致 hook 落空"
  //    打印所有名字里含 applist / appinfo / installed / scheme 的类,
  //    以及这些类里相关的方法,供你核对 / 回贴给我。
  // ---------------------------------------------------------
  try {
    var pat = /(applist|appinfo|installed|appscan|appcheck|TSCENTER|vkeydfp)/i;
    var names = Object.keys(ObjC.classes);
    for (var i = 0; i < names.length; i++) {
      var cn = names[i];
      if (pat.test(cn)) {
        var entry = { cls: cn, methods: [] };
        try {
          ObjC.classes[cn].$ownMethods.forEach(function(sel){
            if (/applist|installed|scan|scheme|canopen|generate/i.test(sel)) {
              entry.methods.push(sel);
            }
          });
        } catch(e){}
        APPLIST.discovered_classes.push(entry);
        console.log("[applist][发现类] " + cn +
          (entry.methods.length ? "  相关方法: " + entry.methods.join(" , ") : ""));
      }
    }
    console.log("[applist] 共发现相关类 " + APPLIST.discovered_classes.length + " 个");
  } catch(e){ console.log("[applist] 类发现失败: " + e); }

  // ---------------------------------------------------------
  // 2) canOpenURL: 全量记录 + 批量扫描判定
  //    批量判定规则:2 秒内出现 >= 8 个不同 scheme -> 记为一次 burst。
  // ---------------------------------------------------------
  try {
    var m = ObjC.classes.UIApplication["- canOpenURL:"];
    var recent = []; // {ts, scheme}
    Interceptor.attach(m.implementation, {
      onEnter(args){
        var scheme = "";
        try { scheme = toStr(args[2]); } catch(e){}
        var ts = Date.now();
        APPLIST.canopen_calls.push({ ts: ts, scheme: scheme });
        APPLIST.distinct_schemes[scheme] = (APPLIST.distinct_schemes[scheme]||0)+1;

        // 滑动窗口判定批量
        recent.push({ ts: ts, scheme: scheme });
        while (recent.length && ts - recent[0].ts > 2000) recent.shift();
        var distinct = {};
        recent.forEach(function(r){ distinct[r.scheme] = 1; });
        var dcount = Object.keys(distinct).length;
        if (dcount >= 8) {
          var win = { at: nowISO(), distinct_schemes: dcount,
                      schemes: Object.keys(distinct).slice(0, 60) };
          // 去重:同一 burst 不重复记
          var last = APPLIST.burst_windows[APPLIST.burst_windows.length-1];
          if (!last || (ts - Date.parse(last.at)) > 2000) {
            APPLIST.burst_windows.push(win);
            console.log("[applist][★批量扫描] " + win.at +
              " 窗口内探测 " + dcount + " 个不同 scheme -> 命中应用列表枚举行为");
          }
        }
      }
    });
    console.log("[applist] canOpenURL: 监控已挂载");
  } catch(e){ console.log("[applist] canOpenURL hook 失败: " + e); }

  // ---------------------------------------------------------
  // 3) 抢加密前的明文列表
  //    (a) hook 任意类里名字含 applist/scanResult/installed 的方法参数
  //    (b) hook KVC: setValue:forKey: 当 key 含 applist 时抓 value
  // ---------------------------------------------------------
  function dumpArgObject(label, obj){
    try {
      var s = new ObjC.Object(obj).toString();
      if (s && s.length > 2) {
        APPLIST.plaintext_results.push({ ts: nowISO(), src: label, data: s.slice(0, 4000) });
        console.log("[applist][★明文] " + label + " => " + s.slice(0, 300));
      }
    } catch(e){}
  }

  // (a) 基于运行时发现的类,挂它们的相关方法
  APPLIST.discovered_classes.forEach(function(entry){
    entry.methods.forEach(function(sel){
      try {
        var full = (sel[0] === "-" || sel[0] === "+") ? sel : "- " + sel;
        var mm = ObjC.classes[entry.cls][full];
        if (!mm) return;
        var argc = (sel.match(/:/g) || []).length;
        Interceptor.attach(mm.implementation, {
          onEnter(args){
            // 把每个对象参数都尝试打印(args[0]=self,args[1]=sel)
            for (var k = 2; k < 2 + argc; k++) {
              dumpArgObject(entry.cls + " " + sel + " arg" + (k-2), args[k]);
            }
          }
        });
      } catch(e){}
    });
  });

  // (b) KVC 兜底:很多 SDK 用 setValue:forKey: 给 _applist 赋值
  try {
    var sv = ObjC.classes.NSObject["- setValue:forKey:"];
    Interceptor.attach(sv.implementation, {
      onEnter(args){
        try {
          var key = toStr(args[3]);
          if (/applist|appList|installedApp/i.test(key)) {
            dumpArgObject("KVC setValue:forKey:(" + key + ")", args[2]);
          }
        } catch(e){}
      }
    });
    console.log("[applist] KVC setValue:forKey: 兜底已挂载");
  } catch(e){ console.log("[applist] KVC hook 失败: " + e); }

  // ---------------------------------------------------------
  // 落盘:写到和 audit-all.js 同目录 tmp,文件名区分开
  // ---------------------------------------------------------
  function dumpApplist(){
    try {
      var tmpDir = ObjC.classes.NSFileManager.defaultManager()
        .temporaryDirectory().path().toString();
      var fp = tmpDir + "/fm_applist_probe.json";
      var json = JSON.stringify(APPLIST, null, 2);
      var nss = ObjC.classes.NSString.stringWithString_(json);
      nss.writeToFile_atomically_encoding_error_(fp, 1, 4, NULL);
      console.log("[applist][dump] 已写入 " + fp +
        "  (canOpen=" + APPLIST.canopen_calls.length +
        ", 批量窗口=" + APPLIST.burst_windows.length +
        ", 明文=" + APPLIST.plaintext_results.length + ")");
    } catch(e){ console.log("[applist][dump] 失败,直接打印:\n" + JSON.stringify(APPLIST).slice(0,2000)); }
  }
  globalThis.dumpApplist = dumpApplist;
  setInterval(dumpApplist, 30000);

  console.log(">>> applist-probe 已加载。请操作:冷启动→登录→进入支付/收银台→分享到微信/QQ→发布商品,然后 dumpApplist() <<<");
}
