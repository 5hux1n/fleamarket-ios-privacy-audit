/* ============================================================
   vimei/vimsi/udid 生成溯源探针 (vimei-trace.js)
   目标:判断闲鱼自建的虚拟设备标识是【伪随机】还是【基于设备特征派生】
   方法:
     1. 记录"虚拟标识写入 Keychain"之前的一段时间里,app 读了哪些设备特征
        (sysctl/IDFV/IDFA/getifaddrs 等)—— 这些是派生的潜在输入。
     2. 写入虚拟标识时,打印深调用栈,定位生成函数。
     3. 记录写入的值,供"删除后是否复活"对比。
   配合删除复活测试(先清 Keychain 再冷启动)效果最好。
   用法:frida -U -n 闲鱼 -l vimei-trace.js
   ============================================================ */

var V = {
  started: new Date().toISOString(),
  feature_reads: [],      // 最近读到的设备特征(滑动窗口)
  virtual_id_writes: []   // vimei/vimsi/udid 写入事件(含值+栈+写前读到的特征)
};

// 目标:闲鱼自建的虚拟标识
var VIRT_KEY = /^(vimei|vimsi|udid)$/i;
// 设备特征读取(派生的潜在输入熵源)
var recentFeatures = []; // {ts, feature}

function pushFeature(name){
  var ts = Date.now();
  recentFeatures.push({ ts: ts, feature: name });
  // 只保留最近 3 秒
  while (recentFeatures.length && ts - recentFeatures[0].ts > 3000) recentFeatures.shift();
}

function cstr(p){ try { return p.readUtf8String(); } catch(e){ return null; } }

// —— 监控设备特征读取(这些是"如果派生"的输入候选)——
var sysctlbyname = Module.findExportByName(null, "sysctlbyname");
if (sysctlbyname) Interceptor.attach(sysctlbyname, {
  onEnter(args){ var n = cstr(args[0]); if (n) pushFeature("sysctl:" + n); }
});
["getifaddrs","gethostname","statfs","statfs64"].forEach(function(fn){
  var p = Module.findExportByName(null, fn);
  if (p) Interceptor.attach(p, { onEnter(){ pushFeature(fn); } });
});
if (ObjC.available) {
  [["ASIdentifierManager","advertisingIdentifier","IDFA"],
   ["UIDevice","identifierForVendor","IDFV"],
   ["UIDevice","systemVersion","systemVersion"],
   ["UIDevice","model","model"],
   ["UIDevice","name","deviceName"]].forEach(function(t){
    try {
      var m = ObjC.classes[t[0]]["- " + t[1]];
      if (m) Interceptor.attach(m.implementation, { onEnter(){ pushFeature(t[2]); } });
    } catch(e){}
  });
}

// —— 监控虚拟标识写入 Keychain ——
function deepBacktrace(ctx){
  try {
    return Thread.backtrace(ctx, Backtracer.ACCURATE)
      .slice(0, 12)
      .map(function(a){
        var s = DebugSymbol.fromAddress(a);
        return (s.moduleName||"?") + "!" + (s.name || s.address);
      });
  } catch(e){ return []; }
}

function inspectKeychainWrite(args, op, ctx){
  if (!ObjC.available) return;
  try {
    var dict = new ObjC.Object(args[0]);
    var desc = dict.toString();
    if (/\bvimei\b|\bvimsi\b|\budid\b/i.test(desc)) {
      var ev = {
        ts: new Date().toISOString(), op: op,
        dict: desc.slice(0, 1500),
        features_before: recentFeatures.slice(),   // 写入前3秒读到的特征
        backtrace: deepBacktrace(ctx)
      };
      V.virtual_id_writes.push(ev);
      console.log("\n[vimei][★虚拟标识写入] " + op +
        "\n  字典: " + desc.slice(0, 300) +
        "\n  写入前读到的设备特征(派生输入候选): " +
        ev.features_before.map(function(f){return f.feature;}).join(", ") +
        "\n  调用栈(前几帧):\n    " + ev.backtrace.slice(0,8).join("\n    "));
    }
  } catch(e){}
}

[["SecItemAdd"],["SecItemUpdate"]].forEach(function(spec){
  var p = Module.findExportByName("Security", spec[0]);
  if (p) Interceptor.attach(p, {
    onEnter(args){ inspectKeychainWrite(args, spec[0], this.context); }
  });
});

function dumpVimei(){
  try {
    var tmpDir = ObjC.classes.NSFileManager.defaultManager()
      .temporaryDirectory().path().toString();
    var fp = tmpDir + "/fm_vimei_trace.json";
    ObjC.classes.NSString.stringWithString_(JSON.stringify(V,null,2))
      .writeToFile_atomically_encoding_error_(fp,1,4,NULL);
    console.log("[vimei][dump] " + fp + " (虚拟标识写入事件=" + V.virtual_id_writes.length + ")");
  } catch(e){ console.log("[vimei][dump] 失败: " + e); }
}
globalThis.dumpVimei = dumpVimei;
setInterval(dumpVimei, 30000);

console.log(">>> vimei-trace 已加载。配合删除复活测试:先清 Keychain,再冷启动,观察虚拟标识重新写入时读了哪些特征 + 值与删前是否相同。<<<");
