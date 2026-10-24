/* ============================================================
   IDFV 跨 App / 跨账号 对比探针 (idfv-compare.js)
   目标:实测证明哪些 App 共享同一 IDFV(同 vendor),
         以及同一 App 换账号后 IDFV 是否不变(认设备不认人)。
   方法:hook [UIDevice identifierForVendor],打印返回值 + 进程名。
   用法:分别 attach 到每个要测的 App:
     frida -U -n 闲鱼   -l idfv-compare.js
     frida -U -n 淘宝   -l idfv-compare.js
     frida -U -n 支付宝 -l idfv-compare.js
     frida -U -n 高德地图 -l idfv-compare.js
   (或用 -f spawn)。把每个 App 打印的 IDFV 值记下来对比。
   ============================================================ */

if (!ObjC.available) {
  console.log("[idfv] ObjC 不可用");
} else {
  function bundleId(){
    try { return ObjC.classes.NSBundle.mainBundle().bundleIdentifier().toString(); }
    catch(e){ return "?"; }
  }
  function procName(){
    try { return ObjC.classes.NSProcessInfo.processInfo().processName().toString(); }
    catch(e){ return "?"; }
  }

  var reported = false;
  function reportIDFV(idfv){
    if (reported) return;
    reported = true;
    console.log("\n========== IDFV 读取 ==========");
    console.log("进程:     " + procName());
    console.log("BundleID: " + bundleId());
    console.log("IDFV:     " + idfv);
    console.log("================================\n");
    console.log(">>> 把上面的 IDFV 值记下来,与其他 App 对比:相同=同 vendor。<<<");
  }

  // 主动读一次(不等 app 自己调)
  try {
    var dev = ObjC.classes.UIDevice.currentDevice();
    var idfv = dev.identifierForVendor();
    reportIDFV(idfv ? idfv.UUIDString().toString() : "(nil,设备刚重启未解锁?稍后重试)");
  } catch(e){ console.log("[idfv] 主动读取失败: " + e); }

  // 同时 hook,抓 app 自己每次读取(确认它确实在用 IDFV)
  try {
    var m = ObjC.classes.UIDevice["- identifierForVendor"];
    Interceptor.attach(m.implementation, {
      onLeave(ret){
        try {
          var v = new ObjC.Object(ret);
          var s = v.UUIDString ? v.UUIDString().toString() : v.toString();
          console.log("[idfv][app 读取] " + procName() + " -> " + s);
        } catch(e){}
      }
    });
    console.log("[idfv] 已 hook identifierForVendor,等待 app 读取...");
  } catch(e){ console.log("[idfv] hook 失败: " + e); }
}
