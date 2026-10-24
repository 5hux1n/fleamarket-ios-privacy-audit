/* ============================================================
   闲鱼 Keychain 写入/读取 实时探针 (keychain-probe.js)
   —— 路2:在写入/读取发生的瞬间,抓键、值、时机、调用方。
   用法(可与 audit-all.js 并行):
     frida -U -n 闲鱼 -l keychain-probe.js
   输出:控制台实时打印 + 落盘 tmp/fm_keychain.json
   dumpKeychainLog() 可随时落盘。
   ============================================================ */

var KC = {
  started: new Date().toISOString(),
  writes: [],   // SecItemAdd / SecItemUpdate 的内容
  reads:  [],   // SecItemCopyMatching 的查询
  applist_hits: []  // 专门标出疑似应用列表 / 设备指纹的项
};

// 关注的敏感 key 名(命中就重点标注)
var SENSITIVE = /applist|APPLIST|APDID|clientkey|dynamicKey|deviceToken|umid|utdid|sskeychain|securesdk|fingerprint|deviceId/i;

function cfToJSObj(ptr){
  // 把 CFDictionary/NSDictionary 转成可读字符串,并尽量提取 key/value
  try {
    var o = new ObjC.Object(ptr);
    var out = { desc: o.toString().slice(0, 3000), pairs: {} };
    try {
      var keys = o.allKeys();
      var n = keys.count();
      for (var i = 0; i < n; i++) {
        var k = keys.objectAtIndex_(i);
        var ks = k.toString();
        var v = o.objectForKey_(k);
        var vs;
        try {
          // v 可能是 NSData(值) / NSString / NSNumber
          var cls = v.$className || "";
          if (/NSData/i.test(v.$className)) {
            // 尝试把 Data 当 UTF8 文本解,不行就标长度+前缀hex
            var asStr = ObjC.classes.NSString.alloc().initWithData_encoding_(v, 4);
            if (asStr && asStr.length() > 0) {
              vs = "[NSData->utf8] " + asStr.toString().slice(0, 1500);
            } else {
              vs = "[NSData " + v.length() + " bytes]";
            }
          } else {
            vs = v.toString().slice(0, 1500);
          }
        } catch(e){ vs = "<?>"; }
        out.pairs[ks] = vs;
      }
    } catch(e){}
    return out;
  } catch(e){ return { desc: "<unreadable>", pairs: {} }; }
}

function backtraceTop(ctx){
  try {
    return Thread.backtrace(ctx, Backtracer.ACCURATE)
      .slice(0, 4).map(DebugSymbol.fromAddress)
      .map(function(s){ return s.name || s.moduleName || "?"; }).join(" <- ");
  } catch(e){ return ""; }
}

function flagSensitive(record){
  try {
    var blob = JSON.stringify(record.data.pairs);
    if (SENSITIVE.test(blob) || SENSITIVE.test(record.data.desc)) {
      KC.applist_hits.push(record);
      console.log("[Keychain][★敏感] " + record.op + " 命中敏感键:\n" +
        JSON.stringify(record.data.pairs, null, 2).slice(0, 1200));
    }
  } catch(e){}
}

if (!ObjC.available) {
  console.log("[keychain] ObjC 不可用");
} else {
  [["SecItemAdd", 0], ["SecItemUpdate", 1]].forEach(function(spec){
    var fn = spec[0], valIdx = spec[1];
    var p = Module.findExportByName("Security", fn);
    if (!p) { console.log("[keychain] 未找到 " + fn); return; }
    Interceptor.attach(p, {
      onEnter(args){
        var rec = { ts: new Date().toISOString(), op: fn,
                    data: cfToJSObj(args[0]), caller: backtraceTop(this.context) };
        if (fn === "SecItemUpdate") {
          rec.updateTo = cfToJSObj(args[1]);  // 第二个参数是"新值"
        }
        KC.writes.push(rec);
        console.log("\n[Keychain][" + fn + "] " + rec.ts +
          "\n  keys: " + Object.keys(rec.data.pairs).join(", ") +
          "\n  caller: " + rec.caller);
        flagSensitive(rec);
        if (rec.updateTo) {
          var r2 = { ts: rec.ts, op: fn+":新值", data: rec.updateTo, caller: rec.caller };
          flagSensitive(r2);
        }
      }
    });
    console.log("[keychain] 已 hook " + fn);
  });

  var sc = Module.findExportByName("Security", "SecItemCopyMatching");
  if (sc) {
    Interceptor.attach(sc, {
      onEnter(args){
        var q = cfToJSObj(args[0]);
        KC.reads.push({ ts: new Date().toISOString(), query: q.pairs });
        // 读取只在命中敏感键时打印,避免刷屏
        if (SENSITIVE.test(JSON.stringify(q.pairs))) {
          console.log("[Keychain][读取-敏感] " + JSON.stringify(q.pairs).slice(0, 400));
        }
      }
    });
    console.log("[keychain] 已 hook SecItemCopyMatching");
  }

  function dumpKeychainLog(){
    try {
      var tmpDir = ObjC.classes.NSFileManager.defaultManager()
        .temporaryDirectory().path().toString();
      var fp = tmpDir + "/fm_keychain.json";
      var nss = ObjC.classes.NSString.stringWithString_(JSON.stringify(KC, null, 2));
      nss.writeToFile_atomically_encoding_error_(fp, 1, 4, NULL);
      console.log("[keychain][dump] 已写入 " + fp +
        " (写入=" + KC.writes.length + ", 读取=" + KC.reads.length +
        ", 敏感=" + KC.applist_hits.length + ")");
    } catch(e){ console.log("[keychain][dump] 失败: " + e); }
  }
  globalThis.dumpKeychainLog = dumpKeychainLog;
  setInterval(dumpKeychainLog, 30000);

  console.log(">>> keychain-probe 已加载。操作:冷启动→登录→进支付/收银台,然后 dumpKeychainLog() <<<");
}
