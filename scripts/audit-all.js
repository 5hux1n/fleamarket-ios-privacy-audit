/* ============================================================
   闲鱼 iOS 隐私行为一体化审计脚本 (audit-all.js)
   输出:tmp/fm_audit.json —— 按类别去重汇总
   frida -U -n 闲鱼 -l audit-all.js
   控制台输入 dump() 可随时落盘;每 30 秒自动落盘一次。
   ============================================================ */

var R = {
  meta:        { started: new Date().toISOString(), events: 0 },
  file_write:  {},
  file_read:   {},
  jailbreak:   {},
  device_info: {},
  pasteboard:  {},
  app_query:   {},
  app_open:    {},
  app_list:    [],
  network:     {},
  anti_debug:  {}
};

function bump(cat, key) {
  if (!key) return;
  R[cat][key] = (R[cat][key] || 0) + 1;
  R.meta.events++;
}
function str(a){ try { return new ObjC.Object(a).toString(); } catch(e){ return "?"; } }
function cstr(p){ try { return p.readUtf8String(); } catch(e){ return null; } }

function hookSel(cls, sel, fn) {
  try {
    var m = ObjC.classes[cls] && ObjC.classes[cls]["- " + sel];
    if (!m) return;
    Interceptor.attach(m.implementation, { onEnter(args){ try{ fn(args); }catch(e){} } });
  } catch(e){}
}
function hookC(name, onE) {
  var p = Module.findExportByName(null, name);
  if (p) Interceptor.attach(p, { onEnter: onE });
}

// ---------- 1. 文件写入 ----------
hookSel("NSData","writeToFile:atomically:",         a => bump("file_write", str(a[2])));
hookSel("NSString","writeToFile:atomically:encoding:error:", a => bump("file_write", str(a[2])));
hookSel("NSFileManager","createFileAtPath:contents:attributes:", a => bump("file_write", str(a[2])));
hookSel("NSFileManager","createDirectoryAtPath:withIntermediateDirectories:attributes:error:",
        a => bump("file_write", str(a[2]) + "/ [mkdir]"));

// ---------- 2. 文件读取 / 目录访问 / 越狱探测 ----------
var JB = ["Cydia","MobileSubstrate","/bin/","/usr/sbin/sshd","/etc/apt",
          "/var/lib/apt","cydia","/var/lib/cydia","Frida","cynject",
          "libcycript","substrate","/User/Applications","/bin/ssh","jailbreak"];
function classifyPath(path){
  if (!path) return;
  var isJB = JB.some(k => path.indexOf(k) >= 0);
  bump(isJB ? "jailbreak" : "file_read", path);
}
["fopen","stat","lstat","access","open","opendir"].forEach(function(fn){
  hookC(fn, function(args){ classifyPath(cstr(args[0])); });
});
hookSel("NSFileManager","fileExistsAtPath:", a => classifyPath(str(a[2])));
hookSel("NSFileManager","contentsOfDirectoryAtPath:error:", a => bump("file_read", str(a[2]) + "/ [enum]"));

// ---------- 3. 设备信息读取 ----------
hookC("sysctlbyname", function(args){ bump("device_info", "sysctl:" + (cstr(args[0])||"?")); });
hookSel("ASIdentifierManager","advertisingIdentifier", () => bump("device_info","IDFA(advertisingIdentifier)"));
hookSel("UIDevice","identifierForVendor",               () => bump("device_info","IDFV(identifierForVendor)"));
hookSel("CTCarrier","carrierName",                      () => bump("device_info","carrierName(运营商)"));
hookSel("CTCarrier","mobileCountryCode",                () => bump("device_info","MCC"));
["CNCopyCurrentNetworkInfo","CNCopySupportedInterfaces","getifaddrs"].forEach(function(fn){
  hookC(fn, function(){ bump("device_info", fn + "(网络/WiFi)"); });
});

// 剪贴板
hookSel("UIPasteboard","string",  () => bump("pasteboard","generalPasteboard.string"));
hookSel("UIPasteboard","strings", () => bump("pasteboard","generalPasteboard.strings"));
hookSel("UIPasteboard","valueForPasteboardType:", a => bump("pasteboard","valueForType:" + str(a[2])));
hookSel("UIPasteboard","itemProviders", () => bump("pasteboard","itemProviders"));

// ---------- 4. app 跳转 / 枚举 ----------
hookSel("UIApplication","canOpenURL:", a => bump("app_query", str(a[2])));
hookSel("UIApplication","openURL:",    a => bump("app_open",  str(a[2])));
hookSel("UIApplication","openURL:options:completionHandler:", a => bump("app_open", str(a[2])));

// 明文应用列表扫描结果(类名按实际调整)
["TSCENTERAppListCmdService","ASSApplistModel","CSJApplistHelper"].forEach(function(c){
  if (!ObjC.classes[c]) return;
  try {
  ObjC.classes[c].$ownMethods.forEach(function(sel){
    var s = sel.toLowerCase();
    if (s.indexOf("applist") >=0 || s.indexOf("scanresult") >=0 || s.indexOf("installed") >=0) {
      try {
        var full = (sel[0] === "-" || sel[0] === "+") ? sel : "- " + sel;
        Interceptor.attach(ObjC.classes[c][full].implementation, {
          onEnter(args){
            try {
              var v = args[2] ? new ObjC.Object(args[2]).toString() : null;
              if (v && v.length > 2) {
                R.app_list.push({ ts: Date.now(), src: c + " " + sel, data: v.slice(0, 2000) });
                R.meta.events++;
              }
            } catch(e){}
          }
        });
      } catch(e){}
    }
  });
  } catch(e){}
});

// ---------- 5. 网络外传 ----------
function recordNet(url, method, body){
  if (!url) return;
  if (!R.network[url]) R.network[url] = { count:0, methods:{}, sampleBody:null };
  var e = R.network[url];
  e.count++;
  if (method) e.methods[method] = (e.methods[method]||0)+1;
  if (body && !e.sampleBody) e.sampleBody = body.slice(0, 1000);
  R.meta.events++;
}
function body2str(d){
  try {
    var o = new ObjC.Object(d);
    var s = ObjC.classes.NSString.alloc().initWithData_encoding_(o, 4);
    return s ? s.toString() : "<" + o.length() + " bytes>";
  } catch(e){ return "<bin>"; }
}
["dataTaskWithRequest:completionHandler:","dataTaskWithRequest:",
 "uploadTaskWithRequest:fromData:completionHandler:"].forEach(function(sel){
  hookSel("NSURLSession", sel, function(args){
    try {
      var req = new ObjC.Object(args[2]);
      var b = req.HTTPBody();
      recordNet(req.URL().absoluteString().toString(),
                req.HTTPMethod() ? req.HTTPMethod().toString() : "GET",
                (b && !b.isNull()) ? body2str(b) : null);
    } catch(e){}
  });
});

// ---------- 6. 自保护 ----------
hookC("ptrace",   function(){ bump("anti_debug","ptrace"); });
hookC("getppid",  function(){ bump("anti_debug","getppid"); });
var cfproxy = Module.findExportByName("CFNetwork","CFNetworkCopySystemProxySettings");
if (cfproxy) Interceptor.attach(cfproxy, { onEnter(){ bump("anti_debug","CFNetworkCopySystemProxySettings(查代理)"); } });

// ---------- 落盘 ----------
function dump() {
  R.meta.dumped = new Date().toISOString();
  var json = JSON.stringify(R, null, 2);
  try {
    var tmpDir = ObjC.classes.NSFileManager.defaultManager().temporaryDirectory().path().toString();
    var fp = tmpDir + "/fm_audit.json";
    ObjC.classes.NSString.stringWithString_(json)
      .writeToFile_atomically_encoding_error_(fp, 1, 4, NULL);
    console.log("[dump] 已写入 " + fp + "  (events=" + R.meta.events + ")");
  } catch(e){
    console.log("[dump] 落盘失败,直接打印:\n" + json.slice(0, 2000));
  }
}
globalThis.dump = dump;
setInterval(dump, 30000);

console.log(">>> 闲鱼一体化审计已加载。正常操作 app,输入 dump() 可随时落盘。<<<");
