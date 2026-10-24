/* ============================================================
   wua / x-sign 签名溯源探针 (wua-probe.js)
   目标:坐实 wua 加密前的明文输入里到底包含什么(是否含越狱标志、
         传感器轨迹、设备指纹等)。
   策略(分阶段,结果都落盘 tmp/fm_wua.json):
     阶段一:自动发现所有与 wua/sign/SecurityGuard/alisec 相关的类与方法
             —— 不靠猜,先拿到真实入口。
     阶段二:hook mtop 请求构建,抓 wua/x-sign 最终密文值(看长度格式);
             hook 发现的签名方法入口,打印入参 + 深调用栈。
   用法:frida -U -n 闲鱼 -l wua-probe.js
   然后正常操作(搜索、刷新、翻页都会触发签名)。dumpWua() 落盘。
   ============================================================ */

var W = {
  started: new Date().toISOString(),
  discovered_classes: [],   // 运行时发现的相关类/方法
  sign_headers: [],         // 抓到的 wua/x-sign/x-mini-wua 最终值(密文)
  sign_inputs: [],          // 签名方法入口的入参(可能是明文)
  notes: []
};

function nowISO(){ return new Date().toISOString(); }
function toStr(o){ try { return o.toString(); } catch(e){ return "?"; } }

if (!ObjC.available) {
  console.log("[wua] ObjC 运行时不可用");
} else {

  // ---------------------------------------------------------
  // 阶段一:自动发现相关类/方法
  // ---------------------------------------------------------
  try {
    var clsPat = /(securityguard|wclient|jaq|alisec|umid|SGMain|wua|xsign|x_sign|avmp|secsdk|SecurityBody|miniwua)/i;
    var selPat = /(wua|sign|hash|encrypt|umid|token|getsign|avmp|invokeapi|securitybody|atlas)/i;
    var names = Object.keys(ObjC.classes);
    for (var i = 0; i < names.length; i++) {
      var cn = names[i];
      if (clsPat.test(cn)) {
        var entry = { cls: cn, methods: [] };
        try {
          ObjC.classes[cn].$ownMethods.forEach(function(sel){
            if (selPat.test(sel)) entry.methods.push(sel);
          });
        } catch(e){}
        W.discovered_classes.push(entry);
        console.log("[wua][发现类] " + cn +
          (entry.methods.length ? "  方法: " + entry.methods.join(" , ") : ""));
      }
    }
    console.log("[wua] 共发现相关类 " + W.discovered_classes.length + " 个");
  } catch(e){ console.log("[wua] 类发现失败: " + e); }

  // ---------------------------------------------------------
  // 阶段二(a):抓 wua/x-sign 最终密文(请求头)
  // ---------------------------------------------------------
  var SIGN_KEYS = /^(wua|x-sign|x-mini-wua|x-umt|x-sgext|x-features|x-app-conf-v|umid|x-sign-type)$/i;

  // hook NSMutableURLRequest setValue:forHTTPHeaderField:
  try {
    var m = ObjC.classes.NSMutableURLRequest["- setValue:forHTTPHeaderField:"];
    Interceptor.attach(m.implementation, {
      onEnter(args){
        try {
          var field = new ObjC.Object(args[3]).toString();
          if (SIGN_KEYS.test(field)) {
            var val = args[2].isNull() ? "(nil)" : new ObjC.Object(args[2]).toString();
            W.sign_headers.push({ ts: nowISO(), field: field,
              len: val.length, value: val.slice(0, 200) });
            console.log("[wua][密文header] " + field + " (len=" + val.length + ") = " + val.slice(0,80) + "...");
          }
        } catch(e){}
      }
    });
    console.log("[wua] 已 hook setValue:forHTTPHeaderField:");
  } catch(e){}

  // mtop 内部常把签名放进参数字典,hook 常见的 addData/setValue
  ["MtopRequest","TBNetworkRequest","AMPRemoteBusiness"].forEach(function(c){
    if (!ObjC.classes[c]) return;
    try {
      ObjC.classes[c].$ownMethods.forEach(function(sel){
        if (/addData|setValue|setExtHeader|dataParams|sign/i.test(sel)) {
          try {
            var full = (sel[0]==="-"||sel[0]==="+") ? sel : "- " + sel;
            Interceptor.attach(ObjC.classes[c][full].implementation, {
              onEnter(args){
                try {
                  // 粗抓:看参数里有没有含 wua 的
                  for (var k=2;k<4;k++){
                    if (args[k] && !args[k].isNull()){
                      var s = new ObjC.Object(args[k]).toString();
                      if (/wua|x-sign/i.test(s)) {
                        W.notes.push({ ts:nowISO(), src:c+" "+sel, snippet:s.slice(0,200) });
                      }
                    }
                  }
                } catch(e){}
              }
            });
          } catch(e){}
        }
      });
    } catch(e){}
  });

  // ---------------------------------------------------------
  // 阶段二(b):hook 发现的签名方法入口,打印入参(可能是明文)
  // ---------------------------------------------------------
  function dumpArg(label, ptr){
    try {
      var o = new ObjC.Object(ptr);
      var s = o.toString();
      if (s && s.length > 1) {
        var rec = { ts: nowISO(), src: label, cls: o.$className || "?",
                    len: s.length, data: s.slice(0, 3000) };
        W.sign_inputs.push(rec);
        console.log("[wua][★签名入参] " + label + " (" + rec.cls + ", len=" + s.length + ")\n    " + s.slice(0, 300));
      }
    } catch(e){}
  }

  W.discovered_classes.forEach(function(entry){
    entry.methods.forEach(function(sel){
      try {
        var full = (sel[0]==="-"||sel[0]==="+") ? sel : "- " + sel;
        var mm = ObjC.classes[entry.cls][full];
        if (!mm) return;
        var argc = (sel.match(/:/g) || []).length;
        Interceptor.attach(mm.implementation, {
          onEnter(args){
            for (var k = 2; k < 2 + argc; k++) {
              dumpArg(entry.cls + " " + sel + " arg" + (k-2), args[k]);
            }
          }
        });
      } catch(e){}
    });
  });

  // ---------------------------------------------------------
  // 落盘
  // ---------------------------------------------------------
  function dumpWua(){
    try {
      var tmpDir = ObjC.classes.NSFileManager.defaultManager()
        .temporaryDirectory().path().toString();
      var fp = tmpDir + "/fm_wua.json";
      ObjC.classes.NSString.stringWithString_(JSON.stringify(W, null, 2))
        .writeToFile_atomically_encoding_error_(fp, 1, 4, NULL);
      console.log("[wua][dump] " + fp +
        " (发现类=" + W.discovered_classes.length +
        ", 密文header=" + W.sign_headers.length +
        ", 签名入参=" + W.sign_inputs.length + ")");
    } catch(e){ console.log("[wua][dump] 失败: " + e); }
  }
  globalThis.dumpWua = dumpWua;
  setInterval(dumpWua, 30000);

  console.log(">>> wua-probe 已加载。操作 app(搜索/翻页/刷新触发签名),然后 dumpWua()。<<<");
  console.log(">>> 先看 [发现类] 输出,把真实的 SecurityGuard/wua 类名贴回以便精确 hook。<<<");
}
