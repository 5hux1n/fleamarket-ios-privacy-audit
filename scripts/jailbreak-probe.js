/* ============================================================
   闲鱼 越狱检测机制 全景探针 (jailbreak-probe.js)
   回答三问:用哪些手段探测 / 结果是否持久化 / 是否上报
   用法(可与其他脚本并行):
     frida -U -n 闲鱼 -l jailbreak-probe.js
   输出:控制台实时 + 落盘 tmp/fm_jailbreak.json
   dumpJB() 随时落盘。
   ============================================================ */

var JB = {
  started: new Date().toISOString(),
  file_checks: {},     // ① 文件/目录存在探测 path->次数
  write_tests: {},     // ② 沙盒外可写性测试
  scheme_checks: {},   // ③ cydia:// 等 scheme 探测
  dyld_scans: 0,       // ④ dylib 遍历次数
  env_checks: {},      // ⑤ getenv 查环境变量
  fork_tests: 0,       // ⑥ fork 测试
  symlink_checks: {},  // ⑦ 符号链接检测
  sysctl_checks: {},   // ⑧ sandbox/P_TRACED
  antidebug: {},       // ⑨ ptrace/getppid
  detector_returns: [],// 越狱判定函数的返回值(若命中)
  suspicious_persist: [], // 疑似把越狱标志写入 Keychain/文件
  // —— 区分探测方式 ——
  existence_probes: {},// ①只查存在(stat/access/fopen 已在 file_checks,这里汇总计数)
  dir_enumerations: {},// ②枚举目录内容(readdir/contentsOfDirectory) path->次数  ★越界信号
  file_reads: {}       // ③读取文件内容(fread/dataWithContentsOfFile) path->次数
};

// 越狱特征路径/关键词
var JB_PATHS = /cydia|MobileSubstrate|substrate|apt\b|\/bin\/|sshd|ssh\b|dpkg|sileo|zebra|checkra|unc0ver|dopamine|roothide|frida|cynject|cycript|\/etc\/apt|jailbreak|\.dylib/i;
var JB_ENV   = /DYLD_INSERT_LIBRARIES|DYLD_/i;
var PERSIST_JB_KEY = /jailbreak|jailbroken|isjb|\bjb\b|rooted|root_status|device_env|risk|sandbox|cydia/i;

function cstr(p){ try { return p.readUtf8String(); } catch(e){ return null; } }
function bump(obj, key){ if(key){ obj[key]=(obj[key]||0)+1; } }

if (!ObjC.available) { console.log("[jb] ObjC 不可用"); }

// ① 文件/目录存在探测(含 ⑦ 符号链接)
["stat","lstat","access","fopen","open"].forEach(function(fn){
  var p = Module.findExportByName(null, fn);
  if (!p) return;
  Interceptor.attach(p, {
    onEnter(args){
      var path = cstr(args[0]);
      if (path && JB_PATHS.test(path)) {
        bump(JB.file_checks, fn + ": " + path);
        if (console._jbverbose) console.log("[jb][文件探测] " + fn + " " + path);
      }
    }
  });
});
// lstat/readlink 归到符号链接检测
["readlink"].forEach(function(fn){
  var p = Module.findExportByName(null, fn);
  if (p) Interceptor.attach(p, { onEnter(args){
    var path = cstr(args[0]);
    if (path) bump(JB.symlink_checks, path);
  }});
});

// NSFileManager fileExistsAtPath: —— ①存在性
try {
  var fe = ObjC.classes.NSFileManager["- fileExistsAtPath:"];
  Interceptor.attach(fe.implementation, { onEnter(args){
    try { var pth = new ObjC.Object(args[2]).toString();
      if (JB_PATHS.test(pth)) { bump(JB.file_checks, "fileExistsAtPath: " + pth);
        bump(JB.existence_probes, pth); }
    } catch(e){}
  }});
} catch(e){}

// ② 目录枚举 —— ★这是"看目录下有什么",比存在性探测越界
// 底层 opendir/readdir
["opendir"].forEach(function(fn){
  var p = Module.findExportByName(null, fn);
  if (p) Interceptor.attach(p, { onEnter(args){
    var path = cstr(args[0]);
    if (path) { bump(JB.dir_enumerations, "opendir: " + path);
      if (JB_PATHS.test(path) || path === "/Applications" || path.indexOf("/var/containers") >= 0)
        console.log("[jb][★★目录枚举] opendir " + path + " (在列举目录内容,非仅查存在)"); }
  }});
});
// Foundation 层目录枚举
["- contentsOfDirectoryAtPath:error:","- contentsOfDirectoryAtURL:includingPropertiesForKeys:options:error:",
 "- enumeratorAtPath:","- subpathsOfDirectoryAtPath:error:","- subpathsAtPath:"].forEach(function(sel){
  try {
    var m = ObjC.classes.NSFileManager[sel];
    if (!m) return;
    Interceptor.attach(m.implementation, { onEnter(args){
      try { var pth = new ObjC.Object(args[2]).toString();
        bump(JB.dir_enumerations, sel + " " + pth);
        console.log("[jb][★★目录枚举] " + sel + " " + pth + " (列举目录内容)");
      } catch(e){}
    }});
  } catch(e){}
});

// ③ 读取文件内容 —— 区别于"只查存在"
["- dataWithContentsOfFile:","- stringWithContentsOfFile:encoding:error:",
 "- initWithContentsOfFile:"].forEach(function(sel){
  ["NSData","NSString"].forEach(function(cls){
    try {
      var m = ObjC.classes[cls] && ObjC.classes[cls][sel];
      if (!m) return;
      Interceptor.attach(m.implementation, { onEnter(args){
        try { var pth = new ObjC.Object(args[2]).toString();
          if (JB_PATHS.test(pth)) { bump(JB.file_reads, cls + sel + " " + pth);
            console.log("[jb][★读文件内容] " + pth); }
        } catch(e){}
      }});
    } catch(e){}
  });
});

// ② 沙盒外写文件测试
["- writeToFile:atomically:","- writeToFile:atomically:encoding:error:",
 "- writeToFile:options:error:"].forEach(function(sel){
  ["NSString","NSData"].forEach(function(cls){
    try {
      var m = ObjC.classes[cls] && ObjC.classes[cls][sel];
      if (!m) return;
      Interceptor.attach(m.implementation, { onEnter(args){
        try { var pth = new ObjC.Object(args[2]).toString();
          // 沙盒外 = 不在 Containers/Data 下
          if (pth.indexOf("/Containers/Data/") < 0 &&
              (pth.indexOf("/private/") === 0 || pth.indexOf("/var/") === 0 ||
               pth.indexOf("/tmp/") === 0 || JB_PATHS.test(pth))) {
            bump(JB.write_tests, cls + sel + " -> " + pth);
            console.log("[jb][★沙盒外写测试] " + pth);
          }
        } catch(e){}
      }});
    } catch(e){}
  });
});

// ③ scheme 探测(cydia:// 等)
try {
  var co = ObjC.classes.UIApplication["- canOpenURL:"];
  Interceptor.attach(co.implementation, { onEnter(args){
    try { var u = new ObjC.Object(args[2]).toString();
      if (/cydia|sileo|zebra|filza|jailbreak/i.test(u)) bump(JB.scheme_checks, u);
    } catch(e){}
  }});
} catch(e){}

// ④ dylib 遍历
["_dyld_image_count","_dyld_get_image_name"].forEach(function(fn){
  var p = Module.findExportByName(null, fn);
  if (p) Interceptor.attach(p, { onEnter(){ JB.dyld_scans++; } });
});

// ⑤ 环境变量
var ge = Module.findExportByName(null, "getenv");
if (ge) Interceptor.attach(ge, { onEnter(args){
  var n = cstr(args[0]);
  if (n && JB_ENV.test(n)) bump(JB.env_checks, n);
}});

// ⑥ fork 测试
["fork","vfork"].forEach(function(fn){
  var p = Module.findExportByName(null, fn);
  if (p) Interceptor.attach(p, { onEnter(){ JB.fork_tests++;
    console.log("[jb][★fork测试] 可能用于越狱检测"); } });
});

// ⑧ sysctl(sandbox / P_TRACED)
var sb = Module.findExportByName(null, "sysctlbyname");
if (sb) Interceptor.attach(sb, { onEnter(args){
  var n = cstr(args[0]);
  if (n && /sandbox|sentinel|proc|kern\.pro/i.test(n)) bump(JB.sysctl_checks, n);
}});

// ⑨ 反调试
["ptrace","getppid"].forEach(function(fn){
  var p = Module.findExportByName(null, fn);
  if (p) Interceptor.attach(p, { onEnter(){ bump(JB.antidebug, fn); } });
});

// 越狱判定函数返回值:hook 任意 ObjC 方法名含 jailbroken/jailbreak/isJail 的
try {
  var pat = /jailbro|jailbreak|isjail|rootcheck|isroot/i;
  for (var cn in ObjC.classes) {
    if (!ObjC.classes.hasOwnProperty(cn)) continue;
    try {
      var own = ObjC.classes[cn].$ownMethods;
      own.forEach(function(sel){
        if (pat.test(sel)) {
          var m = ObjC.classes[cn][sel];
          Interceptor.attach(m.implementation, {
            onLeave(ret){
              JB.detector_returns.push({ ts: new Date().toISOString(),
                cls: cn, sel: sel, ret: ret.toString() });
              console.log("[jb][★判定函数] " + cn + " " + sel + " => " + ret);
            }
          });
        }
      });
    } catch(e){}
  }
} catch(e){}

// 问2:持久化监控 —— hook SecItemAdd,若写入的 key/值含越狱关键词则标记
try {
  var add = Module.findExportByName("Security", "SecItemAdd");
  if (add) Interceptor.attach(add, { onEnter(args){
    try {
      var d = new ObjC.Object(args[0]).toString();
      if (PERSIST_JB_KEY.test(d)) {
        JB.suspicious_persist.push({ ts:new Date().toISOString(),
          where:"Keychain", snippet: d.slice(0,500) });
        console.log("[jb][★越狱标志疑似持久化->Keychain] " + d.slice(0,300));
      }
    } catch(e){}
  }});
} catch(e){}

function dumpJB(){
  try {
    var tmpDir = ObjC.classes.NSFileManager.defaultManager()
      .temporaryDirectory().path().toString();
    var fp = tmpDir + "/fm_jailbreak.json";
    ObjC.classes.NSString.stringWithString_(JSON.stringify(JB,null,2))
      .writeToFile_atomically_encoding_error_(fp,1,4,NULL);
    console.log("[jb][dump] " + fp +
      " (存在性探测=" + Object.keys(JB.existence_probes).length +
      ", ★目录枚举=" + Object.keys(JB.dir_enumerations).length +
      ", 读文件内容=" + Object.keys(JB.file_reads).length +
      ", dyld扫描=" + JB.dyld_scans +
      ", 判定函数命中=" + JB.detector_returns.length +
      ", 疑似持久化=" + JB.suspicious_persist.length + ")");
  } catch(e){ console.log("[jb][dump] 失败: " + e); }
}
globalThis.dumpJB = dumpJB;
setInterval(dumpJB, 30000);

console.log(">>> jailbreak-probe 已加载。冷启动走一遍,然后 dumpJB() <<<");
