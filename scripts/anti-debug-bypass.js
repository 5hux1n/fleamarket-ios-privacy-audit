/* ============================================================
   反调试绕过 (anti-debug-bypass.js)
   —— 最先加载,中和常见反调试,提高 spawn 成功率。
   用法(放在 -l 链的最前面):
     frida -U -f com.taobao.fleamarket -l anti-debug-bypass.js -l <其他脚本...> --no-pause
   说明:闲鱼还用 svc 直系统调用绕过符号,本脚本只覆盖符号级 ptrace/sysctl,
   不保证一定不被杀;若 spawn 仍闪退,改用 attach(手动开 app 后立刻 -n 闲鱼)。
   ============================================================ */

// 1) ptrace(PT_DENY_ATTACH):让其恒成功返回 0
var ptrace = Module.findExportByName(null, "ptrace");
if (ptrace) {
  try {
    Interceptor.replace(ptrace, new NativeCallback(function(request, pid, addr, data){
      return 0;
    }, 'int', ['int','int','pointer','pointer']));
    console.log("[anti-debug] ptrace 已中和");
  } catch(e){ console.log("[anti-debug] ptrace replace 失败: " + e); }
}

// 2) sysctl:清除 P_TRACED 标志位(kinfo_proc.kp_proc.p_flag)
var P_TRACED = 0x00000800;
var sysctl = Module.findExportByName(null, "sysctl");
if (sysctl) {
  Interceptor.attach(sysctl, {
    onEnter(args){ this.oldp = args[2]; },
    onLeave(ret){
      try {
        if (this.oldp && !this.oldp.isNull()) {
          // kinfo_proc 偏移:p_flag 在结构体起始 +32(x64/arm64 常见布局)
          var p_flag = this.oldp.add(32).readU32();
          if (p_flag & P_TRACED) {
            this.oldp.add(32).writeU32(p_flag & ~P_TRACED);
          }
        }
      } catch(e){}
    }
  });
  console.log("[anti-debug] sysctl P_TRACED 清除已挂载");
}

// 3) getppid:部分检测比对父进程;返回 1(launchd)以绕过
var getppid = Module.findExportByName(null, "getppid");
if (getppid) {
  try {
    Interceptor.replace(getppid, new NativeCallback(function(){
      return 1;
    }, 'int', []));
    console.log("[anti-debug] getppid 已中和(返回1)");
  } catch(e){ console.log("[anti-debug] getppid replace 失败: " + e); }
}

console.log(">>> anti-debug-bypass 已加载(符号级)。若 spawn 仍被杀,改用 attach。 <<<");
