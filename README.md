# iOS Privacy Audit — Xianyu (闲鱼) Client

A reproducible static + dynamic reverse-engineering study of the privacy behavior of the
Xianyu (闲鱼) iOS client `7.28.60`, verified across two jailbroken devices.

The goal of this repo is not to find scandal. Most of what a large Chinese app does is
industry-standard and is declared in its privacy documents. The value here is a
**reproducible, evidence-graded method**: every claim is tagged with how strong its
evidence is, and conclusions are deliberately narrowed to the few points that survive
cross-checking against the official privacy policy, the third-party SDK list, and the
system permission statements.

> **Full writeup (中文)**: [blog post](https://shuxin.my/p/a78d2829-8982-4add-b6d3-db1550f23c44) · also mirrored in [`docs/writeup_zh.md`](docs/writeup_zh.md)

---

## Method

"Static casts a wide net, dynamic confirms, every conclusion is graded." The core
principle is to **separate observation from conclusion**: static analysis can show a
behavior *exists in code*; it cannot show the behavior *actually runs at runtime*.
Dynamic instrumentation confirms which code paths actually execute.

- **Static**: Ghidra — symbols, strings, cross-references on the dumped Mach-O main binary.
- **Dynamic**: Frida + objection — hooks on Keychain ops, syscalls, device-attribute APIs,
  URL-scheme probing, and network requests; results are written out as structured JSON.
- **Cross-check**: runtime behavior compared line-by-line against the official privacy
  policy, third-party SDK disclosure, and permission statements (iOS / HarmonyOS / Android).

### Evidence grading

| Grade | Meaning |
| --- | --- |
| 🟩 Static-confirmed | Provable from symbols / plist / official docs, no runtime needed |
| 🟢 Dynamically confirmed | Static anchor + runtime hit |
| 🟡 High-confidence inference | Strong static evidence + known industry behavior; not runtime-confirmed |
| 🟠 Unverified inference | Plausible but no runtime evidence; explicitly flagged |
| ⚪ Not reproduced | Expected to be dynamically verifiable, but not triggered this round |

A principle held throughout: **state the behavior when it's confirmed; do not state a
motive that isn't.** For a reporting domain we can say "data was observed being sent
there"; we do not say "the domain is deliberately hidden" without evidence.

---

## Findings (summary)

| # | Area | Finding | Grade |
| --- | --- | --- | --- |
| 1 | App-list enumeration | Cold-start, no interaction: 50+ `canOpenURL:` scheme probes within 75ms, matching `LSApplicationQueriesSchemes` 100%. Declared in the SDK list, **but the iOS permission statement omits it while the HarmonyOS one declares it** — cross-platform disclosure gap. | 🟢 |
| 2 | Self-built identifiers | `vimei`/`vimsi`/`udid` written to Keychain. Tested **pseudo-random** (regenerate to fresh values after wipe/reinstall; `randomStrWithCount:15`), resettable, not hardware-derived. Not declared in any privacy document. | 🟢 |
| 3 | IDFV isolation | Xianyu / Taobao / Alipay IDFVs are **all different** (different Team IDs). iOS vendor is keyed on signing Team ID, not bundle prefix. Reinstalling Xianyu yields a fresh IDFV. This is *why* vendors build private fingerprints. | 🟢 |
| 4 | Network exfiltration | Runtime-in-use domains: UT telemetry (mmstat), Alipay security gateway, Umeng, AMap. | 🟢 |
| 5 | `puata.info` attribution | Traced to **Umeng** via ICP registration (same entity as umtrack/umengcloud) + binary source path (`UMCommon_iOS/.../UMNetworkWork.m`). | 🟢 |
| 6 | Self-protection | Jailbreak existence-checks, proxy detection, anti-injection (fishhook). Standard RASP for finance/e-commerce apps — environment-trust checks, not a privacy violation. | 🟩 |
| 7 | Keychain access group | All items under Xianyu's own Team ID; **no cross-app sharing** with Alipay. | 🟢 |

> For the complete itemized data, see [`data/scanned_apps.md`](data/scanned_apps.md) (full 50-app scheme audit) and [`data/notable_paths.md`](data/notable_paths.md) (filtered security and sensitive paths).

### What actually warrants scrutiny (narrowed)

1. Self-built pseudo-random identifiers persisted in Keychain, undisclosed in any policy.
2. Cross-platform disclosure gap: app-list capability declared on HarmonyOS, omitted on iOS.
3. Declared-vs-actual purpose gaps (e.g. IDFA declared for splash ads, also read by the
   risk-control module).
4. The persistent tracking anchor is **not** the resettable vimei/IDFV, but immutable
   hardware-combination features + server-side clustering — which is this study's blind spot.

### Limits (honestly stated)

- `wua` / `x-sign` signature payloads are ciphertext (whitebox crypto + obfuscation); their
  plaintext composition was **not** confirmed locally.
- Server-side behavior (risk scoring, device history correlation) is a black box.

---

## Scripts

All scripts are passive observers: they read and record app behavior only. None modify app
data or transmit anything externally. They are written for Frida (iOS, jailbroken).

| Script | Purpose |
| --- | --- |
| `scripts/audit-all.js` | All-in-one: file writes, device-info reads, app-list probes, jailbreak paths, network, self-protection |
| `scripts/applist-probe.js` | App-list enumeration specialist; auto-discovers real class names, detects burst scans |
| `scripts/keychain-probe.js` | Real-time SecItemAdd/Update capture (key, value, caller) |
| `scripts/jailbreak-probe.js` | Jailbreak-detection panorama; distinguishes existence-check vs directory-enumeration |
| `scripts/vimei-trace.js` | Traces vimei/vimsi generation — records device features read before write + deep backtrace |
| `scripts/idfv-compare.js` | Cross-app / cross-account IDFV comparison |
| `scripts/wua-probe.js` | wua/x-sign signature tracing (auto-discovery stage) |
| `scripts/anti-debug-bypass.js` | Symbol-level anti-debug neutralization (load first for spawn) |
| `scripts/merge_audit_report.py` | Merges dynamic JSON + static conclusions into a graded report |

### Reproduce

```bash
# jailbroken device, frida-server running, Xianyu installed (com.taobao.fleamarket)
frida -U -n 闲鱼 -l scripts/audit-all.js
# operate the app across login / search / browse / publish / share, then in console:
dump()
# then merge:
python3 scripts/merge_audit_report.py fm_audit.json -o report.md
```

See [`docs/writeup_zh.md`](docs/writeup_zh.md) for the full narrative and per-finding detail.
`data/sample_output.json` shows the output JSON shape (desensitized).

---

## Disclaimer

See [`DISCLAIMER.md`](DISCLAIMER.md). In short: this is privacy-audit research on an app
legally installed on the author's own devices, analyzing only the author's own account. All
device identifiers are desensitized. **This repo contains no binary, no decrypted IPA, and
no copyrighted code** — only the author's own analysis scripts and desensitized findings.
Scripts are MIT-licensed; see [`LICENSE`](LICENSE).
