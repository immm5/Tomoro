# Tomoro — Nota Reverse Engineering (Sept 2026)

Tujuan: fix script auto-register `tomoro.py` yang sesudah serverpatch return
"not allowed".

## Root cause

Tomoro taruh **Aliyun WAF** di depan API gateway (`api-service.tomoro-coffee.id`).
Sekit ~sept 2026, ELK request API butuh `wToken` header valid, disign oleh
**TigerTally SDK** (`com.aliyun.TigerTally`, native `libtiger_tally.so`).

- Tanpa wToken valid → server return WAF-challenge:
  - HTML (client browser-achtig): slider/JS-challenge `aliyun_waf_aa` / `acw_tc`
  - JSON (`{"retCode":0,"token":"0338...","data":"..."}`) pake client app-achtig
- Issue migrasi: headers request yang di-clone lama tidak include `wToken` (atau
  kosong via `WTOKEN_PASSTHRU`), jadi WAF block → "not allowed".

## Bewijs

- **HAR lama** (`old/Tomoro Reg.har`, flow berfungsi tot 2026-08-24): app send
  `wToken: 0004_<64 hex>` + handshake `cloudauth-device.aliyuncs.com` TLog1/TLog2
  dengan `AccessKeyId=LTAI5tMRsqNQuoAexzYgn3Kq` (TigerTally device-auth).
- **Dex** (`apk/com.tomoro.../classes*.dex`): interceptor `common/config/i.java`
  ```java
  String strVmpSign = TigerTallyAPI.vmpSign(1, bytes);   // bytes = request body UTF-8
  aVarA4.a("wToken", strVmpSign);
  ```
  `TigerTallyAPI.vmpSign` → `B.genericNt3(i2, bArr)` → `System.loadLibrary("tiger_tally")`
  → native.
- **Test live**: python-request TANPA wToken → 405 WAF-challenge. KUMBUK wToken
  valid (dari app di phone lewat frida) → 200 dengan JSON real `{"code":0,"msg":"success"}`.

## Solusi (implemented)

Frida-bridge yang kalkulasi signature ECHT di rooted phone:

```
tigertally_bridge/
  hook.js           — frida-java-bridge: resolve TigerTallyAPI, expose sign()
  _compiled.js      — compiled (npx frida-compile hook.js -o _compiled.js)
  signer_daemon.py  — daemon python: attach app, POST /sign → wToken
```

Flow PC↔phone: frida-server di phone (port 27042) → `adb forward tcp:27042` →
daemon memanggil `TigerTallyAPI.vmpSign(type, bytes)` → return wToken.

`tomoro.py` `_req()` sign EXACT body-bytes (`vmpSign(1, bytes)`, GET = kosong).
Requirement: app Tomoro MUST jalan di phone (kelas resolve).

## Onderdelen die UNIQUE per omgeving

- `frida-server-android-arm64` — frida-server remote puur (no agent needed)
- `start_bridge.bat` — push/start/forward/daemon dalam 1 stap
- Catanan frida: frida 17 tidak global `Java` — pakai `frida-java-bridge` (npm)
  + `npx frida-compile` (see skill frida-native-sign-bridge)

## Kalau wToken nanti sudah tidak required

- Set `USE_SIGNER=0` di `.env`; script fallback ke `WTOKEN_PASSTHRU` + request plain.

## Info tamba / ingat

- HAR lama di `old/`, onderzoek apk di `apk/` (output jadx di `jadx_out/`, tidak commit).
- Page 405-WAF punya cookie `aliyungf_tc` + `acw_tc` — belum cukup, challenge
  harus solved.
- Lokasi capture Reqable: `%APPDATA%\Reqable\box` (objectbox LMDB) +
  `%APPDATA%\Reqable\capture` (body JSON plain) — alternatif HAR.