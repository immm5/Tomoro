# Tomoro Coffee — Auto Register

Script Python untuk auto-register akun Tomoro Coffee ID (via OTP provider /
manual). Sesudah patch September 2026, API Tomoro di belakang **Aliyun WAF**:
semua request MUST header `wToken`, gesign oleh native `libtiger_tally.so`
(TigerTally SDK). Python saja tidak bisa kalkulasi → solusi: **frida bridge ke
rooted phone** yang memanggil `TigerTallyAPI.vmpSign` dan serve token via local
HTTP daemon.

## Alur

```
rooted phone (Tomoro app jalan)
   ├─ frida-server (port 27042)
   ├─ adb forward tcp:27042  (PC <-> phone)
   └─ tigertally_bridge/signer_daemon.py  → http://127.0.0.1:8642/sign

tomoro.py  →  SIGNER.sign(body_bytes)  →  header wToken  →  API accept
```

`TomoroClient._req()` sign EXACT serde body bytes (sama dengan app interceptor:
`json.dumps(separators=(",", ":"))` → UTF-8 → `vmpSign(1, bytes)`).
GET request → sign string kosong `""`. Re-stringify setelah signing = signature break!

## Relay modus (WAF client-pin omzeilen)

Sinds de debugsessies blockt Aliyun WAF ook de app zelf (server-side,
devices/sessie/IP-afhankelijk). De robuuste weg: **stuur elke request VIA de
app** — frida relay swapped de URL/method/body in de app's EIGEN OkHttp, de
app tekent wToken zelf (vmpSign + 2s cooldown) en de response komt terug.

```
tomoro.py (USE_RELAY=1) → POST /relay → app's OkHttp + interceptor → response
```

Gebruik: `.env` `USE_RELAY=1`. De app moet op de phone draaien EN verkeer
maken binnen ~40s (elke UI-tap telt), anders /relay-wait timeout.

## Setup (ker)

1. Rooted phone + app Tomoro installed & **jalan**.
2. frida-server di phone (see start_bridge.bat):
   - push `frida-server-arm64` → `/data/local/tmp/frida-server`
   - start: `setsid /data/local/tmp/frida-server >/dev/null 2>&1 &`
   - forward: `adb forward tcp:27042 tcp:27042`
3. Node dep pake bridge (ker):
   ```
   cd tigertally_bridge
   npm install frida-java-bridge frida-compile
   npx frida-compile hook.js -o _compiled.js
   ```
4. Start daemon:
   ```
   start_bridge.bat        # atau manual:
   python tigertally_bridge/signer_daemon.py --port 8642
   ```
5. `.env`: `USE_SIGNER=1`, `SIGNER_URL=http://127.0.0.1:8642` (default ok).

## Run

```
python tomoro.py                      # interaktif (hero-sms / manual)
python tomoro.py --phone 83878107651  # manual single
python tomoro.py --otp-provider hero-sms --count 5 --workers 3
```

## Config (.env — see .env.example)

| Variabel | Default | Tujuan |
|---|---|---|
| USE_SIGNER | 1 | 1 = wToken lewat frida bridge per request |
| USE_RELAY | 0 | 1 = request VIA app (phone OkHttp) — omzeilt WAF pin |
| SIGNER_URL | http://127.0.0.1:8642 | local bridge daemon |
| SIGNER_TIMEOUT/RETRIES | 15 / 3 | timeout bridge call |
| WTOKEN_PASSTHRU | (kosong) | fallback wToken kalau USE_SIGNER=0 |
| HERO_SMS_* | — | setting OTP provider |
| PROXY_* | — | proxy (proxy.txt) — precheck signed juga |

## Troubleshooting

- `405 challenge / aliyun_waf_aa` di log → request zonder wToken valid.
  Cek: signer daemon jalan? App di phone aktive? `curl http://127.0.0.1:8642/health`.
- Daemon `ping → no-class` → app (re)start, lalu daemon restart.
- Proxy suspect: `precheck_proxy` signed juga — 405-WAF tidak lagi "proxy mati".

## Nota reverse (sept 2026)

See `NOTES.md` — analisi full: tipe WAF-challenge, TigerTally SDK,
shape interceptor, lokasi capture file (Reqable), skill relevan.