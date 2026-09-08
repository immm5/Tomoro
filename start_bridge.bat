@echo off
rem ============================================================
rem  Tomoro TigerTally signer bridge - start daemon op rooted phone
rem  Vereist: root + frida-server op phone (eenmalig gebundeld),
rem  Tomoro app MOET draaien op de phone.
rem ============================================================
cd /d %~dp0

echo [1/4] push frida-server naar phone (alleen eerste keer nodig)...
adb -s 81c5860 shell "su -c 'test -x /data/local/tmp/frida-server || echo MISSING'"

echo [2/4] start frida-server op phone (als nog niet actief)...
adb -s 81c5860 shell "su -c 'pgrep -f /data/local/tmp/frida-server >/dev/null 2>&1 || (setsid /data/local/tmp/frida-server >/dev/null 2>&1 < /dev/null &)'"

echo [3/4] forward poort 27042 (frida) van phone naar PC...
adb -s 81c5860 forward tcp:27042 tcp:27042

echo [4/4] start signer daemon (houd deze terminal open)...
cd tigertally_bridge
python signer_daemon.py --port 8642