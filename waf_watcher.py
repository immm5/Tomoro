"""WAF-cooldown watcher — draai als cron.

Poll getPhoneArea via de frida-bridge (verse wToken). Print ALLEEN
als de server 200 teruggeeft (ban verlopen). Bij 405/error: stil.
Zo blijft het volume minimaal en verlengt de poll de ban niet.
"""
import os, sys, json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tomoro as T

if not T.SIGNER.available:
    sys.exit(0)  # bridge down — stil, niks te rapporteren

persona = T.gen_persona()
cli = T.TomoroClient(persona)
try:
    r = cli.get_phone_area()
    print(f"WAF UNBLOCKED 200: {json.dumps(r)[:400]}")
except Exception as e:
    # 405 / relay idle / netwerk-fout — geen ban-verloop, blijf stil
    sys.exit(0)