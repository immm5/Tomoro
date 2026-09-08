"""TigerTally wToken signer daemon.

Bridges libtiger_tally.so vmpSign on a rooted Android phone to local HTTP.
Attaches to the running Tomoro app process via frida (adb forward 27042).

Endpoints:
  GET  /health          -> {"ok": true, "pid": <tomoro pid>}
  POST /sign            -> {"wToken": "0004_..."}   body: {"body": "<utf8 body>", "type": 1}
  POST /hash            -> {"wToken": "..."}        body: {"body": ..., "type": 0}
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
COMPILED = os.path.join(HERE, "_compiled.js")
PKG = "com.tomoro.indonesia.android"

import frida  # noqa: E402


class Signer:
    def __init__(self, device_host="127.0.0.1:27042", pkg=PKG, attach=True):
        self.device_host = device_host
        self.pkg = pkg
        self.dev = None
        self.session = None
        self.script = None
        self.pid = None
        self.lock = threading.Lock()
        self.attach = attach

    def _get_device(self):
        if self.device_host:
            return frida.get_device_manager().add_remote_device(self.device_host)
        return frida.get_usb_device(timeout=10)

    def _resolve_pid(self):
        procs = self.dev.enumerate_processes()
        best = None
        for p in procs:
            nm = (p.name or "").lower()
            if self.pkg in nm or "tomoro" in nm:
                if "xg_vip" in nm:
                    continue
                best = p.pid
                break
        return best

    def _ensure_attached(self):
        """Re-attach if the app restarted (PID changed / session dead)."""
        if self.session is not None:
            try:
                self.script.exports_sync.ping()
                return
            except Exception:
                pass
        # try clean detach first
        for s in (self.session,):
            try:
                if s is not None:
                    s.detach()
            except Exception:
                pass
        if self.attach:
            self.pid = self._resolve_pid()
            if self.pid is None:
                raise RuntimeError(f"{self.pkg} not running (restart the app)")
        self.session = self.dev.attach(self.pid)
        with open(COMPILED, "r", encoding="utf-8") as f:
            src = f.read()
        self.script = self.session.create_script(src)
        self.script.on("message", self._on_message)
        self.script.load()
        time.sleep(5)
        try:
            ping = self.script.exports_sync.ping()
            print(f"[signer] reattached pid={self.pid} ping={ping}", flush=True)
        except Exception as e:
            print(f"[signer] reattach ping failed: {e}", flush=True)

    def start(self):
        self.dev = self._get_device()
        if self.attach:
            self.pid = self._resolve_pid()
            if self.pid is None:
                print(f"[signer] {self.pkg} not running, spawning...", flush=True)
                self.pid = self.dev.spawn([self.pkg])
                self.session = self.dev.attach(self.pid)
                self.dev.resume(self.pid)
            else:
                self.session = self.dev.attach(self.pid)
        else:
            self.pid = self.dev.spawn([self.pkg])
            self.session = self.dev.attach(self.pid)
            self.dev.resume(self.pid)

        with open(COMPILED, "r", encoding="utf-8") as f:
            src = f.read()
        self.script = self.session.create_script(src)
        self.script.on("message", self._on_message)
        self.script.load()
        # give the JVM a moment to resolve the class
        time.sleep(5)
        try:
            ping = self.script.exports_sync.ping()
            print(f"[signer] ping -> {ping}", flush=True)
        except Exception as e:
            print(f"[signer] ping failed: {e}", flush=True)
        return self.pid

    def _on_message(self, message, data):
        if message.get("type") == "error":
            print("[signer] JS error:", message.get("stack") or message.get("description"), flush=True)
        else:
            print("[signer] JS:", message.get("payload"), flush=True)

    def sign(self, body: str, typ: int = 1) -> str:
        with self.lock:
            self._ensure_attached()
            return self.script.exports_sync.sign(typ, body)

    def health(self) -> dict:
        try:
            self._ensure_attached()
            return {"pid": self.pid, "ping": self.script.exports_sync.ping() if self.script else None}
        except Exception as e:
            return {"pid": self.pid, "ping": f"ERR:{e}"}


class Handler(BaseHTTPRequestHandler):
    signer: Signer = None  # type: ignore[assignment]

    def log_message(self, *a):  # silence
        pass

    def _json(self, code, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            try:
                h = self.signer.health()
                self._json(200, {"ok": True, **h})
            except Exception as e:
                self._json(500, {"ok": False, "error": str(e)})
        elif self.path == "/appInfo":
            try:
                self._json(200, {"ok": True, "info": self.signer.script.exports_sync.appinfo()})
            except Exception as e:
                self._json(500, {"ok": False, "error": str(e)})
        elif self.path == "/lastheaders":
            try:
                self._json(200, self.signer.script.exports_sync.lastheaders())
            except Exception as e:
                self._json(500, {"ok": False, "error": str(e)})
        elif self.path == "/devicecode":
            try:
                self.signer._ensure_attached()
                self._json(200, {"ok": True, "deviceCode": self.signer.script.exports_sync.devicecode()})
            except Exception as e:
                self._json(500, {"ok": False, "error": str(e)})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        ln = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(ln) if ln else b"{}"
        try:
            data = json.loads(raw)
        except Exception:
            data = {}
        body = data.get("body", "")
        typ = int(data.get("type", 1))
        if self.path == "/sign":
            try:
                out = self.signer.sign(body, typ)
                self._json(200, {"ok": True, "wToken": out})
            except Exception as e:
                self._json(500, {"ok": False, "error": str(e)})
        else:
            self._json(404, {"error": "not found"})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8642)
    ap.add_argument("--device", default="127.0.0.1:27042")
    ap.add_argument("--pkg", default=PKG)
    ap.add_argument("--spawn", action="store_true", help="spawn instead of attach")
    args = ap.parse_args()

    signer = Signer(args.device, args.pkg, attach=not args.spawn)
    Handler.signer = signer
    pid = signer.start()
    print(f"[signer] attached to {args.pkg} pid={pid}, listening :{args.port}", flush=True)

    httpd = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        try:
            signer.session.detach()
        except Exception:
            pass


if __name__ == "__main__":
    main()
