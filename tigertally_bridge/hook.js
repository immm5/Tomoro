import Java from 'frida-java-bridge';

let classTT = null;
let u0Class = null;
let deviceCode = 'unknown';
let relay = null;
let relayResp = null;
let relaySeq = 0;
let ready = null;

function init() {
  return new Promise((resolve) => {
    Java.perform(() => {
      try {
        classTT = Java.use('com.aliyun.TigerTally.TigerTallyAPI');
        const vs = classTT.vmpSign;
        if (vs && typeof vs.implementation !== 'undefined') {
          vs.implementation = function (type, bytes) {
            let out = null;
            try {
              out = vs.apply(this, arguments);
              let bodyStr = '';
              try { bodyStr = String(bytes); } catch (e) { bodyStr = '<bytes>'; }
              console.log('[SIGN] type=' + type + ' body=' + bodyStr.slice(0, 120));
            } catch (e) {
              console.log('[SIGN] err=' + e);
            }
            return out;
          };
        }
      } catch (e) {
        console.error('[hook] resolve TigerTallyAPI failed: ' + e);
      }
      try {
        u0Class = Java.use('com.tomoro.indonesia.common.tools.u0');
        const m = u0Class.m;
        if (m && typeof m.implementation !== 'undefined') {
          m.implementation = function () {
            let out = null;
            try {
              out = m.apply(this, arguments);
              deviceCode = String(out);
            } catch (e) {
              deviceCode = 'ERR:' + e;
            }
            return out;
          };
        }
      } catch (e) {
        console.error('[hook] resolve u0 failed: ' + e);
      }
      // ---- request interceptor (signs wToken) ----
      try {
        const I = Java.use('com.tomoro.indonesia.common.config.i');
        const m2 = I.c;
        if (m2 && typeof m2.implementation !== 'undefined') {
          m2.implementation = function (request, chain) {
            if (relay) {
              const r = relay;
              relay = null;
              relaySeq++;
              const seq = relaySeq;
              try {
                const b = request.o(); // j0.a builder copy
                b.I(r.url); // swap url
                let bodyK0 = null;
                if (r.body && r.body.length > 0) {
                  const d0 = Java.use('okhttp3.d0').e.d('application/json; charset=utf-8');
                  bodyK0 = Java.use('okhttp3.k0').Companion.c(r.body, d0);
                }
                b.t(r.method, bodyK0);
                console.log('[RLY] swap -> ' + r.method + ' ' + r.url + ' seq=' + seq);
                return m2.apply(b.b(), chain); // i.c re-signs wToken over OUR body
              } catch (e) {
                console.log('[RLY] build failed ' + e + ' seq=' + seq);
                relayResp = { ok: false, seq: seq, error: String(e) };
                relay = null;
                return m2.apply(this, arguments);
              }
            }
            return m2.apply(this, arguments);
          };
          console.log('[hook] hooked request interceptor c() + relay');
        }
      } catch (e) {
        console.error('[hook] interceptor hook failed: ' + e);
      }
      // ---- response interceptor (captures relayed response) ----
      try {
        const I = Java.use('com.tomoro.indonesia.common.config.i');
        const ma = I.a;
        if (ma && typeof ma.implementation !== 'undefined') {
          ma.implementation = function (response, chain) {
            try {
              if (relaySeq > 0 && (relayResp === null || !relayResp.ok)) {
                const seq = relaySeq;
                const st = Number(response.T());
                let bodyStr = '';
                try {
                  const src = response.L().source();
                  const lv = src.f().d();
                  bodyStr = String(lv.Q0(Java.use('java.nio.charset.Charset').forName('UTF-8')));
                } catch (e2) {
                  bodyStr = 'ERR:' + e2 + ' | ' + String(response);
                }
                relayResp = { ok: true, seq: seq, status: st, body: bodyStr };
                console.log('[RLY] resp seq=' + seq + ' st=' + st + ' len=' + bodyStr.length);
              } else {
                console.log('[RESP] st=' + Number(response.T()));
              }
            } catch (e) {
              console.log('[RLY] resp hook err ' + e);
            }
            return ma.apply(this, arguments);
          };
          console.log('[hook] hooked response interceptor a()');
        }
      } catch (e) {
        console.error('[hook] response hook failed: ' + e);
      }
      resolve();
    });
  });
}

ready = init().catch(() => {});

rpc.exports = {
  ping: () => (classTT ? 'pong' : 'no-class'),
  sign: async (type, body) => {
    await ready;
    if (!classTT) return 'ERR:no-class';
    try {
      const bytes = Java.array('byte', Array.from(Buffer.from(body, 'utf-8')));
      const out = classTT.vmpSign(Number(type), bytes);
      return String(out);
    } catch (e) {
      return 'ERR:' + String(e);
    }
  },
  devicecode: async () => {
    await ready;
    return deviceCode;
  },
  setrelay: async (method, url, body, headers) => {
    await ready;
    relay = { method: method, url: url, body: body || '', headers: headers || {} };
    relayResp = null;
    relaySeq = 0;
    return 'queued';
  },
  getrelay: async () => {
    await ready;
    return relayResp ? JSON.stringify(relayResp) : 'null';
  },
};