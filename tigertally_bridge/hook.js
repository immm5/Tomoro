import Java from 'frida-java-bridge';

let classTT = null;
let u0Class = null;
let mMethod = null;
let deviceCode = 'unknown';
let lastUrl = 'none';
let lastHeaders = 'none';
let ready = null;

function init() {
  return new Promise((resolve) => {
    Java.perform(() => {
      try {
        classTT = Java.use('com.aliyun.TigerTally.TigerTallyAPI');
        console.log('[hook] resolved TigerTallyAPI');
        const vs = classTT.vmpSign;
        if (vs && typeof vs.implementation !== 'undefined') {
          vs.implementation = function (type, bytes) {
            let out = null;
            try {
              out = vs.apply(this, arguments);
              let bodyStr = '';
              try { bodyStr = String(bytes); } catch (e) { bodyStr = '<bytes>'; }
              console.log('[SIGN] type=' + type + ' body=' + bodyStr.slice(0,120));
              console.log('[SIGN] out=' + String(out));
            } catch (e) {
              console.log('[SIGN] err=' + e);
            }
            return out;
          };
          console.log('[hook] hooked vmpSign');
        }
      } catch (e) {
        console.error('[hook] resolve TigerTallyAPI failed: ' + e);
      }
      try {
        u0Class = Java.use('com.tomoro.indonesia.common.tools.u0');
        console.log('[hook] resolved u0');
        const m = u0Class.m;
        if (m && typeof m.implementation !== 'undefined') {
          mMethod = m;
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
          console.log('[hook] hooked u0.m() deviceCode getter');
        } else {
          console.log('[hook] u0.m not hookable: typeof=' + typeof m);
        }
      } catch (e) {
        console.error('[hook] resolve u0 failed: ' + e);
      }
      // Request interceptor capture — dump raw header map (incl. Cookie)
      try {
        const I = Java.use('com.tomoro.indonesia.common.config.i');
        const m2 = I.c;
        if (m2 && typeof m2.implementation !== 'undefined') {
          m2.implementation = function (req, chain) {
            try {
              // Emit full header map to console (log line in daemon stdout)
              try {
                const hs = req.headers();
                console.log('[CAP] url=' + String(req.url()));
                console.log('[CAP] headers=' + String(hs.toString()));
              } catch (e2) {
                console.log('[CAP] req=' + String(req) + ' | ' + e2);
              }
            } catch (e) {
              console.log('[CAP] ERR1:' + e);
            }
            return m2.apply(this, arguments);
          };
          console.log('[hook] hooked request interceptor c()');
        } else {
          console.log('[hook] i.c not hookable: ' + typeof m2);
        }
      } catch (e) {
        console.error('[hook] interceptor hook failed: ' + e);
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
  hash: async (type, body) => {
    await ready;
    if (!classTT) return 'ERR:no-class';
    try {
      const bytes = Java.array('byte', Array.from(Buffer.from(body, 'utf-8')));
      const out = classTT.vmpHash(Number(type), bytes);
      return String(out);
    } catch (e) {
      return 'ERR:' + String(e);
    }
  },
  devicecode: async () => {
    await ready;
    return deviceCode;
  },
  lastheaders: async () => {
    await ready;
    return JSON.stringify({ url: lastUrl, headers: lastHeaders, deviceCode: deviceCode });
  },
};