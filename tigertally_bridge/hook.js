import Java from 'frida-java-bridge';

let classTT = null;
let ready = null;

// Resolve the TigerTallyAPI class once the JVM is available.
function init() {
  return new Promise((resolve) => {
    Java.perform(() => {
      try {
        classTT = Java.use('com.aliyun.TigerTally.TigerTallyAPI');
        console.log('[hook] resolved TigerTallyAPI');
        resolve();
      } catch (e) {
        console.error('[hook] resolve failed: ' + e);
        resolve();  // let ping report status
      }
    });
  });
}

ready = init().catch(() => {});

rpc.exports = {
  ping: () => (classTT ? 'pong' : 'no-class'),
  // body: utf8 string of the exact request body bytes; type: int (interceptor uses 1)
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
  // vmpHash variant (requestType ordinal + bytes)
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
  session: async () => {
    await ready;
    if (!classTT) return 'ERR:no-class';
    try { return String(classTT.getSessionId()); } catch (e) { return 'ERR:' + String(e); }
  },
  version: async () => {
    await ready;
    if (!classTT) return 'ERR:no-class';
    try { return String(classTT.getVersion()); } catch (e) { return 'ERR:' + String(e); }
  },
};