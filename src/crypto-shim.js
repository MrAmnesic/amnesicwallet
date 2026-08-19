/* ══════════════════════════════════════════════════════════════════
   Adapter for the slip39 library, which is written for Node and uses
   its `crypto` module. In the browser that module does not exist, so
   this file reproduces only the three functions slip39 actually uses,
   backed by Web Crypto and the @noble libraries already present.

   Surface required by slip39:
     - crypto.randomBytes(len)
     - crypto.pbkdf2Sync(pass, salt, iters, keylen, 'sha256')
     - crypto.createHmac('sha256', key).update(data).digest()
   ══════════════════════════════════════════════════════════════════ */
import { pbkdf2 } from '@noble/hashes/pbkdf2.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';

/* slip39 passes Buffers and expects array-indexable objects.
   Uint8Array satisfies both needs (slice, length, indexes). */
function toBytes(x) {
  if (x instanceof Uint8Array) return x;
  if (Array.isArray(x)) return Uint8Array.from(x);
  if (x && typeof x.length === 'number') return Uint8Array.from(x);
  if (typeof x === 'string') return new TextEncoder().encode(x);
  return new Uint8Array(0);
}

export function randomBytes(length = 32) {
  const out = new Uint8Array(length);
  globalThis.crypto.getRandomValues(out);
  return out;
}

export function pbkdf2Sync(password, salt, iterations, keylen, digest) {
  if (digest && digest !== 'sha256') throw new Error('unsupported digest: ' + digest);
  return pbkdf2(sha256, toBytes(password), toBytes(salt), { c: iterations, dkLen: keylen });
}

export function createHmac(algo, key) {
  if (algo !== 'sha256') throw new Error('unsupported algorithm: ' + algo);
  const chunks = [];
  return {
    update(data) { chunks.push(toBytes(data)); return this; },
    digest() {
      let total = 0;
      for (const c of chunks) total += c.length;
      const joined = new Uint8Array(total);
      let off = 0;
      for (const c of chunks) { joined.set(c, off); off += c.length; }
      return hmac(sha256, toBytes(key), joined);
    },
  };
}

export default { randomBytes, pbkdf2Sync, createHmac };
