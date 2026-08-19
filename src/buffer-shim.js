/* ══════════════════════════════════════════════════════════════════
   Minimal Buffer for the browser.

   The slip39 library is written for Node and uses `Buffer.from(...)`
   in four places, always to convert byte arrays before passing them
   to the cryptographic functions. In the browser `Buffer` does not
   exist, so this file provides a version covering exactly that use:
   Uint8Array is already indexable and has slice/length, which is
   everything slip39 requires.
   ══════════════════════════════════════════════════════════════════ */
export const Buffer = {
  from(input, encoding) {
    if (input instanceof Uint8Array) return input;
    if (Array.isArray(input)) return Uint8Array.from(input);
    if (typeof input === 'string') {
      if (encoding === 'hex') {
        const out = new Uint8Array(input.length / 2);
        for (let i = 0; i < out.length; i++) out[i] = parseInt(input.substr(i * 2, 2), 16);
        return out;
      }
      return new TextEncoder().encode(input);
    }
    if (input && typeof input.length === 'number') return Uint8Array.from(input);
    return new Uint8Array(0);
  },
  isBuffer(x) { return x instanceof Uint8Array; },
  alloc(n) { return new Uint8Array(n); },
  concat(list) {
    let total = 0;
    for (const b of list) total += b.length;
    const out = new Uint8Array(total);
    let off = 0;
    for (const b of list) { out.set(b, off); off += b.length; }
    return out;
  },
};

export default Buffer;
