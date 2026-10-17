/*
 * Zero-dependency cryptographic primitives used in Monero seed derivation:
 * - Pre-NIST Keccak-256 (domain separator 0x01, rate 1088 bits / 136 bytes)
 * - Ed25519 scalar reduction sc_reduce32 (mod l = 2^252 + 27742317777372353535851937790883648493)
 * - Standard CRC-32 (IEEE 802.3 polynomial 0xEDB88320) for Monero mnemonic checksums
 */

/** Ed25519 group order l = 2^252 + 27742317777372353535851937790883648493 */
export const ED25519_L = (1n << 252n) + 27742317777372353535851937790883648493n;

const RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];

const ROTC = [
  1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
  27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

const PILN = [
  10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
  15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

const MASK64 = 0xffffffffffffffffn;

function rotl64(x, s) {
  const n = BigInt(s);
  return ((x << n) | (x >> (64n - n))) & MASK64;
}

function keccakF1600(state) {
  const bc = new Array(5);
  for (let round = 0; round < 24; round++) {
    for (let i = 0; i < 5; i++) {
      bc[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
    }
    for (let i = 0; i < 5; i++) {
      const t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
      for (let j = 0; j < 25; j += 5) {
        state[j + i] = (state[j + i] ^ t) & MASK64;
      }
    }
    let t = state[1];
    for (let i = 0; i < 24; i++) {
      const j = PILN[i];
      const temp = state[j];
      state[j] = rotl64(t, ROTC[i]);
      t = temp;
    }
    for (let j = 0; j < 25; j += 5) {
      for (let i = 0; i < 5; i++) bc[i] = state[j + i];
      for (let i = 0; i < 5; i++) {
        state[j + i] = (state[j + i] ^ ((~bc[(i + 1) % 5] & MASK64) & bc[(i + 2) % 5])) & MASK64;
      }
    }
    state[0] = (state[0] ^ RC[round]) & MASK64;
  }
}

/**
 * Computes original Keccak-256 (padding 0x01, used by Monero).
 * Note: NIST SHA3-256 uses padding 0x06 and produces different outputs!
 */
export function keccak256(inputBytes) {
  const rate = 136; // 1088 bits
  const state = new Array(25).fill(0n);
  const paddedLen = Math.ceil((inputBytes.length + 1) / rate) * rate;
  const buf = new Uint8Array(paddedLen);
  buf.set(inputBytes);
  buf[inputBytes.length] ^= 0x01;
  buf[paddedLen - 1] ^= 0x80;

  const view = new DataView(buf.buffer);
  for (let offset = 0; offset < paddedLen; offset += rate) {
    for (let i = 0; i < 17; i++) {
      const lo = BigInt(view.getUint32(offset + i * 8, true));
      const hi = BigInt(view.getUint32(offset + i * 8 + 4, true));
      state[i] = (state[i] ^ ((hi << 32n) | lo)) & MASK64;
    }
    keccakF1600(state);
  }

  const out = new Uint8Array(32);
  const outView = new DataView(out.buffer);
  for (let i = 0; i < 4; i++) {
    const lane = state[i];
    outView.setUint32(i * 8, Number(lane & 0xffffffffn), true);
    outView.setUint32(i * 8 + 4, Number((lane >> 32n) & 0xffffffffn), true);
  }
  return out;
}

/**
 * Reduces a 32-byte little-endian integer modulo the Ed25519 group order l.
 */
export function scReduce32(bytes) {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    n = (n << 8n) | BigInt(bytes[i]);
  }
  n %= ED25519_L;
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

export function crc32(text) {
  let c = 0xffffffff;
  for (const byte of new TextEncoder().encode(text)) {
    c = CRC_TABLE[(c ^ byte) & 0xff] ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

export function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function hexToBytes(hex) {
  const clean = hex.trim().toLowerCase();
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
