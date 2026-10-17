import { MONERO_ENGLISH_WORDS } from "./wordlist-monero-en.mjs";
import { bytesToHex, crc32, ED25519_L, keccak256, scReduce32 } from "./keccak256.mjs";

const PREFIX_LEN = 3;
const N = MONERO_ENGLISH_WORDS.length; // 1626

const prefixMap = new Map(
  MONERO_ENGLISH_WORDS.map((word, idx) => [word.slice(0, PREFIX_LEN), idx])
);

export function splitPhrase(phrase) {
  return String(phrase || "")
    .trim()
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean);
}

export function lookupMoneroWordIndex(word) {
  return prefixMap.get(word.slice(0, PREFIX_LEN)) ?? -1;
}

/**
 * Decodes either a 13-word (16-byte) or 25-word (32-byte) Monero Electrum-style mnemonic,
 * verifying both prefix membership and the final CRC-32 checksum word.
 */
export function decodeMoneroMnemonic(phrase, expectedWords = null) {
  const words = splitPhrase(phrase);
  if (expectedWords !== null && words.length !== expectedWords) {
    throw new Error(`Expected ${expectedWords} words, got ${words.length}.`);
  }
  if (words.length !== 13 && words.length !== 25) {
    throw new Error(`Unsupported Monero Electrum word count: ${words.length} (expected 13 or 25).`);
  }

  const dataWordCount = words.length - 1;
  const dataWords = words.slice(0, dataWordCount);
  const checksumWord = words[dataWordCount];

  for (const w of words) {
    if (lookupMoneroWordIndex(w) < 0) {
      throw new Error(`Word "${w}" is not in the 1,626-word Monero English dictionary.`);
    }
  }

  const trimmedPrefixes = dataWords.map((w) => w.slice(0, PREFIX_LEN)).join("");
  const expectedChecksumWord = dataWords[crc32(trimmedPrefixes) % dataWordCount];
  if (expectedChecksumWord.slice(0, PREFIX_LEN) !== checksumWord.slice(0, PREFIX_LEN)) {
    throw new Error(
      `Checksum mismatch: expected "${expectedChecksumWord}" as word #${words.length}, got "${checksumWord}".`
    );
  }

  const chunkCount = dataWordCount / 3;
  const out = new Uint8Array(chunkCount * 4);
  const view = new DataView(out.buffer);

  for (let i = 0; i < chunkCount; i++) {
    const w1 = lookupMoneroWordIndex(dataWords[i * 3]);
    const w2 = lookupMoneroWordIndex(dataWords[i * 3 + 1]);
    const w3 = lookupMoneroWordIndex(dataWords[i * 3 + 2]);
    const val = w1 + N * ((N - w1 + w2) % N) + N * N * ((N - w2 + w3) % N);
    if (val % N !== w1) {
      throw new Error(`Word triplet at index ${i * 3} overflows 32-bit integer encoding.`);
    }
    view.setUint32(i * 4, val >>> 0, true);
  }

  return out;
}

/**
 * Encodes a 16-byte or 32-byte seed array into a 13-word or 25-word Monero mnemonic.
 */
export function encodeMoneroMnemonic(seedBytes) {
  if (seedBytes.length !== 16 && seedBytes.length !== 32) {
    throw new Error(`Seed must be 16 or 32 bytes, got ${seedBytes.length}.`);
  }
  const view = new DataView(seedBytes.buffer, seedBytes.byteOffset, seedBytes.byteLength);
  const words = [];
  for (let i = 0; i < seedBytes.length / 4; i++) {
    const val = view.getUint32(i * 4, true);
    const w1 = val % N;
    const w2 = (Math.floor(val / N) + w1) % N;
    const w3 = (Math.floor(Math.floor(val / N) / N) + w2) % N;
    words.push(MONERO_ENGLISH_WORDS[w1], MONERO_ENGLISH_WORDS[w2], MONERO_ENGLISH_WORDS[w3]);
  }
  const trimmedPrefixes = words.map((w) => w.slice(0, PREFIX_LEN)).join("");
  const checksumIndex = crc32(trimmedPrefixes) % words.length;
  words.push(words[checksumIndex]);
  return words.join(" ");
}

/**
 * Standard 25-word Legacy Monero derivation:
 *   private_spend_key = 32-byte decoded seed
 *   private_view_key  = sc_reduce32(keccak256(private_spend_key))
 */
export function deriveLegacy25Keys(phrase) {
  const seedBytes = decodeMoneroMnemonic(phrase, 25);
  const viewBytes = scReduce32(keccak256(seedBytes));
  return {
    seedHex: bytesToHex(seedBytes),
    privateSpendKey: bytesToHex(seedBytes),
    privateViewKey: bytesToHex(viewBytes),
  };
}

/**
 * MyMonero 13-word derivation:
 *   seed16            = 16-byte decoded seed
 *   firstHash         = keccak256(seed16)
 *   private_spend_key = sc_reduce32(firstHash)
 *   private_view_key  = sc_reduce32(keccak256(firstHash))   <-- hashes UNREDUCED firstHash!
 */
export function deriveMyMonero13Keys(phrase) {
  const seed16 = decodeMoneroMnemonic(phrase, 13);
  const firstHash = keccak256(seed16);
  const spendBytes = scReduce32(firstHash);
  const viewBytes = scReduce32(keccak256(firstHash));
  const naiveStandardViewBytes = scReduce32(keccak256(spendBytes));

  let firstInt = 0n;
  for (let i = 31; i >= 0; i--) {
    firstInt = (firstInt << 8n) | BigInt(firstHash[i]);
  }

  return {
    seedHex: bytesToHex(seed16),
    unreducedFirstHashHex: bytesToHex(firstHash),
    privateSpendKey: bytesToHex(spendBytes),
    privateViewKey: bytesToHex(viewBytes),
    naive25WordViewKey: bytesToHex(naiveStandardViewBytes),
    unreducedExceededGroupOrder: firstInt >= ED25519_L,
  };
}

/**
 * Classifies a mnemonic by word count and dictionary membership without logging or storing secrets.
 */
export function inspectSeedFormat(phrase) {
  const words = splitPhrase(phrase);
  const count = words.length;
  const allInMoneroList = words.every((w) => lookupMoneroWordIndex(w) >= 0);

  if (count === 25) {
    let checksumValid = false;
    let error = null;
    try {
      decodeMoneroMnemonic(phrase, 25);
      checksumValid = true;
    } catch (e) {
      error = e.message;
    }
    return {
      wordCount: 25,
      formatId: "legacy-25-electrum",
      formatName: "25-Word Monero Legacy (Electrum v2)",
      dictionary: "Monero 1,626-word list (3-letter unique prefix)",
      embedsBirthday: false,
      checksumValid,
      error,
    };
  }

  if (count === 16) {
    return {
      wordCount: 16,
      formatId: "polyseed-16",
      formatName: "16-Word Polyseed",
      dictionary: "BIP-39 2,048-word list (4-letter unique prefix)",
      embedsBirthday: true,
      checksumValid: null,
      note: "Uses GF(2048) polynomial checksum and embeds a 10-bit wallet creation timestamp.",
    };
  }

  if (count === 13) {
    let checksumValid = false;
    let error = null;
    try {
      decodeMoneroMnemonic(phrase, 13);
      checksumValid = true;
    } catch (e) {
      error = e.message;
    }
    return {
      wordCount: 13,
      formatId: "mymonero-13",
      formatName: "13-Word MyMonero Legacy (128-bit)",
      dictionary: "Monero 1,626-word list (3-letter unique prefix)",
      embedsBirthday: false,
      checksumValid,
      error,
    };
  }

  if (count === 12 || count === 24) {
    return {
      wordCount: count,
      formatId: count === 12 ? "bip39-12-exodus" : "bip39-24-hardware",
      formatName: `${count}-Word BIP-39 Multi-Coin / Hardware Seed`,
      dictionary: "BIP-39 2,048-word list",
      embedsBirthday: false,
      moneroListOverlapOnly: allInMoneroList,
      note: "Requires knowing whether the wallet used Exodus-style (direct sc_reduce32 on m/44'/128'/0'/0/0) or Ledger/Coinomi-style (Keccak-256 before sc_reduce32) derivation.",
    };
  }

  return {
    wordCount: count,
    formatId: "unknown",
    formatName: `Unrecognized word count (${count} words)`,
    dictionary: "Unknown",
    embedsBirthday: false,
  };
}
