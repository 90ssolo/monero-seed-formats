#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  decodeMoneroMnemonic,
  deriveLegacy25Keys,
  deriveMyMonero13Keys,
  encodeMoneroMnemonic,
  inspectSeedFormat,
} from "../src/codecs.mjs";
import { MONERO_ENGLISH_WORDS } from "../src/wordlist-monero-en.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, "..");

let failures = 0;
function assert(condition, message) {
  if (!condition) {
    console.error(`FAIL: ${message}`);
    failures++;
  }
}

// 1. Validate Monero 1,626-word English dictionary
assert(MONERO_ENGLISH_WORDS.length === 1626, `Expected 1,626 words, got ${MONERO_ENGLISH_WORDS.length}`);
const uniquePrefixes = new Set(MONERO_ENGLISH_WORDS.map((w) => w.slice(0, 3)));
assert(uniquePrefixes.size === 1626, `Expected 1,626 unique 3-letter prefixes, got ${uniquePrefixes.size}`);

// 2. Validate data/seed-formats.json and all published test vectors
const dataPath = path.join(rootDir, "data", "seed-formats.json");
const spec = JSON.parse(fs.readFileSync(dataPath, "utf8"));
assert(Array.isArray(spec.formats) && spec.formats.length === 5, "Expected 5 documented seed formats in seed-formats.json");

for (const vec of spec.test_vectors.mymonero_13) {
  const derived = deriveMyMonero13Keys(vec.phrase);
  assert(derived.seedHex === vec.seed_16_hex, `MyMonero seed mismatch for "${vec.source}"`);
  assert(derived.privateSpendKey === vec.private_spend_key, `MyMonero spend key mismatch for "${vec.source}"`);
  assert(derived.privateViewKey === vec.private_view_key, `MyMonero view key mismatch for "${vec.source}"`);

  // Verify round-trip encoding back to 13 words
  const rawBytes = decodeMoneroMnemonic(vec.phrase, 13);
  const reEncoded = encodeMoneroMnemonic(rawBytes);
  assert(reEncoded === vec.phrase, `MyMonero 13-word round-trip mismatch for "${vec.source}"`);
}

for (const vec of spec.test_vectors.exodus_bip39_to_legacy25) {
  const info = inspectSeedFormat(vec.equivalent_25_word_seed);
  assert(info.checksumValid === true, `25-word checksum failed for "${vec.source}": ${info.error}`);
  const keys = deriveLegacy25Keys(vec.equivalent_25_word_seed);
  assert(/^[0-9a-f]{64}$/.test(keys.privateSpendKey), `Invalid 25-word spend key hex for "${vec.source}"`);
  assert(/^[0-9a-f]{64}$/.test(keys.privateViewKey), `Invalid 25-word view key hex for "${vec.source}"`);

  // Verify round-trip encoding back to 25 words
  const rawBytes = decodeMoneroMnemonic(vec.equivalent_25_word_seed, 25);
  const reEncoded = encodeMoneroMnemonic(rawBytes);
  assert(reEncoded === vec.equivalent_25_word_seed, `25-word round-trip mismatch for "${vec.source}"`);
}

// 3. Check SVG assets
for (const svgFile of ["hero-banner.svg", "seed-derivation-comparison.svg"]) {
  const svgPath = path.join(rootDir, "assets", svgFile);
  assert(fs.existsSync(svgPath), `Missing SVG asset: assets/${svgFile}`);
  const content = fs.readFileSync(svgPath, "utf8");
  assert(content.includes("<svg") && content.includes("</svg>"), `Malformed SVG in assets/${svgFile}`);
}

if (failures > 0) {
  console.error(`\nValidation failed with ${failures} error(s).`);
  process.exit(1);
}

console.log(
  `OK: Verified 1,626-word dictionary, ${spec.formats.length} seed formats, ${
    spec.test_vectors.mymonero_13.length + spec.test_vectors.exodus_bip39_to_legacy25.length
  } published test vectors, and SVG diagrams.`
);
