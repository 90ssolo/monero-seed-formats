#!/usr/bin/env node
import { deriveLegacy25Keys, deriveMyMonero13Keys, inspectSeedFormat } from "../src/codecs.mjs";

const input = process.argv.slice(2).join(" ").trim();
if (!input) {
  console.error("Usage: node scripts/inspect-format.mjs \"<mnemonic phrase>\"");
  process.exit(1);
}

const info = inspectSeedFormat(input);
console.log(JSON.stringify(info, null, 2));

if (info.formatId === "legacy-25-electrum" && info.checksumValid) {
  const keys = deriveLegacy25Keys(input);
  console.log("\nDerived Keys (25-Word Legacy):");
  console.log(`  Private Spend Key: ${keys.privateSpendKey}`);
  console.log(`  Private View Key : ${keys.privateViewKey}`);
} else if (info.formatId === "mymonero-13" && info.checksumValid) {
  const keys = deriveMyMonero13Keys(input);
  console.log("\nDerived Keys (13-Word MyMonero):");
  console.log(`  16-Byte Seed     : ${keys.seedHex}`);
  console.log(`  Private Spend Key: ${keys.privateSpendKey}`);
  console.log(`  Private View Key : ${keys.privateViewKey}`);
  if (keys.unreducedExceededGroupOrder) {
    console.log(
      `  Note: Unreduced first hash >= l; naive 25-word conversion would derive wrong view key (${keys.naive25WordViewKey}).`
    );
  }
}
