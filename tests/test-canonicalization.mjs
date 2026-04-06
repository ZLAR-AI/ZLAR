// ═══════════════════════════════════════════════════════════════════════════════
// ZLAR Canonicalization — Test Suite
//
// Tests: canonical output against test vectors, validation of constrained schema,
// cross-implementation consistency, edge cases.
// ═══════════════════════════════════════════════════════════════════════════════

import { canonicalize, canonicalizeBytes, validateCanonical } from '../lib/canonicalize.mjs';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTORS_PATH = join(__dirname, 'fixtures', 'canonicalization-vectors.json');

let pass = 0;
let fail = 0;
let total = 0;

function assert(label, expected, actual) {
  total++;
  if (expected === actual) {
    pass++;
  } else {
    fail++;
    console.log(`  FAIL: ${label}`);
    console.log(`    expected: ${JSON.stringify(expected)}`);
    console.log(`    actual:   ${JSON.stringify(actual)}`);
  }
}

function assertThrows(label, fn) {
  total++;
  try {
    fn();
    fail++;
    console.log(`  FAIL: ${label} — expected throw, got none`);
  } catch (e) {
    pass++;
  }
}

function assertNoThrow(label, fn) {
  total++;
  try {
    fn();
    pass++;
  } catch (e) {
    fail++;
    console.log(`  FAIL: ${label} — unexpected throw: ${e.message}`);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
console.log('=== Test Vectors ===');
console.log();

const vectors = JSON.parse(readFileSync(VECTORS_PATH, 'utf8')).vectors;

for (const v of vectors) {
  const result = canonicalize(v.input, { validate: false });
  assert(`${v.id}: ${v.description}`, v.expected, result);
}

// ═══════════════════════════════════════════════════════════════════════════════
console.log('=== Validation: Allowed Types ===');
console.log();

assertNoThrow('null is allowed', () => validateCanonical(null));
assertNoThrow('true is allowed', () => validateCanonical(true));
assertNoThrow('false is allowed', () => validateCanonical(false));
assertNoThrow('integer 0 is allowed', () => validateCanonical(0));
assertNoThrow('integer 42 is allowed', () => validateCanonical(42));
assertNoThrow('negative integer is allowed', () => validateCanonical(-100));
assertNoThrow('max safe integer is allowed', () => validateCanonical(9007199254740991));
assertNoThrow('min safe integer is allowed', () => validateCanonical(-9007199254740991));
assertNoThrow('string is allowed', () => validateCanonical('hello'));
assertNoThrow('empty string is allowed', () => validateCanonical(''));
assertNoThrow('unicode string value is allowed', () => validateCanonical('\u65e5\u672c\u8a9e'));
assertNoThrow('array is allowed', () => validateCanonical([1, 2, 3]));
assertNoThrow('nested object is allowed', () => validateCanonical({ a: { b: 1 } }));
assertNoThrow('empty object is allowed', () => validateCanonical({}));
assertNoThrow('empty array is allowed', () => validateCanonical([]));

// ═══════════════════════════════════════════════════════════════════════════════
console.log('=== Validation: Prohibited Types ===');
console.log();

assertThrows('float 1.5 is rejected', () => validateCanonical(1.5));
assertThrows('float 0.1 is rejected', () => validateCanonical(0.1));
assertThrows('float 3.14159 is rejected', () => validateCanonical(3.14159));
assertThrows('NaN is rejected', () => validateCanonical(NaN));
assertThrows('Infinity is rejected', () => validateCanonical(Infinity));
assertThrows('-Infinity is rejected', () => validateCanonical(-Infinity));
assertThrows('unsafe integer above 2^53-1 is rejected', () => validateCanonical(9007199254740992));
assertThrows('unsafe integer below -(2^53-1) is rejected', () => validateCanonical(-9007199254740992));

// ═══════════════════════════════════════════════════════════════════════════════
console.log('=== Validation: Key Constraints ===');
console.log();

assertThrows('non-ASCII key is rejected', () => validateCanonical({ '\u00e9': 1 }));
assertThrows('emoji key is rejected', () => validateCanonical({ '\ud83d\ude00': 1 }));
assertNoThrow('ASCII key is allowed', () => validateCanonical({ abc_123: 1 }));
assertNoThrow('underscore key is allowed', () => validateCanonical({ _id: 1 }));

// ═══════════════════════════════════════════════════════════════════════════════
console.log('=== Negative Zero ===');
console.log();

// -0 is valid input but must serialize as 0
assert('negative zero serializes as 0', '0', canonicalize(-0));
assert('negative zero in object', '{"a":0}', canonicalize({ a: -0 }));

// ═══════════════════════════════════════════════════════════════════════════════
console.log('=== 100.0 is integer in JavaScript ===');
console.log();

// In JavaScript, 100.0 === 100 and Number.isInteger(100.0) === true.
// This is correct behavior — 100.0 is allowed because it's an integer.
assertNoThrow('100.0 is integer in JS, allowed', () => validateCanonical(100.0));
assert('100.0 serializes as 100', '100', canonicalize(100.0));

// ═══════════════════════════════════════════════════════════════════════════════
console.log('=== canonicalizeBytes ===');
console.log();

const bytes = canonicalizeBytes({ b: 2, a: 1 });
assert('canonicalizeBytes returns Buffer', true, Buffer.isBuffer(bytes));
assert('canonicalizeBytes content matches', '{"a":1,"b":2}', bytes.toString('utf8'));

// ═══════════════════════════════════════════════════════════════════════════════
console.log('=== Cross-gate consistency (jq -S -c simulation) ===');
console.log();

// The receipt-shaped vector (C023) should match what jq -S -c produces.
// We verify the Node.js output matches the expected string which was
// computed from the specification rules.
const receiptVector = vectors.find(v => v.id === 'C023');
const nodeOutput = canonicalize(receiptVector.input, { validate: false });
assert('receipt canonical matches spec vector', receiptVector.expected, nodeOutput);

// ═══════════════════════════════════════════════════════════════════════════════
// Summary
console.log();
console.log(`=== Results: ${pass}/${total} passed, ${fail} failed ===`);

if (fail > 0) process.exit(1);
