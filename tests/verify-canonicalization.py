#!/usr/bin/env python3
"""
ZLAR Canonicalization — Python Cross-Language Verifier

Verifies that Python produces byte-identical canonical output to the
test vectors defined in fixtures/canonicalization-vectors.json.

This script uses only Python stdlib. No external packages required.

Usage: python3 tests/verify-canonicalization.py
"""

import json
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
VECTORS_PATH = os.path.join(SCRIPT_DIR, 'fixtures', 'canonicalization-vectors.json')


def sort_keys_recursive(value):
    """Recursively sort object keys. Arrays preserve order. Primitives pass through."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, list):
        return [sort_keys_recursive(item) for item in value]
    if isinstance(value, dict):
        return {k: sort_keys_recursive(v) for k, v in sorted(value.items())}
    return value


def canonicalize(value):
    """
    Produce ZLAR canonical form.

    Uses json.dumps with:
      - ensure_ascii=False (non-ASCII as literal UTF-8, not \\uXXXX)
      - separators=(',', ':') (no whitespace)
      - sort_keys via recursive pre-sort (not json.dumps sort_keys, which is not recursive for nested)

    Note: json.dumps(sort_keys=True) only sorts top-level keys.
    We pre-sort recursively, then serialize.
    """
    sorted_value = sort_keys_recursive(value)
    return json.dumps(sorted_value, ensure_ascii=False, separators=(',', ':'))


def main():
    with open(VECTORS_PATH, 'r', encoding='utf-8') as f:
        data = json.load(f)

    vectors = data['vectors']
    passed = 0
    failed = 0
    total = 0

    print('=== Python Cross-Language Canonicalization Verification ===')
    print()

    for v in vectors:
        total += 1
        vid = v['id']
        desc = v['description']
        expected = v['expected']
        result = canonicalize(v['input'])

        if result == expected:
            passed += 1
        else:
            failed += 1
            print(f'  FAIL: {vid}: {desc}')
            print(f'    expected: {expected!r}')
            print(f'    actual:   {result!r}')

    print()
    print(f'=== Results: {passed}/{total} passed, {failed} failed ===')

    if failed > 0:
        sys.exit(1)


if __name__ == '__main__':
    main()
