#!/usr/bin/env python3

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from canonical import CanonicalError, canonical_bytes, strict_loads, validate_relative_path
from contract import (
    CANONICAL_REQUEST,
    DECLARED_ROUTES,
    MANDATORY_NONCOVERAGE,
    RECOGNITION_FIELDS,
    ROLE_BINDINGS,
    TOOL_CONTRACT_DIGEST,
)
from coverage_independent import regenerate
from coverage_subject import generate
from manifest import validate_internal
from renderer import UNAVAILABLE, derive
from static_check import run as static_run


class CanonicalTests(unittest.TestCase):
    def test_duplicate_keys_refuse(self) -> None:
        with self.assertRaises(CanonicalError):
            strict_loads(b'{"a":1,"a":2}')

    def test_float_refuses(self) -> None:
        with self.assertRaises(CanonicalError):
            strict_loads(b'{"a":1.5}')

    def test_path_grammar(self) -> None:
        validate_relative_path("test/test_invariants.py")
        for value in ("", "/absolute", "a//b", "a/./b", "a/../b", "a/"):
            with self.assertRaises(CanonicalError, msg=value):
                validate_relative_path(value)


class ContractTests(unittest.TestCase):
    def test_fixed_terminal(self) -> None:
        self.assertEqual(CANONICAL_REQUEST["expected_generation"], 7)
        self.assertEqual(CANONICAL_REQUEST["slot"], "release-slot-A")
        self.assertEqual(len(TOOL_CONTRACT_DIGEST), 64)
        self.assertGreaterEqual(len(RECOGNITION_FIELDS), 30)

    def test_identity_nonclaims(self) -> None:
        self.assertTrue(all(record["presence"] == "explicitly_unbound" for record in ROLE_BINDINGS.values()))

    def test_one_effect_route(self) -> None:
        effect_routes = [row for row in DECLARED_ROUTES if row["consequence_class"] != "none"]
        self.assertEqual(len(effect_routes), 1)
        self.assertGreater(len(MANDATORY_NONCOVERAGE), 20)


class CoverageTests(unittest.TestCase):
    def test_independent_regeneration_agrees(self) -> None:
        runtime = {"live_agent_adapter": "absent"}
        matrix = {"totals": {"recognized_crossings": 1}}
        registry = {"routes": DECLARED_ROUTES}
        noncoverage = {
            "surfaces": [
                {"required_disposition": disposition, "surface_id": name}
                for name, disposition in MANDATORY_NONCOVERAGE
            ]
        }
        self.assertEqual(
            generate(runtime, matrix, registry, noncoverage),
            regenerate(runtime, matrix, registry, noncoverage),
        )


class RendererTests(unittest.TestCase):
    def test_missing_or_untrusted_never_positive(self) -> None:
        self.assertEqual(derive(None, {})["label"], UNAVAILABLE)
        self.assertTrue(derive({}, {})["exit_nonzero"])


class PackageTests(unittest.TestCase):
    def test_manifest_and_static_gate(self) -> None:
        validate_internal(ROOT)
        result = static_run(ROOT, require_manifest=True)
        self.assertTrue(result["checks"]["exactly_one_protected_commit_site"])
        self.assertTrue(result["checks"]["live_agent_adapter_absent"])


if __name__ == "__main__":
    unittest.main()
