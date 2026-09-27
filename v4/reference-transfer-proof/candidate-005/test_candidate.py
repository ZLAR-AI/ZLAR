#!/usr/bin/env python3
"""Focused pre-freeze regressions for Candidate 005."""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import unittest
from copy import deepcopy

from canonical import CanonicalError, strict_loads
from contract import (
    CLASS_SUBTOTALS,
    COLLISION_CASE,
    TOTAL_CASES,
    make_destination_registry,
    make_noncoverage_baseline,
    make_run_plan,
    make_runtime_inventory,
    ordered_case_rows,
    validate_run_plan,
)
from coverage_model import generate_coverage
from crypto_rsa import KeyGenerationError, PrivateKey, PublicKeyError, generate_rsa_key, sign_bytes


def dummy_attempt_hashes() -> dict[str, str]:
    return {row["case_id"]: format(index + 1, "064x") for index, row in enumerate(ordered_case_rows())}


class CanonicalizationTests(unittest.TestCase):
    def test_duplicate_key_refuses(self) -> None:
        with self.assertRaisesRegex(CanonicalError, "duplicate_json_key"):
            strict_loads('{"a":1,"a":2}')

    def test_float_refuses_as_byte_ambiguity(self) -> None:
        with self.assertRaisesRegex(CanonicalError, "byte_ambiguity"):
            strict_loads('{"a":1.0}')


class ActualModulusTests(unittest.TestCase):
    def test_2047_bit_short_product_is_skipped_before_use(self) -> None:
        candidates = iter(
            [
                PrivateKey(n=(1 << 2046) + 1, e=65537, d=3),
                PrivateKey(n=(1 << 2047) + 1, e=65537, d=3),
            ]
        )
        selected, attempts, observed = generate_rsa_key(candidate_factory=lambda: next(candidates), max_attempts=2)
        self.assertEqual(observed, [2047, 2048])
        self.assertEqual(attempts, 2)
        self.assertEqual(selected.n.bit_length(), 2048)

    def test_short_products_exhaust_bounded_generation(self) -> None:
        with self.assertRaisesRegex(KeyGenerationError, "actual_public_modulus_bit_length_not_2048"):
            generate_rsa_key(
                candidate_factory=lambda: PrivateKey(n=(1 << 2046) + 1, e=65537, d=3),
                max_attempts=2,
            )

    def test_signer_rejects_2047_bit_modulus(self) -> None:
        with self.assertRaisesRegex(PublicKeyError, "public_key_modulus_bits"):
            sign_bytes(PrivateKey(n=(1 << 2046) + 1, e=65537, d=3), b"must-not-sign")


class RunPlanContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.hashes = dummy_attempt_hashes()
        self.plan = make_run_plan("package-sha256:test", "source-sha256:test", self.hashes)

    def test_exact_closed_plan(self) -> None:
        result = validate_run_plan(self.plan, attempt_hashes=self.hashes)
        self.assertEqual(len(self.plan["cases"]), TOTAL_CASES)
        self.assertEqual(self.plan["class_subtotals"], CLASS_SUBTOTALS)
        self.assertTrue(all(value for key, value in result.items() if key != "plan_matrix_set_equal"))
        self.assertFalse(result["plan_matrix_set_equal"])

    def test_wrong_total_refuses(self) -> None:
        changed = deepcopy(self.plan)
        changed["total_cases"] = TOTAL_CASES - 1
        with self.assertRaisesRegex(ValueError, "run_plan_total"):
            validate_run_plan(changed, attempt_hashes=self.hashes)

    def test_wrong_class_subtotal_refuses(self) -> None:
        changed = deepcopy(self.plan)
        changed["class_subtotals"]["protocol_probe"] -= 1
        with self.assertRaisesRegex(ValueError, "class_subtotals"):
            validate_run_plan(changed, attempt_hashes=self.hashes)

    def test_missing_row_refuses(self) -> None:
        changed = deepcopy(self.plan)
        changed["cases"].pop()
        with self.assertRaises(ValueError):
            validate_run_plan(changed, attempt_hashes=self.hashes)

    def test_duplicate_row_refuses(self) -> None:
        changed = deepcopy(self.plan)
        changed["cases"][-1] = deepcopy(changed["cases"][0])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            validate_run_plan(changed, attempt_hashes=self.hashes)

    def test_extra_row_refuses(self) -> None:
        changed = deepcopy(self.plan)
        changed["cases"].append(deepcopy(changed["cases"][-1]))
        changed["cases"][-1]["case_id"] = "EXTRA-001"
        with self.assertRaises(ValueError):
            validate_run_plan(changed, attempt_hashes=self.hashes)

    def test_renamed_row_refuses(self) -> None:
        changed = deepcopy(self.plan)
        changed["cases"][0]["case_id"] += "-renamed"
        with self.assertRaisesRegex(ValueError, "renamed"):
            validate_run_plan(changed, attempt_hashes=self.hashes)

    def test_input_without_plan_refuses(self) -> None:
        hashes = dict(self.hashes)
        hashes["INPUT-EXTRA"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "attempt_set"):
            validate_run_plan(self.plan, attempt_hashes=hashes)

    def test_plan_without_input_refuses(self) -> None:
        hashes = dict(self.hashes)
        hashes.pop(next(iter(hashes)))
        with self.assertRaisesRegex(ValueError, "attempt_set"):
            validate_run_plan(self.plan, attempt_hashes=hashes)

    def test_matrix_without_plan_refuses(self) -> None:
        matrix = [
            {"case_id": row["case_id"], "case_class": row["case_class"]}
            for row in self.plan["cases"][1:]
        ]
        with self.assertRaisesRegex(ValueError, "matrix_plan_set"):
            validate_run_plan(self.plan, attempt_hashes=self.hashes, matrix_rows=matrix)

    def test_class_mismatched_matrix_refuses(self) -> None:
        matrix = [
            {"case_id": row["case_id"], "case_class": row["case_class"]}
            for row in self.plan["cases"]
        ]
        matrix[0]["case_class"] = "base_authorization_negative"
        with self.assertRaisesRegex(ValueError, "matrix_plan_class"):
            validate_run_plan(self.plan, attempt_hashes=self.hashes, matrix_rows=matrix)

    def test_collision_cannot_hide_outside_plan(self) -> None:
        changed = deepcopy(self.plan)
        for row in changed["cases"]:
            if row["case_id"] == COLLISION_CASE[0]:
                row["case_class"] = "protocol_probe"
        changed["case_class_map"][COLLISION_CASE[0]] = "protocol_probe"
        with self.assertRaises(ValueError):
            validate_run_plan(changed, attempt_hashes=self.hashes)


class CoverageContractTests(unittest.TestCase):
    def test_exact_43_rows_and_mandatory_side_doors(self) -> None:
        package_id = "package-sha256:test"
        source_id = "source-sha256:test"
        matrix = {
            "payload": {"receipt_id": "matrix-sha256:test"},
            "schema_version": "zlar.star4.evidence-envelope.v1",
        }
        coverage = generate_coverage(
            make_runtime_inventory(package_id, source_id),
            make_destination_registry(package_id, source_id),
            matrix,
            make_noncoverage_baseline(package_id, source_id),
        )
        self.assertEqual(coverage["row_count"], 43)
        self.assertEqual(len({row["surface_id"] for row in coverage["rows"]}), 43)
        governed = [row for row in coverage["rows"] if row["surface_disposition"] == "governed"]
        self.assertEqual([row["surface_id"] for row in governed], ["mcp.tool.deployment-promote"])
        self.assertTrue(
            all(row["surface_disposition"] != "governed" for row in coverage["rows"] if row["surface_id"].startswith("side-door."))
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
