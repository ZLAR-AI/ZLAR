#!/usr/bin/env python3
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
PRODUCT = Path(__file__).absolute().parents[2] / "demos/zlar-destination-gate"
sys.path.insert(0, str(PRODUCT))

from product_identity import CANDIDATE_ROOTS, collect_candidate, repository_root


class CleanCheckoutBoundaryTests(unittest.TestCase):
    def test_all_candidate_nodes_resolve_inside_clone_without_hardlinks(self) -> None:
        root = repository_root()
        directories, files = collect_candidate(root)
        self.assertEqual(
            [path.as_posix() for path in CANDIDATE_ROOTS],
            ["cyan", "demos/zlar-destination-gate", "tests/product-cut-0.1", "v4/reference-transfer-proof/candidate-005"],
        )
        self.assertTrue(directories)
        self.assertTrue(files)


if __name__ == "__main__":
    unittest.main(verbosity=2)
