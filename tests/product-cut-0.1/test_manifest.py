#!/usr/bin/env python3
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
PRODUCT = Path(__file__).absolute().parents[2] / "demos/zlar-destination-gate"
sys.path.insert(0, str(PRODUCT))

from product_identity import verify_manifest


class ProductManifestTests(unittest.TestCase):
    def test_complete_manifest_verifies_read_only(self) -> None:
        manifest = verify_manifest()
        self.assertEqual(manifest["engine_file_count"], 13)
        self.assertEqual(manifest["schema_version"], "zlar.demo1.source-manifest.v1")
        self.assertEqual(manifest["current_source_roots"], ["cyan", "demos/zlar-destination-gate"])
        self.assertEqual(manifest["historical_runner_status"], "fail_closed_non_routing")


if __name__ == "__main__":
    unittest.main(verbosity=2)
