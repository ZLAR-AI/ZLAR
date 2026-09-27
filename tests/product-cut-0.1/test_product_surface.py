#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
PRODUCT = Path(__file__).absolute().parents[2] / "demos/zlar-destination-gate"
sys.path.insert(0, str(PRODUCT))

from product_surface import derive_verified_view


@unittest.skipUnless(os.environ.get("ZLAR_PRODUCT_CAMPAIGN_ROOT"), "set ZLAR_PRODUCT_CAMPAIGN_ROOT to saved evidence")
class ProductSurfaceTests(unittest.TestCase):
    def test_signed_human_view(self) -> None:
        view = derive_verified_view(Path(os.environ["ZLAR_PRODUCT_CAMPAIGN_ROOT"]))
        self.assertEqual((view["case_count"], view["accepted"], view["refused"]), (86, 1, 85))
        self.assertEqual((view["auth"]["generation_before"], view["auth"]["generation_after"]), (7, 7))
        self.assertEqual((view["crossing"]["generation_before"], view["crossing"]["generation_after"]), (7, 8))
        self.assertEqual((view["replay"]["generation_before"], view["replay"]["generation_after"]), (8, 8))
        self.assertEqual(sum(view["zero_counters"].values()), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
