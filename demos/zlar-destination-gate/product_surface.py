#!/usr/bin/env python3
"""Read-only derivation of human-facing facts from signed campaign evidence."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

from product_identity import ENGINE_RELATIVE, repository_root


def _engine_imports() -> tuple[Any, Any, Any, Any]:
    engine = repository_root() / ENGINE_RELATIVE
    if str(engine) not in sys.path:
        sys.path.insert(0, str(engine))
    from canonical import read_json
    from evidence import verify_envelope
    from offline_verify import verify_campaign
    from contract import INITIAL_GENERATION
    return read_json, verify_envelope, verify_campaign, INITIAL_GENERATION


def tree_projection(root: Path) -> tuple[tuple[str, str, int], ...]:
    import hashlib
    import os
    import stat

    rows: list[tuple[str, str, int]] = []
    for current_text, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        dirnames.sort(key=lambda value: value.encode("utf-8"))
        filenames.sort(key=lambda value: value.encode("utf-8"))
        current = Path(current_text)
        for dirname in dirnames:
            node = current / dirname
            if stat.S_ISLNK(node.lstat().st_mode):
                raise RuntimeError(f"tree_symlink:{node.relative_to(root).as_posix()}")
            rows.append((node.relative_to(root).as_posix(), "directory", 0))
        for filename in filenames:
            node = current / filename
            mode = node.lstat().st_mode
            if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
                raise RuntimeError(f"tree_nonregular:{node.relative_to(root).as_posix()}")
            rows.append((node.relative_to(root).as_posix(), hashlib.sha256(node.read_bytes()).hexdigest(), node.stat().st_size))
    return tuple(rows)


def derive_verified_view(campaign_root: Path) -> dict[str, Any]:
    read_json, verify_envelope, verify_campaign, initial_generation = _engine_imports()
    offline = verify_campaign(str(campaign_root))
    public_key = read_json(campaign_root / "public-key.json")
    matrix = verify_envelope(read_json(campaign_root / "matrix-evidence.json"), public_key, expected_type="matrix")
    effect = verify_envelope(read_json(campaign_root / "effect-receipt.json"), public_key, expected_type="effect")
    consumption = verify_envelope(
        read_json(campaign_root / "consumption-receipt.json"), public_key, expected_type="consumption"
    )
    case_ids = (
        "AUTH-001-missing-authorization",
        "CROSSING-001-recognized-promotion",
        "REPLAY-001-consumed-authorization",
    )
    rows = {row["case_id"]: row for row in matrix["cases"]}
    decisions: dict[str, Any] = {}
    for case_id in case_ids:
        decision = verify_envelope(
            read_json(campaign_root / "decision-receipts" / f"{case_id}.json"), public_key, expected_type="decision"
        )
        if decision["receipt_id"] != rows[case_id]["decision_receipt_id"]:
            raise RuntimeError(f"named_case_decision_link:{case_id}")
        decisions[case_id] = decision
    auth = rows[case_ids[0]]
    crossing = rows[case_ids[1]]
    replay = rows[case_ids[2]]
    if auth["observed_outcome"] != "refused" or auth["mutation_delta"] != 0 or auth["consumption_delta"] != 0:
        raise RuntimeError("auth_visible_case")
    if decisions[case_ids[0]]["state_before_digest"] != decisions[case_ids[0]]["state_after_digest"]:
        raise RuntimeError("auth_state_changed")
    if crossing["observed_outcome"] != "accepted" or crossing["mutation_delta"] != 1 or crossing["consumption_delta"] != 1:
        raise RuntimeError("crossing_visible_case")
    if replay["observed_outcome"] != "refused" or replay["mutation_delta"] != 0 or replay["consumption_delta"] != 0:
        raise RuntimeError("replay_visible_case")
    if decisions[case_ids[2]]["state_before_digest"] != decisions[case_ids[2]]["state_after_digest"]:
        raise RuntimeError("replay_state_changed")
    if effect["generation_before"] != initial_generation or effect["generation_after"] != initial_generation + 1:
        raise RuntimeError("effect_generation")
    if effect["protected_mutation_count"] != 1 or consumption["recognized_consumption_count"] != 1:
        raise RuntimeError("effect_consumption_count")
    if consumption["effect_receipt_id"] != effect["receipt_id"]:
        raise RuntimeError("consumption_effect_link")
    accepted = sum(1 for row in matrix["cases"] if row["observed_outcome"] == "accepted")
    refused = sum(1 for row in matrix["cases"] if row["observed_outcome"] == "refused")
    zero_counter_names = (
        "negative_protected_consumptions", "negative_protected_mutations",
        "outside_domain_protected_consumptions", "outside_domain_protected_mutations",
        "prohibited_protected_consumptions", "prohibited_protected_mutations",
        "real_external_protected_consumptions", "real_external_protected_mutations",
        "replay_protected_consumptions", "replay_protected_mutations",
    )
    zero_counters = {name: matrix[name] for name in zero_counter_names}
    if any(zero_counters.values()):
        raise RuntimeError("nonzero_prohibited_counter")
    return {
        "accepted": accepted,
        "auth": {"case_id": case_ids[0], "generation_after": effect["generation_before"], "generation_before": effect["generation_before"], "outcome": auth["observed_outcome"], "reason": auth["observed_reason"]},
        "case_count": matrix["case_count"],
        "coverage_disposition_counts": offline["coverage_disposition_counts"],
        "coverage_row_count": offline["coverage_row_count"],
        "crossing": {"case_id": case_ids[1], "consumptions": crossing["consumption_delta"], "generation_after": effect["generation_after"], "generation_before": effect["generation_before"], "mutations": crossing["mutation_delta"], "outcome": crossing["observed_outcome"]},
        "offline_assertions": offline["assertions"],
        "refused": refused,
        "replay": {"case_id": case_ids[2], "generation_after": effect["generation_after"], "generation_before": effect["generation_after"], "outcome": replay["observed_outcome"], "reason": replay["observed_reason"]},
        "zero_counters": zero_counters,
    }
