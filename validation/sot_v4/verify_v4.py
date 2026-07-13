#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "validation/sot_v4/out")
    tgb_path = out / "tgb_results.json"
    dd_path = out / "differential_results.json"
    tgb = json.loads(tgb_path.read_text())
    dd = json.loads(dd_path.read_text())
    checks = {
        "tgb_schema": tgb["schema"] == "sot-v4-tgb-1.0",
        "tgb_edges_nonzero": tgb["metadata"]["num_edges"] > 0,
        "tgb_chronological": tgb["metadata"]["input_already_sorted"],
        "triangle_counts_monotone": (
            tgb["temporal_triangle_counts"]["86400"]
            <= tgb["temporal_triangle_counts"]["604800"]
            <= tgb["temporal_triangle_counts"]["2592000"]
        ),
        "cover_all_pass": (
            tgb["cover_certificates"]["attempted"] >= 64
            and tgb["cover_certificates"]["passed"] == tgb["cover_certificates"]["attempted"]
            and tgb["cover_certificates"]["all_wl_equal"]
            and tgb["cover_certificates"]["all_counts_2_vs_0"]
        ),
        "walsh_rank_one": (
            tgb["walsh_repair"]["repair_rank"] == 1
            and tgb["walsh_repair"]["full_catalogue_bits"] == 6
            and tgb["walsh_repair"]["all_wl_equal"]
        ),
        "python_incremental_exact": all(x["match"] for x in tgb["incremental_python_checkpoints"]),
        "link_records_present": (
            tgb["link_prediction"]["num_val_queries"] > 0
            and tgb["link_prediction"]["num_test_queries"] > 0
        ),
        "dd_schema": dd["schema"] == "sot-v4-differential-1.0",
        "dd_uses_pinned_version": (
            dd["differential_dataflow_version"] == "0.24.0"
            and dd["timely_version"] == "0.30"
        ),
        "dd_exact": dd["all_exact"] and all(x["exact_match"] for x in dd["checkpoints"]),
        "dd_deletions_exercised": dd["total_relation_removes"] > 0,
        "dd_blindness_pair": (
            dd["canonical_blindness"]["degree_hist_equal"]
            and dd["canonical_blindness"]["c6_ordered_triangles"] == 0
            and dd["canonical_blindness"]["two_c3_ordered_triangles"] == 6
        ),
    }
    all_pass = all(checks.values())
    result = {
        "schema": "sot-v4-validation-1.0",
        "all_pass": all_pass,
        "checks": checks,
        "tgb_result_sha256": sha256(tgb_path),
        "differential_result_sha256": sha256(dd_path),
        "external_systems": {
            "tgb": "py-tgb 2.2.0 / tgbl-uci",
            "differential_dataflow": "differential-dataflow 0.24.0 / timely 0.30",
        },
        "reproduction_level": "internal external-system integration; not R2",
    }
    result_bytes = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
    result["canonical_sha256_without_digest"] = hashlib.sha256(result_bytes).hexdigest()
    (out / "v4_validation.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    if not all_pass:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
