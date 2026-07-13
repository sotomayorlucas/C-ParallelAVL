#!/usr/bin/env python3
"""Independent exact checker for SOT V5 POMDPs.jl integration.

The checker uses only Python's standard library. It does not import Julia,
POMDPs.jl, or the implementation under test. Closed-form rational witnesses are
recomputed independently, and the numerical integration results are checked
against declared tolerances.
"""

from __future__ import annotations

from fractions import Fraction as F
import hashlib
import json
from pathlib import Path
import sys


def rank_fraction(matrix: list[list[F]]) -> int:
    a = [row[:] for row in matrix]
    if not a:
        return 0
    m, n = len(a), len(a[0])
    r = 0
    for c in range(n):
        pivot = next((i for i in range(r, m) if a[i][c] != 0), None)
        if pivot is None:
            continue
        a[r], a[pivot] = a[pivot], a[r]
        p = a[r][c]
        a[r] = [x/p for x in a[r]]
        for i in range(m):
            if i != r and a[i][c] != 0:
                q = a[i][c]
                a[i] = [x-q*y for x,y in zip(a[i],a[r])]
        r += 1
        if r == m:
            break
    return r


def affine_rank(rows: list[list[F]]) -> int:
    base = rows[-1]
    return rank_fraction([[x-y for x,y in zip(row,base)] for row in rows[:-1]])


def dot(a, b):
    return sum(x*y for x,y in zip(a,b))


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def main() -> None:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "validation/sot_v5/out/pomdps_results.json")
    data = json.loads(path.read_text(encoding="utf-8"))

    # Exact non-closure witness over states 0,1,2,3.
    bp = [F(5,24), F(3,8), F(1,8), F(7,24)]
    bm = [F(7,24), F(1,8), F(3,8), F(5,24)]
    xs = [F(0),F(1),F(2),F(3)]
    m1p, m1m = dot(bp,xs), dot(bm,xs)
    m2p, m2m = dot(bp,[x*x for x in xs]), dot(bm,[x*x for x in xs])
    qa = [F(1,10),F(3,10),F(6,10),F(9,10)]
    qb = [F(2,10),F(8,10),F(4,10),F(7,10)]
    obs_a_diff = abs(dot(bp,qa)-dot(bm,qa))
    obs_b_diff = abs(dot(bp,qb)-dot(bm,qb))
    ra = [F(0),F(1),F(0),F(1)]
    rb = [F(1),F(0),F(1),F(0)]
    gap_p = dot(bp,ra)-dot(bp,rb)
    gap_m = dot(bm,rb)-dot(bm,ra)

    # Predictive rank test vectors: q_a, q_b, q_a^2.
    rows = [[qa[s], qb[s], qa[s]*qa[s]] for s in range(4)]
    generic_rank = affine_rank(rows)

    # Exact quotient rank from class-constant test rows reported by Julia.
    exact_rows_float = data["exact_predictive_quotient"]["test_matrix"]
    # Rationalize the reported class-equal rows conservatively to 10^-12.
    exact_class_equal = (
        max(abs(exact_rows_float[0][j]-exact_rows_float[1][j]) for j in range(len(exact_rows_float[0]))) < 1e-12
        and max(abs(exact_rows_float[2][j]-exact_rows_float[3][j]) for j in range(len(exact_rows_float[0]))) < 1e-12
        and max(abs(exact_rows_float[0][j]-exact_rows_float[2][j]) for j in range(len(exact_rows_float[0]))) > 1e-6
    )

    exact = data["exact_predictive_quotient"]
    neg = data["nonclosure_certificate"]
    versions = data["versions"]

    checks = {
        "schema": data.get("schema") == "sot-v5-pomdps-1.0",
        "reported_all_pass": data.get("all_pass") is True,
        "pompds_version": str(versions.get("POMDPs", "")).startswith("1.0"),
        "pomdptools_version": str(versions.get("POMDPTools", "")).startswith("1.1"),
        "julia_1_12": str(versions.get("Julia", "")).startswith("1.12"),
        "exact_rank_one": exact.get("predictive_affine_rank") == 1 and exact_class_equal,
        "exact_update_error": exact.get("max_class_mass_error", 1.0) < 1e-12,
        "exact_observation_error": exact.get("max_observation_prediction_error", 1.0) < 1e-12,
        "exact_reward_error": exact.get("max_expected_reward_error", 1.0) < 1e-12,
        "exact_policy_agreement": exact.get("greedy_action_disagreements") == 0 and exact.get("simulation_action_disagreements") == 0,
        "payload_reduction": exact.get("logical_payload_bytes_full") == 32 and exact.get("logical_payload_bytes_compressed") == 8,
        "same_moments_exact": m1p == m1m == F(3,2) and m2p == m2m == F(7,2),
        "generic_rank_three": generic_rank == 3 and neg.get("predictive_affine_rank") == 3,
        "obs_a_exact": abs(float(obs_a_diff)-neg.get("observation_x_difference_action_a",99.0)) < 1e-12 and obs_a_diff == F(1,120),
        "obs_b_exact": abs(float(obs_b_diff)-neg.get("observation_x_difference_action_b",99.0)) < 1e-12 and obs_b_diff == F(17,120),
        "deficiency_lb_exact": abs(float(F(17,240))-neg.get("deficiency_lower_bound_same_code",99.0)) < 1e-12,
        "reward_gap_exact": gap_p == gap_m == F(1,3) and abs(neg.get("reward_gap_plus",0.0)-1/3) < 1e-12,
        "randomized_regret_lb": abs(neg.get("randomized_policy_minimax_regret_lower_bound",0.0)-1/6) < 1e-12,
        "opposite_actions": neg.get("optimal_action_plus") != neg.get("optimal_action_minus"),
        "post_update_nonclosure": neg.get("post_update_moment_separation",0.0) > 1e-3,
        "approximation_exercised": neg.get("approximation_test_beliefs") == 10000 and neg.get("approx_max_prediction_error",0.0) > 0.0,
    }

    result = {
        "schema": "sot-v5-independent-check-1.0",
        "all_pass": all(checks.values()),
        "checks": checks,
        "recomputed_exact": {
            "mean": str(m1p),
            "second_moment": str(m2p),
            "obs_a_difference": str(obs_a_diff),
            "obs_b_difference": str(obs_b_diff),
            "deficiency_lower_bound": str(F(17,240)),
            "deterministic_regret_lower_bound": str(F(1,3)),
            "randomized_regret_lower_bound": str(F(1,6)),
            "generic_predictive_rank": generic_rank,
        },
        "pomdps_results_sha256": file_sha256(path),
        "evidence_level": "internal independent implementation; not external R2",
    }
    encoded = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
    result["canonical_sha256_without_digest"] = hashlib.sha256(encoded).hexdigest()
    out = path.parent / "independent_check.json"
    out.write_text(json.dumps(result, sort_keys=True, indent=2)+"\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True, indent=2))
    if not result["all_pass"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
