#!/usr/bin/env python3
"""SOT V4 external validation on the official TGB tgbl-uci stream.

The script uses py-tgb 2.2.0 to load the dataset and its official validation/test
negative samples. It then:
  * measures exact causal temporal closure at three windows;
  * builds cover-derived blindness certificates from real temporal triangles;
  * synthesizes the minimal Walsh repair on a six-coordinate real-derived fibre;
  * evaluates EdgeBank, a one-feature closure repair, a random-bit control, and
    a larger catalogue on official TGB negative samples;
  * exports a chronological edge stream for Differential Dataflow.

All tie handling follows TGB's MRR evaluator:
rank = 0.5 * (#neg > pos + #neg >= pos) + 1.
"""

from __future__ import annotations

import argparse
import bisect
import collections
import hashlib
import json
import math
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Deque, Dict, List, Mapping, Sequence, Tuple

import numpy as np

DAY = 86_400
WINDOWS = (DAY, 7 * DAY, 30 * DAY)
DATASET = "tgbl-uci"
SEED = 20260713


def canonical_json_bytes(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sha256_obj(obj: object) -> str:
    return hashlib.sha256(canonical_json_bytes(obj)).hexdigest()


def mrr_one(pos: float, neg: np.ndarray) -> float:
    optimistic = int(np.sum(neg > pos))
    pessimistic = int(np.sum(neg >= pos))
    rank = 0.5 * (optimistic + pessimistic) + 1.0
    return 1.0 / rank


def evaluate_records(records: Sequence[dict], model: str, params: Tuple[float, ...]) -> float:
    vals: List[float] = []
    for rec in records:
        f = rec["features"]
        if model == "baseline":
            scores = f[:, 0]
        elif model == "sot":
            (lam,) = params
            scores = f[:, 0] + lam * f[:, 1]
        elif model == "random":
            (lam,) = params
            scores = f[:, 0] + lam * f[:, 3]
        elif model == "catalogue":
            lam, mu = params
            scores = f[:, 0] + lam * f[:, 1] + mu * f[:, 2]
        else:
            raise ValueError(model)
        vals.append(mrr_one(float(scores[0]), np.asarray(scores[1:], dtype=np.float64)))
    return float(np.mean(vals)) if vals else float("nan")


def tune(records: Sequence[dict], model: str) -> Tuple[Tuple[float, ...], float]:
    grid = (0.0, 1.0 / 64.0, 1.0 / 32.0, 1.0 / 16.0, 0.125, 0.25, 0.5, 1.0, 2.0, 4.0)
    if model in ("sot", "random"):
        choices = [(x,) for x in grid]
    elif model == "catalogue":
        choices = [(x, y) for x in grid for y in grid]
    else:
        return tuple(), evaluate_records(records, "baseline", tuple())
    best_params: Tuple[float, ...] | None = None
    best = -1.0
    for p in choices:
        val = evaluate_records(records, model, p)
        if val > best + 1e-15 or (abs(val - best) <= 1e-15 and (best_params is None or p < best_params)):
            best = val
            best_params = p
    assert best_params is not None
    return best_params, best


class WindowRepair:
    """Maintains active simple edges and the directed two-path repair.

    two_paths[(c, a)] counts distinct intermediates b with active edges
    a -> b and b -> c. Thus a candidate c -> a closes a directed 3-cycle.
    """

    def __init__(self, window: int):
        self.window = int(window)
        self.events: Deque[Tuple[int, int, int]] = collections.deque()
        self.active_count: Dict[Tuple[int, int], int] = collections.defaultdict(int)
        self.out: Dict[int, set[int]] = collections.defaultdict(set)
        self.inn: Dict[int, set[int]] = collections.defaultdict(set)
        self.two_paths: Dict[Tuple[int, int], int] = collections.defaultdict(int)
        self.history: set[Tuple[int, int]] = set()
        self.relation_inserts = 0
        self.relation_removes = 0
        self.two_path_key_changes = 0

    def _bump_two(self, key: Tuple[int, int], delta: int) -> None:
        old = self.two_paths.get(key, 0)
        new = old + delta
        if new < 0:
            raise AssertionError((key, old, delta))
        if (old == 0) != (new == 0):
            self.two_path_key_changes += 1
        if new:
            self.two_paths[key] = new
        else:
            self.two_paths.pop(key, None)

    def _activate(self, a: int, b: int) -> None:
        if a == b:
            return
        for x in tuple(self.inn.get(a, ())):
            if x != b:
                self._bump_two((b, x), +1)
        for y in tuple(self.out.get(b, ())):
            if y != a:
                self._bump_two((y, a), +1)
        self.out[a].add(b)
        self.inn[b].add(a)
        self.relation_inserts += 1

    def _deactivate(self, a: int, b: int) -> None:
        if a == b:
            return
        for x in tuple(self.inn.get(a, ())):
            if x != b:
                self._bump_two((b, x), -1)
        for y in tuple(self.out.get(b, ())):
            if y != a:
                self._bump_two((y, a), -1)
        self.out[a].discard(b)
        self.inn[b].discard(a)
        if not self.out[a]:
            self.out.pop(a, None)
        if not self.inn[b]:
            self.inn.pop(b, None)
        self.relation_removes += 1

    def expire(self, now: int) -> None:
        cutoff = int(now) - self.window
        while self.events and self.events[0][0] < cutoff:
            _t, a, b = self.events.popleft()
            key = (a, b)
            old = self.active_count[key]
            if old <= 0:
                raise AssertionError(key)
            if old == 1:
                del self.active_count[key]
                self._deactivate(a, b)
            else:
                self.active_count[key] = old - 1

    def insert(self, a: int, b: int, t: int) -> None:
        key = (int(a), int(b))
        self.history.add(key)
        self.events.append((int(t), int(a), int(b)))
        if self.active_count[key] == 0:
            self._activate(*key)
        self.active_count[key] += 1

    def features(self, src: int, dst: int) -> Tuple[float, float, float, float]:
        seen = 1.0 if (src, dst) in self.history else 0.0
        closure = math.log1p(self.two_paths.get((src, dst), 0))
        reciprocal = 1.0 if (dst, src) in self.history else 0.0
        hash_bit = float(((src * 73_856_093) ^ (dst * 19_349_663)) & 1)
        return seen, closure, reciprocal, hash_bit

    def ordered_cycle_count(self) -> int:
        return sum(self.two_paths.get(edge, 0) for edge in self.active_count)

    def full_rebuild(self) -> Tuple[int, int, int]:
        edges = set(self.active_count)
        out: Dict[int, set[int]] = collections.defaultdict(set)
        for a, b in edges:
            if a != b:
                out[a].add(b)
        ordered = 0
        two: Dict[Tuple[int, int], int] = collections.defaultdict(int)
        for a, b in edges:
            if a == b:
                continue
            for c in out.get(b, ()):
                if c == a:
                    continue
                two[(c, a)] += 1
                if (c, a) in edges:
                    ordered += 1
        return ordered, len(two), sum(two.values())


@dataclass(frozen=True)
class TriangleWitness:
    e1: int
    e2: int
    e3: int
    a: object
    b: object
    c: object
    t1: int
    t2: int
    t3: int


def count_temporal_triangles(src: Sequence, dst: Sequence, ts: Sequence, delta: int, witness_limit: int = 0):
    incoming: Dict[object, List[Tuple[int, int, object]]] = collections.defaultdict(list)
    pair_times: Dict[Tuple[object, object], List[Tuple[int, int]]] = collections.defaultdict(list)
    total = 0
    witnesses: List[TriangleWitness] = []

    def node_value(x):
        if isinstance(x, np.ndarray):
            return tuple(x.tolist())
        if isinstance(x, np.generic):
            return x.item()
        return x

    for idx, (c_raw, a_raw, t_raw) in enumerate(zip(src, dst, ts)):
        c, a, t3 = node_value(c_raw), node_value(a_raw), int(t_raw)
        inc = incoming.get(c, ())
        lo2 = bisect.bisect_left(inc, (t3 - delta, -1, None))
        hi2 = bisect.bisect_left(inc, (t3, -1, None))
        for t2, e2, b in inc[lo2:hi2]:
            if len({a, b, c}) < 3:
                continue
            p = pair_times.get((a, b), ())
            lo1 = bisect.bisect_left(p, (t2 - delta, -1))
            hi1 = bisect.bisect_left(p, (t2, -1))
            total += hi1 - lo1
            if witness_limit and len(witnesses) < witness_limit:
                for t1, e1 in p[lo1:hi1]:
                    witnesses.append(TriangleWitness(e1, e2, idx, a, b, c, t1, t2, t3))
                    if len(witnesses) >= witness_limit:
                        break
        incoming[a].append((t3, idx, c))
        pair_times[(c, a)].append((t3, idx))
    return total, witnesses


def augmented_graph(nodes, events, delta: int):
    labels = {}
    out = collections.defaultdict(set)
    inn = collections.defaultdict(set)
    entity_nodes = [("v", n) for n in nodes]
    event_nodes = [("e", i) for i in range(len(events))]
    for x in entity_nodes:
        labels[x] = 0
    for x in event_nodes:
        labels[x] = 1
    for i, (u, v, _t) in enumerate(events):
        e = ("e", i)
        su, tv = ("v", u), ("v", v)
        out[su].add(e); inn[e].add(su)
        out[e].add(tv); inn[tv].add(e)
    by_src = collections.defaultdict(list)
    for j, (u, _v, _t) in enumerate(events):
        by_src[u].append(j)
    for i, (_u, v, t) in enumerate(events):
        for j in by_src.get(v, ()):
            t2 = events[j][2]
            if 1 <= t2 - t <= delta:
                a, b = ("e", i), ("e", j)
                out[a].add(b); inn[b].add(a)
    return entity_nodes + event_nodes, labels, out, inn


def joint_wl_hist(graphs):
    all_tagged = []
    labels = {}
    out = collections.defaultdict(set)
    inn = collections.defaultdict(set)
    sides = []
    for side, (nodes, lab, gout, ginn) in enumerate(graphs):
        side_nodes = []
        for n in nodes:
            tn = (side, n)
            side_nodes.append(tn)
            labels[tn] = lab[n]
        for n in nodes:
            tn = (side, n)
            out[tn] = {(side, m) for m in gout.get(n, ())}
            inn[tn] = {(side, m) for m in ginn.get(n, ())}
        sides.append(side_nodes)
        all_tagged.extend(side_nodes)
    colors = {n: labels[n] for n in all_tagged}
    strict_changes = 0
    while True:
        signatures = {n: (colors[n], tuple(sorted(colors[m] for m in inn.get(n, ()))),
                          tuple(sorted(colors[m] for m in out.get(n, ())))) for n in all_tagged}
        dictionary = {sig: i for i, sig in enumerate(sorted(set(signatures.values()), key=repr))}
        new = {n: dictionary[signatures[n]] for n in all_tagged}
        if all((colors[a] == colors[b]) == (new[a] == new[b]) for a in all_tagged for b in all_tagged):
            colors = new
            break
        colors = new
        strict_changes += 1
    return [tuple(sorted(colors[n] for n in side_nodes)) for side_nodes in sides], strict_changes


def double_cover(base_events, voltages):
    base_nodes = sorted({x for e in base_events for x in e[:2]})
    nodes = [(v, s) for v in base_nodes for s in (0, 1)]
    events = []
    for i, (u, v, t) in enumerate(base_events):
        bit = int(voltages[i]) & 1
        for s in (0, 1):
            events.append(((u, s), (v, s ^ bit), int(t)))
    return nodes, events


def cover_certificate(w: TriangleWitness, delta: int) -> dict:
    base = [(0, 1, w.t1), (1, 2, w.t2), (2, 0, w.t3)]
    tn, te = double_cover(base, [0, 0, 0])
    wn, we = double_cover(base, [0, 0, 1])
    hists, rounds = joint_wl_hist([augmented_graph(tn, te, delta), augmented_graph(wn, we, delta)])
    c0, _ = count_temporal_triangles([e[0] for e in te], [e[1] for e in te], [e[2] for e in te], delta)
    c1, _ = count_temporal_triangles([e[0] for e in we], [e[1] for e in we], [e[2] for e in we], delta)
    return {"wl_equal": hists[0] == hists[1], "wl_strict_refinements": rounds,
            "trivial_count": int(c0), "twisted_count": int(c1),
            "base_gaps": [w.t2 - w.t1, w.t3 - w.t2]}


def gf2_rank(vectors, beta: int) -> int:
    basis = [0] * beta
    rank = 0
    for x0 in vectors:
        x = int(x0)
        while x:
            p = x.bit_length() - 1
            if basis[p]:
                x ^= basis[p]
            else:
                basis[p] = x
                rank += 1
                break
    return rank


def walsh_table(values, beta: int):
    n = 1 << beta
    out = {}
    for a in range(n):
        coeff = sum(int(values[x]) * (-1 if ((a & x).bit_count() & 1) else 1) for x in range(n))
        if coeff:
            out[a] = coeff
    return out


def real_derived_walsh(witnesses, delta: int, beta: int = 6) -> dict:
    if len(witnesses) < beta:
        raise RuntimeError("not enough witnesses")
    base_cycles = []
    offset = 0
    for i, w in enumerate(witnesses[:beta]):
        gaps = (max(1, w.t2 - w.t1), max(1, w.t3 - w.t2))
        times = (0, gaps[0], gaps[0] + gaps[1]) if i == 0 else (0, gaps[0] + gaps[1], gaps[0])
        base_cycles.append([(offset, offset + 1, times[0]), (offset + 1, offset + 2, times[1]),
                            (offset + 2, offset, times[2])])
        offset += 3
    query = []
    reference_hist = None
    wl_all_equal = True
    for x in range(1 << beta):
        nodes, events = [], []
        for i, cycle in enumerate(base_cycles):
            cn, ce = double_cover(cycle, [0, 0, (x >> i) & 1])
            nodes.extend(cn); events.extend(ce)
        c, _ = count_temporal_triangles([e[0] for e in events], [e[1] for e in events],
                                        [e[2] for e in events], delta)
        query.append(int(c))
        hist = joint_wl_hist([augmented_graph(nodes, events, delta)])[0][0]
        if reference_hist is None:
            reference_hist = hist
        else:
            wl_all_equal = wl_all_equal and hist == reference_hist
    spectrum = walsh_table(query, beta)
    support = sorted(a for a in spectrum if a != 0)
    return {"beta": beta, "query_table": query,
            "spectrum": {format(a, f"0{beta}b"): int(v) for a, v in sorted(spectrum.items())},
            "nonconstant_support": [format(a, f"0{beta}b") for a in support],
            "repair_rank": gf2_rank(support, beta), "full_catalogue_bits": beta,
            "all_wl_equal": wl_all_equal, "expected_active_direction": format(1, f"0{beta}b")}


def select_evenly(indices: np.ndarray, limit: int) -> set[int]:
    if len(indices) <= limit:
        return {int(x) for x in indices}
    positions = np.linspace(0, len(indices) - 1, num=limit, dtype=np.int64)
    return {int(indices[p]) for p in positions}


def collect_link_records(dataset, data, limit_per_split: int, window: int):
    src = np.asarray(data["sources"], dtype=np.int64)
    dst = np.asarray(data["destinations"], dtype=np.int64)
    ts = np.asarray(data["timestamps"], dtype=np.int64)
    selected_val = select_evenly(np.flatnonzero(np.asarray(dataset.val_mask, dtype=bool)), limit_per_split)
    selected_test = select_evenly(np.flatnonzero(np.asarray(dataset.test_mask, dtype=bool)), limit_per_split)
    dataset.load_val_ns(); dataset.load_test_ns()
    sampler = dataset.negative_sampler
    state = WindowRepair(window)
    records = {"val": [], "test": []}
    checkpoint_checks = []
    i, n = 0, len(src)
    while i < n:
        t = int(ts[i]); j = i + 1
        while j < n and int(ts[j]) == t:
            j += 1
        state.expire(t)
        for idx in range(i, j):
            split = "val" if idx in selected_val else ("test" if idx in selected_test else None)
            if split:
                u, v = int(src[idx]), int(dst[idx])
                negs = sampler.query_batch(np.asarray([u]), np.asarray([v]), np.asarray([t]), split_mode=split)[0]
                candidates = [v] + [int(x) for x in negs]
                records[split].append({"edge_index": idx, "timestamp": t, "src": u, "dst": v,
                                       "num_negatives": len(negs),
                                       "features": np.asarray([state.features(u, x) for x in candidates], dtype=np.float64)})
        for idx in range(i, j):
            state.insert(int(src[idx]), int(dst[idx]), t)
        if j % 5000 < (j - i):
            inc = state.ordered_cycle_count(); full, full_keys, full_paths = state.full_rebuild()
            checkpoint_checks.append({"prefix": j, "timestamp": t,
                "incremental_ordered_cycles": inc, "full_ordered_cycles": full, "match": inc == full,
                "two_path_keys": len(state.two_paths), "full_two_path_keys": full_keys,
                "two_path_multiplicity": sum(state.two_paths.values()),
                "full_two_path_multiplicity": full_paths})
        i = j
    return records, checkpoint_checks, state


def model_results(records):
    val, test = records["val"], records["test"]
    out = {"baseline": {"params": [], "val_mrr": evaluate_records(val, "baseline", tuple()),
                         "test_mrr": evaluate_records(test, "baseline", tuple())}}
    for model in ("sot", "random", "catalogue"):
        params, val_score = tune(val, model)
        out[model] = {"params": list(params), "val_mrr": val_score,
                      "test_mrr": evaluate_records(test, model, params)}
    out.update({"num_val_queries": len(val), "num_test_queries": len(test),
        "mean_negatives_val": float(np.mean([r["num_negatives"] for r in val])) if val else 0.0,
        "mean_negatives_test": float(np.mean([r["num_negatives"] for r in test])) if test else 0.0,
        "positive_closure_rate_val": float(np.mean([r["features"][0, 1] > 0 for r in val])) if val else 0.0,
        "positive_closure_rate_test": float(np.mean([r["features"][0, 1] > 0 for r in test])) if test else 0.0})
    return out


def run(args):
    from tgb.linkproppred.dataset import LinkPropPredDataset
    import tgb
    out_dir = Path(args.out_dir); out_dir.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    dataset = LinkPropPredDataset(name=DATASET, root="datasets", preprocess=True)
    data = dataset.full_data
    src = np.asarray(data["sources"], dtype=np.int64)
    dst = np.asarray(data["destinations"], dtype=np.int64)
    ts = np.asarray(data["timestamps"], dtype=np.int64)
    sorted_input = bool(np.all(ts[:-1] <= ts[1:]))
    if not sorted_input:
        raise RuntimeError("TGB stream is not chronologically sorted; refusing to reorder masks/negative samples")
    edges_path = out_dir / "tgbl_uci_edges.tsv"
    with edges_path.open("w", encoding="utf-8") as f:
        f.write("src\tdst\ttimestamp\n")
        for u, v, t in zip(src, dst, ts):
            f.write(f"{int(u)}\t{int(v)}\t{int(t)}\n")
    triangle_counts, triangle_times, witnesses = {}, {}, []
    for delta in WINDOWS:
        t0 = time.perf_counter()
        count, ws = count_temporal_triangles(src, dst, ts, delta,
                                             args.cover_witnesses if delta == 7 * DAY else 0)
        triangle_counts[str(delta)] = int(count); triangle_times[str(delta)] = time.perf_counter() - t0
        if delta == 7 * DAY:
            witnesses = ws
    certs = [cover_certificate(w, 7 * DAY) for w in witnesses[:args.cover_witnesses]]
    cover_summary = {"attempted": len(certs),
        "passed": sum(c["wl_equal"] and c["trivial_count"] == 2 and c["twisted_count"] == 0 for c in certs),
        "mean_wl_refinements": float(np.mean([c["wl_strict_refinements"] for c in certs])) if certs else 0.0,
        "all_counts_2_vs_0": all(c["trivial_count"] == 2 and c["twisted_count"] == 0 for c in certs),
        "all_wl_equal": all(c["wl_equal"] for c in certs), "sample": certs[:5]}
    walsh = real_derived_walsh(witnesses, 7 * DAY, beta=6)
    records, checkpoints, final_state = collect_link_records(dataset, data, args.eval_queries, 7 * DAY)
    metadata = {"dataset": DATASET, "py_tgb_version": getattr(tgb, "__version__", "unknown"),
        "num_edges": int(len(src)), "num_nodes": int(len(np.unique(np.concatenate([src, dst])))),
        "timestamp_min": int(ts.min()), "timestamp_max": int(ts.max()),
        "duration_seconds": int(ts.max() - ts.min()), "input_already_sorted": sorted_input,
        "train_edges": int(np.sum(dataset.train_mask)), "val_edges": int(np.sum(dataset.val_mask)),
        "test_edges": int(np.sum(dataset.test_mask)), "eval_metric": dataset.eval_metric,
        "edge_stream_sha256": hashlib.sha256(edges_path.read_bytes()).hexdigest()}
    result = {"schema": "sot-v4-tgb-1.0", "seed": SEED, "metadata": metadata,
        "temporal_triangle_counts": triangle_counts, "temporal_triangle_runtime_seconds": triangle_times,
        "cover_certificates": cover_summary, "walsh_repair": walsh,
        "link_prediction": model_results(records), "incremental_python_checkpoints": checkpoints,
        "final_window_state": {"active_edge_keys": len(final_state.active_count),
            "two_path_keys": len(final_state.two_paths), "two_path_multiplicity": sum(final_state.two_paths.values()),
            "ordered_cycles": final_state.ordered_cycle_count(), "relation_inserts": final_state.relation_inserts,
            "relation_removes": final_state.relation_removes,
            "two_path_key_changes": final_state.two_path_key_changes},
        "runtime_seconds": time.perf_counter() - started}
    result["result_sha256_without_digest"] = sha256_obj(result)
    (out_dir / "tgb_results.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def self_test():
    s = WindowRepair(10); s.insert(0, 1, 1); s.insert(1, 2, 2)
    assert s.two_paths[(2, 0)] == 1 and s.ordered_cycle_count() == 0
    s.insert(2, 0, 3); assert s.ordered_cycle_count() == 3 and s.full_rebuild()[0] == 3
    s.expire(12); assert s.ordered_cycle_count() == 0
    src = np.array([0, 1, 2, 3, 4, 5]); dst = np.array([1, 2, 0, 4, 5, 3]); ts = np.array([1, 2, 3, 1, 2, 3])
    c, ws = count_temporal_triangles(src, dst, ts, 10, 10)
    assert c == 2 and len(ws) == 2
    cert = cover_certificate(ws[0], 10)
    assert cert["wl_equal"] and cert["trivial_count"] == 2 and cert["twisted_count"] == 0
    values = [2 if (x & 1) == 0 else 0 for x in range(64)]
    assert gf2_rank([a for a in walsh_table(values, 6) if a], 6) == 1
    print("self-test: PASS")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", default="validation/sot_v4/out")
    parser.add_argument("--eval-queries", type=int, default=1200)
    parser.add_argument("--cover-witnesses", type=int, default=128)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test(); return
    print(json.dumps(run(args), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
