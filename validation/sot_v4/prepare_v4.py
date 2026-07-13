from pathlib import Path

path = Path("validation/sot_v4/tgb_validation.py")
source = path.read_text(encoding="utf-8")

old = '''    data = dataset.full_data
    src = np.asarray(data["sources"], dtype=np.int64)
    dst = np.asarray(data["destinations"], dtype=np.int64)
    ts = np.asarray(data["timestamps"], dtype=np.int64)
    sorted_input = bool(np.all(ts[:-1] <= ts[1:]))
    if not sorted_input:
        raise RuntimeError("TGB stream is not chronologically sorted; refusing to reorder masks/negative samples")
'''
new = '''    data = dataset.full_data
    src = np.asarray(data["sources"], dtype=np.int64)
    dst = np.asarray(data["destinations"], dtype=np.int64)
    ts = np.asarray(data["timestamps"], dtype=np.int64)
    sorted_input = bool(np.all(ts[:-1] <= ts[1:]))
    if not sorted_input:
        raise RuntimeError("TGB processed stream is not chronologically sorted; refusing to reorder masks/negative samples")

    # TGB's JODIE-compatible loader shifts destination identifiers into a
    # disjoint range. That is correct for the official link-prediction task,
    # but it intentionally erases cycles. For structural SOT tests we read the
    # same official raw TGB edge file before this bipartite reindexing.
    import pandas as pd
    raw_df = pd.read_csv(dataset.meta_dict["fname"], skiprows=1, header=None)
    raw_src = np.asarray(raw_df.iloc[:, 0], dtype=np.int64)
    raw_dst = np.asarray(raw_df.iloc[:, 1], dtype=np.int64)
    raw_ts = np.asarray(raw_df.iloc[:, 2], dtype=np.int64)
    raw_sorted_input = bool(np.all(raw_ts[:-1] <= raw_ts[1:]))
    if not raw_sorted_input:
        order = np.argsort(raw_ts, kind="stable")
        raw_src, raw_dst, raw_ts = raw_src[order], raw_dst[order], raw_ts[order]
'''
if old not in source:
    raise SystemExit("processed/raw stream block not found")
source = source.replace(old, new, 1)

old = '''    with edges_path.open("w", encoding="utf-8") as f:
        f.write("src\tdst\ttimestamp\n")
        for u, v, t in zip(src, dst, ts):
            f.write(f"{int(u)}\t{int(v)}\t{int(t)}\n")
'''
new = '''    with edges_path.open("w", encoding="utf-8") as f:
        f.write("src\tdst\ttimestamp\n")
        for u, v, t in zip(raw_src, raw_dst, raw_ts):
            f.write(f"{int(u)}\t{int(v)}\t{int(t)}\n")
'''
if old not in source:
    raise SystemExit("edge export block not found")
source = source.replace(old, new, 1)

old = '''    triangle_counts, triangle_times, witnesses = {}, {}, []
    for delta in WINDOWS:
        t0 = time.perf_counter()
        count, ws = count_temporal_triangles(src, dst, ts, delta,
                                             args.cover_witnesses if delta == 7 * DAY else 0)
        triangle_counts[str(delta)] = int(count); triangle_times[str(delta)] = time.perf_counter() - t0
        if delta == 7 * DAY:
            witnesses = ws
    certs = [cover_certificate(w, 7 * DAY) for w in witnesses[:args.cover_witnesses]]
'''
new = '''    cover_delta = 30 * DAY
    triangle_counts, triangle_times, witnesses = {}, {}, []
    for delta in WINDOWS:
        t0 = time.perf_counter()
        count, ws = count_temporal_triangles(raw_src, raw_dst, raw_ts, delta,
                                             args.cover_witnesses if delta == cover_delta else 0)
        triangle_counts[str(delta)] = int(count); triangle_times[str(delta)] = time.perf_counter() - t0
        if delta == cover_delta:
            witnesses = ws
    if len(witnesses) < 6:
        raise RuntimeError(f"only {len(witnesses)} raw-stream temporal triangles at cover window {cover_delta}")
    certs = [cover_certificate(w, cover_delta) for w in witnesses[:args.cover_witnesses]]
'''
if old not in source:
    raise SystemExit("triangle witness block not found")
source = source.replace(old, new, 1)

old = '    walsh = real_derived_walsh(witnesses, 7 * DAY, beta=6)\n'
new = '    walsh = real_derived_walsh(witnesses, cover_delta, beta=6)\n'
if old not in source:
    raise SystemExit("walsh block not found")
source = source.replace(old, new, 1)

old = '''    metadata = {"dataset": DATASET, "py_tgb_version": getattr(tgb, "__version__", "unknown"),
        "num_edges": int(len(src)), "num_nodes": int(len(np.unique(np.concatenate([src, dst])))),
        "timestamp_min": int(ts.min()), "timestamp_max": int(ts.max()),
        "duration_seconds": int(ts.max() - ts.min()), "input_already_sorted": sorted_input,
'''
new = '''    metadata = {"dataset": DATASET, "py_tgb_version": getattr(tgb, "__version__", "unknown"),
        "num_edges": int(len(src)), "num_nodes": int(len(np.unique(np.concatenate([src, dst])))),
        "timestamp_min": int(ts.min()), "timestamp_max": int(ts.max()),
        "duration_seconds": int(ts.max() - ts.min()), "input_already_sorted": sorted_input,
        "raw_num_edges": int(len(raw_src)),
        "raw_num_nodes": int(len(np.unique(np.concatenate([raw_src, raw_dst])))),
        "raw_timestamp_min": int(raw_ts.min()), "raw_timestamp_max": int(raw_ts.max()),
        "raw_input_already_sorted": raw_sorted_input,
        "structural_stream_semantics": "official raw TGB IDs before JODIE bipartite destination shift",
'''
if old not in source:
    raise SystemExit("metadata block not found")
source = source.replace(old, new, 1)

old = '        "cover_certificates": cover_summary, "walsh_repair": walsh,\n'
new = '        "cover_delta_seconds": cover_delta, "cover_certificates": cover_summary, "walsh_repair": walsh,\n'
if old not in source:
    raise SystemExit("result block not found")
source = source.replace(old, new, 1)

path.write_text(source, encoding="utf-8")
