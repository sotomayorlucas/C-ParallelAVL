from pathlib import Path

path = Path("validation/sot_v4/tgb_validation.py")
source = path.read_text(encoding="utf-8")

# Insert access to the official raw TGB edge file. The processed TGB stream is
# retained unchanged for the official link-prediction task and negative samples.
needle = '''    if not sorted_input:
        raise RuntimeError("TGB stream is not chronologically sorted; refusing to reorder masks/negative samples")
'''
replacement = '''    if not sorted_input:
        raise RuntimeError("TGB processed stream is not chronologically sorted; refusing to reorder masks/negative samples")

    # TGB's JODIE-compatible loader shifts destination identifiers into a
    # disjoint range. That is correct for the official link-prediction task,
    # but it intentionally erases cycles. Structural SOT tests therefore read
    # the same official raw TGB edge file before the bipartite reindexing.
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
if needle not in source:
    raise SystemExit("chronology marker not found")
source = source.replace(needle, replacement, 1)

# Export raw identifiers to Differential Dataflow while keeping official TGB
# processed identifiers for the link-prediction evaluator.
needle = "        for u, v, t in zip(src, dst, ts):\n"
if needle not in source:
    raise SystemExit("edge export iterator not found")
source = source.replace(needle, "        for u, v, t in zip(raw_src, raw_dst, raw_ts):\n", 1)

# Count structural motifs and construct blind fibres on the raw stream.
needle = "    triangle_counts, triangle_times, witnesses = {}, {}, []\n"
if needle not in source:
    raise SystemExit("triangle-count marker not found")
source = source.replace(needle, "    cover_delta = 30 * DAY\n" + needle, 1)
source = source.replace(
    "        count, ws = count_temporal_triangles(src, dst, ts, delta,\n",
    "        count, ws = count_temporal_triangles(raw_src, raw_dst, raw_ts, delta,\n",
    1,
)
source = source.replace(
    "                                             args.cover_witnesses if delta == 7 * DAY else 0)\n",
    "                                             args.cover_witnesses if delta == cover_delta else 0)\n",
    1,
)
source = source.replace("        if delta == 7 * DAY:\n", "        if delta == cover_delta:\n", 1)
source = source.replace(
    "    certs = [cover_certificate(w, 7 * DAY) for w in witnesses[:args.cover_witnesses]]\n",
    '''    if len(witnesses) < 6:
        raise RuntimeError(f"only {len(witnesses)} raw-stream temporal triangles at cover window {cover_delta}")
    certs = [cover_certificate(w, cover_delta) for w in witnesses[:args.cover_witnesses]]
''',
    1,
)
source = source.replace(
    "    walsh = real_derived_walsh(witnesses, 7 * DAY, beta=6)\n",
    "    walsh = real_derived_walsh(witnesses, cover_delta, beta=6)\n",
    1,
)

# Record both processed-task and raw-structural semantics.
needle = '        "duration_seconds": int(ts.max() - ts.min()), "input_already_sorted": sorted_input,\n'
if needle not in source:
    raise SystemExit("metadata marker not found")
source = source.replace(
    needle,
    needle + '''        "raw_num_edges": int(len(raw_src)),
        "raw_num_nodes": int(len(np.unique(np.concatenate([raw_src, raw_dst])))),
        "raw_timestamp_min": int(raw_ts.min()), "raw_timestamp_max": int(raw_ts.max()),
        "raw_input_already_sorted": raw_sorted_input,
        "structural_stream_semantics": "official raw TGB IDs before JODIE bipartite destination shift",
''',
    1,
)
needle = '        "cover_certificates": cover_summary, "walsh_repair": walsh,\n'
if needle not in source:
    raise SystemExit("result marker not found")
source = source.replace(
    needle,
    '        "cover_delta_seconds": cover_delta, "cover_certificates": cover_summary, "walsh_repair": walsh,\n',
    1,
)

path.write_text(source, encoding="utf-8")
