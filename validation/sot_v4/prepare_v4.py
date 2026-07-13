from pathlib import Path

path = Path("validation/sot_v4/tgb_validation.py")
source = path.read_text(encoding="utf-8")

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
        count, ws = count_temporal_triangles(src, dst, ts, delta,
                                             args.cover_witnesses if delta == cover_delta else 0)
        triangle_counts[str(delta)] = int(count); triangle_times[str(delta)] = time.perf_counter() - t0
        if delta == cover_delta:
            witnesses = ws
    if len(witnesses) < 6:
        raise RuntimeError(f"only {len(witnesses)} real temporal triangles at cover window {cover_delta}")
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

old = '        "cover_certificates": cover_summary, "walsh_repair": walsh,\n'
new = '        "cover_delta_seconds": cover_delta, "cover_certificates": cover_summary, "walsh_repair": walsh,\n'
if old not in source:
    raise SystemExit("result block not found")
source = source.replace(old, new, 1)

path.write_text(source, encoding="utf-8")
