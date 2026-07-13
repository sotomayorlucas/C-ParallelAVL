from pathlib import Path

path = Path("validation/sot_v4/differential/src/main.rs")
source = path.read_text(encoding="utf-8")

source = source.replace("use differential_dataflow::operators::*;\n", "", 1)

needle = '''    let events = all_events[..process_count].to_vec();
    let timer = Instant::now();
'''
replacement = '''    let events = all_events[..process_count].to_vec();
    let events_len = events.len();
    let timer = Instant::now();
'''
if needle not in source:
    raise SystemExit("events marker not found")
source = source.replace(needle, replacement, 1)

needle = '''    timely::execute(timely::Config::thread(), move |worker| {
        let mut probe = Handle::new();
        let mut input = worker.dataflow(|scope| {
'''
replacement = '''    timely::execute(timely::Config::thread(), move |worker| {
        let mut probe = Handle::new();
        let mut input = worker.dataflow(|scope| {
            let edge_state_data = edge_state_cb.clone();
            let path_state_data = path_state_cb.clone();
            let cycle_state_data = cycle_state_cb.clone();
            let path_abs_data = path_abs_cb.clone();
            let cycle_abs_data = cycle_abs_cb.clone();
'''
if needle not in source:
    raise SystemExit("dataflow closure marker not found")
source = source.replace(needle, replacement, 1)

for old, new in [
    ("edge_state_cb.lock()", "edge_state_data.lock()"),
    ("path_abs_cb.lock()", "path_abs_data.lock()"),
    ("path_state_cb.lock()", "path_state_data.lock()"),
    ("cycle_abs_cb.lock()", "cycle_abs_data.lock()"),
    ("cycle_state_cb.lock()", "cycle_state_data.lock()"),
]:
    if old not in source:
        raise SystemExit(f"callback marker not found: {old}")
    source = source.replace(old, new, 1)

needle = "        input_events_available: all_events.len(), input_events_processed: events.len(), window_seconds, batch_size,\n"
replacement = "        input_events_available: all_events.len(), input_events_processed: events_len, window_seconds, batch_size,\n"
if needle not in source:
    raise SystemExit("output length marker not found")
source = source.replace(needle, replacement, 1)

path.write_text(source, encoding="utf-8")
