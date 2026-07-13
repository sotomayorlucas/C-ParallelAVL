use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use differential_dataflow::input::Input;
use differential_dataflow::operators::*;
use serde::Serialize;
use timely::dataflow::operators::probe::Handle;

type Node = u32;
type Edge = (Node, Node);

#[derive(Clone, Copy, Debug)]
struct Event { src: Node, dst: Node, ts: i64 }

#[derive(Debug, Serialize)]
struct Checkpoint {
    epoch: usize,
    events_processed: usize,
    timestamp: i64,
    active_edges: usize,
    dataflow_edge_keys: usize,
    two_path_keys: usize,
    two_path_multiplicity: i64,
    dataflow_ordered_cycles: i64,
    rebuild_ordered_cycles: i64,
    rebuild_two_path_keys: usize,
    rebuild_two_path_multiplicity: i64,
    exact_match: bool,
    relation_inserts: usize,
    relation_removes: usize,
    two_path_abs_delta: i64,
    cycle_abs_delta: i64,
    full_rebuild_edge_visits: usize,
    full_rebuild_wedge_visits: usize,
}

#[derive(Debug, Serialize)]
struct Output {
    schema: &'static str,
    differential_dataflow_version: &'static str,
    timely_version: &'static str,
    input_events_available: usize,
    input_events_processed: usize,
    window_seconds: i64,
    batch_size: usize,
    checkpoints: Vec<Checkpoint>,
    all_exact: bool,
    total_relation_inserts: usize,
    total_relation_removes: usize,
    total_two_path_abs_delta: i64,
    total_cycle_abs_delta: i64,
    total_full_rebuild_edge_visits: usize,
    total_full_rebuild_wedge_visits: usize,
    wall_seconds: f64,
    canonical_blindness: CanonicalBlindness,
}

#[derive(Debug, Serialize)]
struct CanonicalBlindness {
    degree_hist_equal: bool,
    c6_ordered_triangles: i64,
    two_c3_ordered_triangles: i64,
}

fn read_events(path: &str) -> Vec<Event> {
    let file = BufReader::new(File::open(path).expect("open edge stream"));
    let mut events = Vec::new();
    for (idx, line) in file.lines().enumerate() {
        let line = line.expect("read line");
        if idx == 0 && line.starts_with("src") { continue; }
        if line.trim().is_empty() { continue; }
        let mut it = line.split('\t');
        let src: Node = it.next().expect("src").parse().expect("src integer");
        let dst: Node = it.next().expect("dst").parse().expect("dst integer");
        let ts: i64 = it.next().expect("timestamp").parse().expect("timestamp integer");
        events.push(Event { src, dst, ts });
    }
    events
}

fn update_map<K: std::hash::Hash + Eq + Copy>(map: &mut HashMap<K, isize>, key: K, diff: isize) {
    let next = map.get(&key).copied().unwrap_or(0) + diff;
    if next == 0 { map.remove(&key); } else { map.insert(key, next); }
}

fn full_rebuild(edges: &HashSet<Edge>) -> (i64, usize, i64, usize, usize) {
    let mut out: HashMap<Node, Vec<Node>> = HashMap::new();
    for &(u, v) in edges {
        if u != v { out.entry(u).or_default().push(v); }
    }
    let mut two: HashMap<Edge, i64> = HashMap::new();
    let mut ordered = 0i64;
    let mut edge_visits = 0usize;
    let mut wedge_visits = 0usize;
    for &(u, v) in edges {
        edge_visits += 1;
        if u == v { continue; }
        if let Some(nexts) = out.get(&v) {
            for &w in nexts {
                wedge_visits += 1;
                if w == u { continue; }
                *two.entry((w, u)).or_insert(0) += 1;
                if edges.contains(&(w, u)) { ordered += 1; }
            }
        }
    }
    let multiplicity = two.values().sum();
    (ordered, two.len(), multiplicity, edge_visits, wedge_visits)
}

fn canonical_blindness() -> CanonicalBlindness {
    let c6: HashSet<Edge> = (0u32..6).map(|i| (i, (i + 1) % 6)).collect();
    let two_c3: HashSet<Edge> = vec![(0,1),(1,2),(2,0),(3,4),(4,5),(5,3)].into_iter().collect();
    fn degree_hist(edges: &HashSet<Edge>) -> Vec<(usize, usize)> {
        let mut nodes = HashSet::new();
        let mut indeg: HashMap<Node, usize> = HashMap::new();
        let mut outdeg: HashMap<Node, usize> = HashMap::new();
        for &(u, v) in edges {
            nodes.insert(u); nodes.insert(v);
            *outdeg.entry(u).or_insert(0) += 1;
            *indeg.entry(v).or_insert(0) += 1;
        }
        let mut hist: Vec<_> = nodes.into_iter().map(|n| (*indeg.get(&n).unwrap_or(&0), *outdeg.get(&n).unwrap_or(&0))).collect();
        hist.sort_unstable(); hist
    }
    CanonicalBlindness {
        degree_hist_equal: degree_hist(&c6) == degree_hist(&two_c3),
        c6_ordered_triangles: full_rebuild(&c6).0,
        two_c3_ordered_triangles: full_rebuild(&two_c3).0,
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let input_path = args.next().expect("usage: sot_v4_differential EDGES_TSV OUTPUT_JSON [MAX_EVENTS] [BATCH] [WINDOW]");
    let output_path = args.next().expect("output json");
    let max_events: usize = args.next().map(|x| x.parse().expect("max events")).unwrap_or(30_000);
    let batch_size: usize = args.next().map(|x| x.parse().expect("batch")).unwrap_or(500);
    let window_seconds: i64 = args.next().map(|x| x.parse().expect("window")).unwrap_or(604_800);

    let all_events = read_events(&input_path);
    let process_count = std::cmp::min(max_events, all_events.len());
    let events = all_events[..process_count].to_vec();
    let timer = Instant::now();

    let edge_state: Arc<Mutex<HashMap<Edge, isize>>> = Arc::new(Mutex::new(HashMap::new()));
    let path_state: Arc<Mutex<HashMap<Edge, isize>>> = Arc::new(Mutex::new(HashMap::new()));
    let cycle_state: Arc<Mutex<i64>> = Arc::new(Mutex::new(0));
    let path_abs_delta: Arc<Mutex<i64>> = Arc::new(Mutex::new(0));
    let cycle_abs_delta: Arc<Mutex<i64>> = Arc::new(Mutex::new(0));

    let edge_state_cb = edge_state.clone();
    let path_state_cb = path_state.clone();
    let cycle_state_cb = cycle_state.clone();
    let path_abs_cb = path_abs_delta.clone();
    let cycle_abs_cb = cycle_abs_delta.clone();
    let checkpoints_arc: Arc<Mutex<Vec<Checkpoint>>> = Arc::new(Mutex::new(Vec::new()));
    let checkpoints_out = checkpoints_arc.clone();

    timely::execute(timely::Config::thread(), move |worker| {
        let mut probe = Handle::new();
        let mut input = worker.dataflow(|scope| {
            let (input, raw_edges) = scope.new_collection::<Edge, isize>();
            let edges = raw_edges.distinct();
            edges.clone().consolidate().inspect(move |x| {
                let key = x.0; let diff = *x.2;
                update_map(&mut edge_state_cb.lock().expect("edge state lock"), key, diff);
            });
            let first_by_mid = edges.clone().map(|(u, mid)| (mid, u));
            let two_paths = first_by_mid.join_map(edges.clone(), |_mid, u, w| (*w, *u));
            two_paths.clone().consolidate().inspect(move |x| {
                let key = x.0; let diff = *x.2;
                *path_abs_cb.lock().expect("path delta lock") += (diff as i64).abs();
                update_map(&mut path_state_cb.lock().expect("path state lock"), key, diff);
            });
            let edge_keyed = edges.map(|e| (e, ()));
            let closed = two_paths.map(|p| (p, ())).join_map(edge_keyed, |_key, _path, _edge| ());
            closed.consolidate().inspect(move |x| {
                let diff = *x.2 as i64;
                *cycle_abs_cb.lock().expect("cycle delta lock") += diff.abs();
                *cycle_state_cb.lock().expect("cycle state lock") += diff;
            }).probe_with(&mut probe);
            input
        });

        let mut active_event_counts: HashMap<Edge, usize> = HashMap::new();
        let mut active_edges: HashSet<Edge> = HashSet::new();
        let mut queue: VecDeque<Event> = VecDeque::new();
        let mut relation_inserts = 0usize;
        let mut relation_removes = 0usize;
        let mut last_path_abs = 0i64;
        let mut last_cycle_abs = 0i64;
        let mut epoch = 0usize;

        for (idx, event) in events.iter().copied().enumerate() {
            let cutoff = event.ts - window_seconds;
            while queue.front().map(|e| e.ts < cutoff).unwrap_or(false) {
                let old = queue.pop_front().unwrap();
                let edge = (old.src, old.dst);
                let count = active_event_counts.get_mut(&edge).expect("active event count");
                *count -= 1;
                if *count == 0 {
                    active_event_counts.remove(&edge); active_edges.remove(&edge);
                    input.remove(edge); relation_removes += 1;
                }
            }
            let edge = (event.src, event.dst);
            let count = active_event_counts.entry(edge).or_insert(0);
            if *count == 0 { active_edges.insert(edge); input.insert(edge); relation_inserts += 1; }
            *count += 1; queue.push_back(event);

            if (idx + 1) % batch_size == 0 || idx + 1 == events.len() {
                epoch += 1; input.advance_to(epoch); input.flush();
                while probe.less_than(input.time()) { worker.step(); }
                let dataflow_cycles = *cycle_state.lock().expect("cycle state");
                let edge_keys = edge_state.lock().expect("edge map").len();
                let path_map = path_state.lock().expect("path map");
                let path_keys = path_map.len();
                let path_mult: i64 = path_map.values().map(|x| *x as i64).sum();
                drop(path_map);
                let (rebuild_cycles, rebuild_keys, rebuild_mult, edge_visits, wedge_visits) = full_rebuild(&active_edges);
                let path_abs_now = *path_abs_delta.lock().expect("path abs");
                let cycle_abs_now = *cycle_abs_delta.lock().expect("cycle abs");
                checkpoints_out.lock().expect("checkpoint lock").push(Checkpoint {
                    epoch, events_processed: idx + 1, timestamp: event.ts,
                    active_edges: active_edges.len(), dataflow_edge_keys: edge_keys,
                    two_path_keys: path_keys, two_path_multiplicity: path_mult,
                    dataflow_ordered_cycles: dataflow_cycles, rebuild_ordered_cycles: rebuild_cycles,
                    rebuild_two_path_keys: rebuild_keys, rebuild_two_path_multiplicity: rebuild_mult,
                    exact_match: dataflow_cycles == rebuild_cycles && edge_keys == active_edges.len()
                        && path_keys == rebuild_keys && path_mult == rebuild_mult,
                    relation_inserts, relation_removes,
                    two_path_abs_delta: path_abs_now - last_path_abs,
                    cycle_abs_delta: cycle_abs_now - last_cycle_abs,
                    full_rebuild_edge_visits: edge_visits, full_rebuild_wedge_visits: wedge_visits,
                });
                last_path_abs = path_abs_now; last_cycle_abs = cycle_abs_now;
            }
        }
        input.close(); while worker.step() {}
    }).expect("timely execution");

    let checkpoints = Arc::try_unwrap(checkpoints_arc).expect("checkpoint arc").into_inner().expect("checkpoint mutex");
    let output = Output {
        schema: "sot-v4-differential-1.0", differential_dataflow_version: "0.24.0", timely_version: "0.30",
        input_events_available: all_events.len(), input_events_processed: events.len(), window_seconds, batch_size,
        all_exact: checkpoints.iter().all(|x| x.exact_match),
        total_relation_inserts: checkpoints.last().map(|x| x.relation_inserts).unwrap_or(0),
        total_relation_removes: checkpoints.last().map(|x| x.relation_removes).unwrap_or(0),
        total_two_path_abs_delta: checkpoints.iter().map(|x| x.two_path_abs_delta).sum(),
        total_cycle_abs_delta: checkpoints.iter().map(|x| x.cycle_abs_delta).sum(),
        total_full_rebuild_edge_visits: checkpoints.iter().map(|x| x.full_rebuild_edge_visits).sum(),
        total_full_rebuild_wedge_visits: checkpoints.iter().map(|x| x.full_rebuild_wedge_visits).sum(),
        checkpoints, wall_seconds: timer.elapsed().as_secs_f64(), canonical_blindness: canonical_blindness(),
    };
    serde_json::to_writer_pretty(File::create(output_path).expect("create output"), &output).expect("write output");
}
