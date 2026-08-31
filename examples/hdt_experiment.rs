//! Phase H1 of `docs/scaling-info-to-millions.md`: does HDT beat `Graph`?
//!
//! Measures the two metadata representations against each other on the same
//! container, reporting time, peak RSS, and steady-state resident size for
//! each, plus the query patterns `build_objects` and `order_objects` depend on.
//!
//! **This changes nothing.** It is an `examples/` binary behind the
//! `hdt-experiment` feature; the library and CLI never reach it, and `Graph`
//! remains the only representation `aff4tools` uses. Its output is evidence for
//! deciding whether phase H2 — an interchangeable backend — is worth building.
//!
//! ```sh
//! cargo run --release --features hdt-experiment --example hdt_experiment -- <PATH>
//! ```
//!
//! # What is compared
//!
//! Both paths start from the same bytes: `information.turtle`, read out of the
//! container once. Neither writes anything — the HDT is built in memory via
//! `Hdt::from_triples`, so no cache file exists to go stale (see the plan's
//! "Caching is not required").
//!
//! # Reading the numbers
//!
//! **Steady state** is what matters for the scaling question: how much memory
//! the representation occupies once built, since that is what bounds the object
//! count a machine can hold. **Peak RSS** is the transient high-water mark
//! during construction, which is higher for both paths and is a separate
//! (smaller) problem.

use std::time::Instant;

use aff4tools::Locus;
use aff4tools::rdf::Graph;
use aff4tools::zip::{Volume as _, ZipVolume};

/// Peak RSS is **not** measured in-process.
///
/// Doing so would need `getrusage` through `libc` and an `unsafe` block, and
/// `src/lib.rs` sets `#![deny(unsafe_code)]` — a measurement harness is not a
/// good enough reason for the project's second unsafe exception (the first,
/// `block_device_size`, was owner-approved for a capability with no safe
/// alternative). Run it under `/usr/bin/time -l` (macOS) or `-v` (Linux)
/// instead; the wrapper reports the same high-water mark from outside.
///
/// What *is* measured in-process is the HDT's own `size_in_bytes`, which is
/// the steady-state figure the scaling question turns on.
fn mib(bytes: u64) -> String {
    format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let Some(path) = args.get(1) else {
        eprintln!("usage: hdt_experiment <container.aff4> [graph|hdt|both]");
        eprintln!();
        eprintln!("Run each mode under a memory wrapper to get its peak RSS in");
        eprintln!("isolation; `both` builds them in one process, so its peak");
        eprintln!("describes whichever representation is larger, not each:");
        eprintln!("  /usr/bin/time -l ... --example hdt_experiment -- C.aff4 graph");
        eprintln!("  /usr/bin/time -l ... --example hdt_experiment -- C.aff4 hdt");
        std::process::exit(2);
    };
    let mode = args.get(2).map_or("both", String::as_str);
    let want_graph = matches!(mode, "graph" | "both");
    // Read only under `hdt-experiment`; the default build never branches on it.
    #[cfg_attr(not(feature = "hdt-experiment"), allow(unused_variables))]
    let want_hdt = matches!(mode, "hdt" | "both");

    // The metadata segment, read once and shared by both paths, so neither is
    // charged for I/O the other avoided.
    let mut volume = ZipVolume::open(path).expect("open container");
    let turtle = volume
        .read_segment("information.turtle")
        .expect("read information.turtle");
    let locus = Locus::new(std::path::PathBuf::from(&path));

    println!("Container : {path}");
    println!("Turtle    : {} uncompressed", mib(turtle.len() as u64));
    println!();

    // --- Path A: the current representation -------------------------------
    // The probe subject is needed by both paths, so it is derived from a graph
    // parse even in `hdt` mode — timed separately and reported only when the
    // graph is what is being measured.
    let t = Instant::now();
    let graph = Graph::parse(&turtle, &locus).expect("parse turtle");
    let graph_time = t.elapsed();
    let triples = graph.len();
    let subjects = graph.subjects().len();

    // The two access patterns the report path actually makes.
    let probe = graph
        .subjects()
        .get(subjects / 2)
        .cloned()
        .unwrap_or_default();
    let t = Instant::now();
    let graph_lookup = graph.statements_for(&probe).len();
    let graph_lookup_time = t.elapsed();

    let file_image = "http://aff4.org/Schema#FileImage";
    let t = Instant::now();
    let graph_scan = graph.subjects_of_type(file_image).len();
    let graph_scan_time = t.elapsed();

    if want_graph {
        println!("Graph (current)");
        println!("  build          : {graph_time:?}");
        println!("  triples        : {triples}");
        println!("  subjects       : {subjects}");
        println!("  subject lookup : {graph_lookup_time:?} ({graph_lookup} triples)");
        println!("  type scan      : {graph_scan_time:?} ({graph_scan} subjects)");
        println!();
    }

    // Released before building the HDT so the two peaks do not overlap and
    // each figure describes one representation rather than both at once.
    drop(graph);

    // --- Path B: HDT ------------------------------------------------------
    #[cfg(feature = "hdt-experiment")]
    if want_hdt {
        // Turtle -> triples in HDT's dictionary string format: IRIs without
        // angle brackets, literals keeping their quotes and datatype suffix.
        let t = Instant::now();
        let mut rows: Vec<[String; 3]> = Vec::new();
        let parser = oxttl::TurtleParser::new().for_reader(&turtle[..]);
        for triple in parser {
            let triple = triple.expect("valid turtle");
            rows.push([
                unbracket(triple.subject.to_string()),
                unbracket(triple.predicate.to_string()),
                unbracket(triple.object.to_string()),
            ]);
        }
        let convert_time = t.elapsed();
        let row_count = rows.len();

        let t = Instant::now();
        let hdt = hdt::Hdt::from_triples(rows, "aff4://container").expect("build hdt");
        let build_time = t.elapsed();
        let hdt_size = hdt.size_in_bytes() as u64;

        let t = Instant::now();
        let hdt_lookup = hdt.triples_with_pattern(Some(&probe), None, None).count();
        let hdt_lookup_time = t.elapsed();

        let rdf_type = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
        let t = Instant::now();
        let hdt_scan = hdt
            .triples_with_pattern(None, Some(rdf_type), Some(file_image))
            .count();
        let hdt_scan_time = t.elapsed();

        println!("HDT (experiment)");
        println!("  turtle->triples: {convert_time:?} ({row_count} triples)");
        println!("  build          : {build_time:?}");
        println!("  total          : {:?}", convert_time + build_time);
        println!("  steady state   : {}", mib(hdt_size));
        println!("  subject lookup : {hdt_lookup_time:?} ({hdt_lookup} triples)");
        println!("  type scan      : {hdt_scan_time:?} ({hdt_scan} subjects)");
        println!();

        // Equality of what each representation found. A representation that is
        // smaller because it dropped triples would be worthless, so this is the
        // check that makes the size figures mean anything.
        println!();
        println!("Agreement");
        println!(
            "  triples        : graph {triples}, hdt {row_count}{}",
            if triples == row_count {
                ""
            } else {
                "  ** MISMATCH **"
            }
        );
        println!(
            "  subject lookup : graph {graph_lookup}, hdt {hdt_lookup}{}",
            if graph_lookup == hdt_lookup {
                ""
            } else {
                "  ** MISMATCH **"
            }
        );
        println!(
            "  type scan      : graph {graph_scan}, hdt {hdt_scan}{}",
            if graph_scan == hdt_scan {
                ""
            } else {
                "  ** MISMATCH **"
            }
        );
    }

    #[cfg(not(feature = "hdt-experiment"))]
    println!("(rebuild with --features hdt-experiment for the HDT half)");
}

/// Strip the angle brackets `oxrdf`'s `Display` puts around an IRI.
///
/// HDT's dictionary stores IRIs bare and literals with their quotes intact, so
/// only the bracketed form is unwrapped.
#[cfg(feature = "hdt-experiment")]
fn unbracket(term: String) -> String {
    if term.starts_with('<') && term.ends_with('>') {
        term[1..term.len() - 1].to_owned()
    } else {
        term
    }
}
