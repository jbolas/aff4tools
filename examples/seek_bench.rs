//! This is an `examples/` binary that reads a container
//! and prints numbers; the library and CLI never reach it. Its output decides
//! whether `Image::read_at` needs a cache of resident bevies, which the plan
//! forbids building before this measurement exists.
//!
//! ```sh
//! cargo run --release --example seek_bench -- <PATH> [SIBLING...]
//! ```
//!
//! # What's measured
//!
//! Four access patterns over the same image, each issuing the same number of
//! 4 KiB reads:
//!
//! - **sequential** — ascending offsets, the pattern `verify` already has.
//! - **random** — uniformly distributed offsets.
//! - **alternating** — offsets that ping-pong between two widely separated
//!   regions, the pattern most likely to thrash a single cached bevy.
//! - **backward** — descending offsets, which never reuse a bevy under a
//!   forward-only cache.
//!
//! The concern is that `SetStreams` holds **one** resident bevy and hands it
//! between readers. A client alternating between two stored streams would then
//! decompress a bevy per read. Whether that happens depends on how much of the
//! image is stored rather than described: `Base-Linear.aff4` is 98.5%
//! described, so most reads terminate in a filler with no I/O at all.

use std::path::PathBuf;
use std::time::Instant;

use aff4tools::image::Image;
use aff4tools::model::ObjectRole;
use aff4tools::zip_volume_set::{VolumeOrigin, open_with_graph};
use aff4tools::{Container, Locus};

/// One 4 KiB read, the size a filesystem client typically issues.
const READ_LEN: usize = 4096;
/// Reads per pattern. Enough to be stable, small enough to stay quick.
const READS: usize = 2000;

/// A deterministic generator, so runs are comparable.
///
/// Not `rand`: this is a measurement harness, and reproducibility matters more
/// than distribution quality.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 16
    }
}

fn main() {
    let mut args = std::env::args_os().skip(1).map(PathBuf::from);
    let Some(path) = args.next() else {
        eprintln!("usage: seek_bench <PATH> [SIBLING...]");
        std::process::exit(2);
    };
    let siblings: Vec<PathBuf> = args.collect();

    let locus = Locus::new(&path);
    let mut container = match Container::open(&path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("opening {}: {e}", path.display());
            std::process::exit(1);
        }
    };
    for sibling in &siblings {
        match open_with_graph(sibling) {
            Ok((volume, graph)) => {
                container.add_volume(volume, graph, VolumeOrigin::Named);
            }
            Err(e) => {
                eprintln!("opening sibling {}: {e}", sibling.display());
                std::process::exit(1);
            }
        }
    }

    let lexicon = container.lexicon();
    let summary = match container.summarize() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("summarising: {e}");
            std::process::exit(1);
        }
    };
    let Some(image_arn) = summary
        .images()
        .iter()
        .find(|o| o.role == ObjectRole::DiskImage)
        .map(|o| o.arn.clone())
    else {
        eprintln!("no DiskImage in {}", path.display());
        std::process::exit(1);
    };

    let image = match Image::open_in_set(&image_arn, container.volumes_mut(), lexicon, &locus) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("opening image: {e}");
            std::process::exit(1);
        }
    };

    let size = image.size();
    let span = size.saturating_sub(READ_LEN as u64);
    println!("image {image_arn}");
    println!("  size          {size} bytes");
    println!("  volumes       {}", 1 + siblings.len());

    // How much of the address space is stored rather than described. A read
    // landing in a described run costs no I/O, so this bounds how much any
    // cache could possibly matter.
    let map = image.map();
    let stored: u64 = map
        .entries()
        .iter()
        .filter(|e| {
            map.target_of(e)
                .is_some_and(aff4tools::map::Target::is_stored)
        })
        .map(|e| e.length)
        .sum();
    let stored_pct = if size == 0 {
        0.0
    } else {
        (stored as f64 / size as f64) * 100.0
    };
    println!("  stored        {stored} bytes ({stored_pct:.2}% of the image)");
    println!("  entries       {}", map.entries().len());
    println!(
        "  stored targets {}",
        map.targets().iter().filter(|t| t.is_stored()).count()
    );
    println!();

    /// Turns a read index into an offset, given the span and a generator.
    type Pattern = fn(usize, u64, &mut Lcg) -> u64;

    let patterns: [(&str, Pattern); 4] = [
        ("sequential", |i, span, _| {
            if span == 0 {
                0
            } else {
                (i as u64 * READ_LEN as u64) % span
            }
        }),
        (
            "random",
            |_, span, rng| {
                if span == 0 { 0 } else { rng.next() % span }
            },
        ),
        // Ping-pong between the first and second half: the pattern that would
        // thrash a single resident bevy hardest.
        ("alternating", |i, span, _| {
            if span == 0 {
                return 0;
            }
            let step = (i as u64 / 2) * READ_LEN as u64;
            if i % 2 == 0 {
                step % (span / 2).max(1)
            } else {
                (span / 2) + step % (span / 2).max(1)
            }
        }),
        ("backward", |i, span, _| {
            span.saturating_sub((i as u64 + 1) * READ_LEN as u64) % span.max(1)
        }),
    ];

    println!(
        "{:<12} {:>10} {:>14} {:>12}",
        "pattern", "reads", "elapsed", "MiB/s"
    );
    for (name, offset_of) in patterns {
        let mut rng = Lcg(0x2026_0824);
        let mut buf = vec![0u8; READ_LEN];
        let mut delivered: u64 = 0;

        let start = Instant::now();
        for i in 0..READS {
            let offset = offset_of(i, span, &mut rng);
            match image.read_at_in_set(container.volumes_mut(), offset, &mut buf, &locus) {
                Ok(n) => delivered += n as u64,
                Err(e) => {
                    eprintln!("read at {offset} failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        let elapsed = start.elapsed().as_secs_f64();
        let mib = delivered as f64 / 1_048_576.0;
        println!(
            "{name:<12} {READS:>10} {elapsed:>13.3}s {:>12.1}",
            if elapsed > 0.0 { mib / elapsed } else { 0.0 }
        );
    }

    // The patterns above sample the whole address space, where a mostly
    // described image lets most reads terminate in a filler with no I/O. That
    // flatters any cache. Re-run confined to stored regions, which is the
    // worst case a cache would have to survive.
    let stored_entries: Vec<_> = map
        .entries()
        .iter()
        .filter(|e| {
            map.target_of(e)
                .is_some_and(aff4tools::map::Target::is_stored)
        })
        .filter(|e| e.length >= READ_LEN as u64)
        .copied()
        .collect();

    if stored_entries.len() >= 2 {
        println!();
        println!(
            "Confined to {} stored runs (the worst case for a bevy cache):",
            stored_entries.len()
        );
        println!(
            "{:<12} {:>10} {:>14} {:>12}",
            "pattern", "reads", "elapsed", "MiB/s"
        );

        for name in ["sequential", "alternating", "random"] {
            let mut rng = Lcg(0x2026_0824);
            let mut buf = vec![0u8; READ_LEN];
            let mut delivered: u64 = 0;
            let start = Instant::now();

            for i in 0..READS {
                // Pick a stored run, then an offset inside it.
                let pick = match name {
                    // Walk the runs in order.
                    "sequential" => i % stored_entries.len(),
                    // Ping-pong between the first and last run, which are the
                    // most likely to live in different streams or bevies.
                    "alternating" => {
                        if i % 2 == 0 {
                            0
                        } else {
                            stored_entries.len() - 1
                        }
                    }
                    _ => (rng.next() as usize) % stored_entries.len(),
                };
                let entry = stored_entries[pick];
                let room = entry.length - READ_LEN as u64;
                let within = if room == 0 { 0 } else { rng.next() % room };
                let offset = entry.offset + within;

                match image.read_at_in_set(container.volumes_mut(), offset, &mut buf, &locus) {
                    Ok(n) => delivered += n as u64,
                    Err(e) => {
                        eprintln!("stored read at {offset} failed: {e}");
                        std::process::exit(1);
                    }
                }
            }
            let elapsed = start.elapsed().as_secs_f64();
            let mib = delivered as f64 / 1_048_576.0;
            println!(
                "{name:<12} {READS:>10} {elapsed:>13.3}s {:>12.1}",
                if elapsed > 0.0 { mib / elapsed } else { 0.0 }
            );
        }
    }

    // The same worst case through `reader_in_set`, which keeps the bevy
    // resident across reads instead of rebuilding the source per call.
    if stored_entries.len() >= 2 {
        println!();
        println!("The same stored runs through reader_in_set (residency kept):");
        println!(
            "{:<12} {:>10} {:>14} {:>12}",
            "pattern", "reads", "elapsed", "MiB/s"
        );

        for name in ["sequential", "alternating", "random"] {
            let mut rng = Lcg(0x2026_0824);
            let mut buf = vec![0u8; READ_LEN];
            let mut delivered: u64 = 0;
            let mut reader = image.reader_in_set(container.volumes_mut());
            let start = Instant::now();

            for i in 0..READS {
                let pick = match name {
                    "sequential" => i % stored_entries.len(),
                    "alternating" => {
                        if i % 2 == 0 {
                            0
                        } else {
                            stored_entries.len() - 1
                        }
                    }
                    _ => (rng.next() as usize) % stored_entries.len(),
                };
                let entry = stored_entries[pick];
                let room = entry.length - READ_LEN as u64;
                let within = if room == 0 { 0 } else { rng.next() % room };
                let offset = entry.offset + within;

                match reader.read_at(offset, &mut buf, &locus) {
                    Ok(n) => delivered += n as u64,
                    Err(e) => {
                        eprintln!("stored read at {offset} failed: {e}");
                        std::process::exit(1);
                    }
                }
            }
            let elapsed = start.elapsed().as_secs_f64();
            let mib = delivered as f64 / 1_048_576.0;
            println!(
                "{name:<12} {READS:>10} {elapsed:>13.3}s {:>12.1}",
                if elapsed > 0.0 { mib / elapsed } else { 0.0 }
            );
        }
    }

    println!();
    println!("Compare the patterns. If `alternating` and `backward` are close to");
    println!("`sequential`, one resident bevy is enough and no cache is needed. If");
    println!("they collapse, a bounded LRU of bevies is warranted — see the plan's");
    println!("Task A4 before building one.");
}
