//! The parallel read path, against a container with enough bevies to stress it.
//!
//! The reference corpus tops out at **one bevy per stream**, so its reorder
//! window can never fill. Two deadlocks in `src/parallel.rs` reached a real
//! 236 GB container with the whole suite green, because nothing in it could
//! reach the state they needed.
//!
//! The fixture here is built in-process: ten thousand bevies of 512 bytes.
//! Small bevies are the point — they read almost instantly, so readers outrun
//! the consumer and the window saturates. Instrumenting the window-full
//! condition measured **80 hits in 0.4 seconds** here against **none in 60
//! seconds** of the real container, whose 32 MiB bevies keep the pipeline
//! I/O-starved instead. This is the cheap way to reach the state the deadlocks
//! lived in.
//!
//! What this file does *not* cover: throughput, the CPU budget, or the reader
//! governor, which needs seconds of sustained reading before it probes. Those
//! need a fixture with realistically sized bevies and do not belong in a suite
//! that has to stay fast.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write as _;
use std::path::PathBuf;

use aff4tools::parallel::{ThreadPlan, read_all_parallel};
use aff4tools::stream::ImageStream;
use aff4tools::{Container, Locus, ObjectRole};

const VOLUME: &str = "aff4://11111111-2222-3333-4444-555555555555";
const STREAM: &str = "aff4://99999999-8888-7777-6666-555555555555";
const MAP: &str = "aff4://12121212-3434-5656-7878-909090909090";
const IMAGE: &str = "aff4://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

/// Bevies in the fixture.
///
/// Enough that the consumer waits on a bevy still behind others many times
/// over — the window holds eighteen, so this cycles it hundreds of times.
const BEVIES: u64 = 10_000;

/// Bytes per chunk, and per bevy: one chunk each.
///
/// Deliberately tiny. A bevy that reads instantly is what lets readers run
/// ahead and fill the window, which is the condition under test.
const CHUNK: usize = 512;

/// The ARN as a ZIP member path prefix, per v1.0a §5's URI→path mapping.
fn escaped(arn: &str) -> String {
    arn.replace(':', "%3A").replace('/', "%2F")
}

/// Deterministic synthetic content for one chunk. Lorem ipsum, never evidence.
fn chunk_bytes(index: u64) -> Vec<u8> {
    const LOREM: &[u8] = b"Lorem ipsum dolor sit amet, consectetur adipiscing \
        elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. ";
    let mut body = format!("[chunk {index:08}] ").into_bytes();
    while body.len() < CHUNK {
        body.extend_from_slice(LOREM);
    }
    body.truncate(CHUNK);
    body
}

/// Build the fixture: a valid AFF4 volume with [`BEVIES`] bevies.
fn fixture() -> (tempfile::TempDir, PathBuf) {
    let bevies: Vec<Vec<Vec<u8>>> = (0..BEVIES).map(|b| vec![chunk_bytes(b)]).collect();
    volume("many-bevies.aff4", &bevies, 1, CHUNK as u64 * BEVIES, None)
}

/// A valid AFF4 volume whose one stored stream holds `bevies`, each a list of
/// stored chunks, declaring `size` bytes in `CHUNK`-byte chunks. `image_md5`,
/// when given, is recorded on the image as a whole-image digest.
///
/// The one sanctioned use of a ZIP writer in this project — it creates a fresh
/// throwaway archive to read back, and never touches evidence.
#[allow(clippy::disallowed_types, clippy::disallowed_methods)]
fn volume(
    name: &str,
    bevies: &[Vec<Vec<u8>>],
    chunks_in_segment: usize,
    size: u64,
    image_md5: Option<&str>,
) -> (tempfile::TempDir, PathBuf) {
    let image_hash = image_md5
        .map(|md5| format!("\x20   aff4:hash       \"{md5}\"^^aff4:MD5 ;\n"))
        .unwrap_or_default();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(name);
    let file = std::fs::File::create(&path).unwrap();
    let mut writer = zip::ZipWriter::new(file);
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);

    let stream_dir = escaped(STREAM);
    let map_dir = escaped(MAP);

    writer.start_file("container.description", options).unwrap();
    writer.write_all(VOLUME.as_bytes()).unwrap();
    writer.start_file("version.txt", options).unwrap();
    writer
        .write_all(b"major=1\nminor=0\ntool=aff4tools-test\n")
        .unwrap();

    for (bevy, chunks) in bevies.iter().enumerate() {
        // Chunks back to back; one index entry per chunk: <QI> offset, length.
        let mut data = Vec::new();
        let mut index = Vec::with_capacity(12 * chunks.len());
        for chunk in chunks {
            index.extend_from_slice(&(data.len() as u64).to_le_bytes());
            index.extend_from_slice(&(chunk.len() as u32).to_le_bytes());
            data.extend_from_slice(chunk);
        }
        writer
            .start_file(format!("{stream_dir}/{bevy:08}"), options)
            .unwrap();
        writer.write_all(&data).unwrap();
        writer
            .start_file(format!("{stream_dir}/{bevy:08}.index"), options)
            .unwrap();
        writer.write_all(&index).unwrap();
    }

    // A map covering the whole image: <QQQI> offset, length, target offset, id.
    let mut map = Vec::with_capacity(28);
    map.extend_from_slice(&0u64.to_le_bytes());
    map.extend_from_slice(&size.to_le_bytes());
    map.extend_from_slice(&0u64.to_le_bytes());
    map.extend_from_slice(&0u32.to_le_bytes());
    writer
        .start_file(format!("{map_dir}/map"), options)
        .unwrap();
    writer.write_all(&map).unwrap();
    writer
        .start_file(format!("{map_dir}/idx"), options)
        .unwrap();
    writer.write_all(format!("{STREAM}\n").as_bytes()).unwrap();

    let turtle = format!(
        "@prefix aff4: <http://aff4.org/Schema#> .\n\
         @prefix xsd:  <http://www.w3.org/2001/XMLSchema#> .\n\n\
         <{STREAM}>\n\
         \x20   a                       aff4:ImageStream ;\n\
         \x20   aff4:chunkSize          \"{CHUNK}\"^^xsd:int ;\n\
         \x20   aff4:chunksInSegment    \"{chunks_in_segment}\"^^xsd:int ;\n\
         \x20   aff4:compressionMethod  <http://aff4.org/Schema#compression/stored> ;\n\
         \x20   aff4:size               \"{size}\"^^xsd:long ;\n\
         \x20   aff4:stored             <{VOLUME}> ;\n\
         \x20   aff4:target             <{MAP}> .\n\n\
         <{MAP}>\n\
         \x20   a                    aff4:Map ;\n\
         \x20   aff4:dependentStream <{STREAM}> ;\n\
         \x20   aff4:size            \"{size}\"^^xsd:long ;\n\
         \x20   aff4:stored          <{VOLUME}> ;\n\
         \x20   aff4:target          <{IMAGE}> .\n\n\
         <{IMAGE}>\n\
         \x20   a               aff4:Image , aff4:ContiguousImage ;\n\
         \x20   aff4:dataStream <{MAP}> ;\n\
         {image_hash}\
         \x20   aff4:size       \"{size}\"^^xsd:long ;\n\
         \x20   aff4:stored     <{VOLUME}> .\n\n\
         <{VOLUME}>\n\
         \x20   a             aff4:ZipVolume ;\n\
         \x20   aff4:contains <{IMAGE}> , <{STREAM}> , <{MAP}> ;\n\
         \x20   aff4:stored   \"{name}\" .\n"
    );
    writer.start_file("information.turtle", options).unwrap();
    writer.write_all(turtle.as_bytes()).unwrap();
    writer.finish().unwrap();

    (dir, path)
}

/// Open the fixture's image stream.
fn open_stream(path: &PathBuf) -> (Container, ImageStream, Locus) {
    let mut container = Container::open(path).unwrap();
    let graph = container.graph().unwrap();
    let lexicon = container.lexicon();
    let locus = Locus::new(path);
    let summary = container.summarize().unwrap();
    let arn = summary
        .objects
        .iter()
        .find(|o| matches!(o.role, ObjectRole::ImageStream))
        .map(|o| o.arn.clone())
        .expect("the fixture declares an image stream");
    let stream = ImageStream::open(&arn, &graph, lexicon, &locus).unwrap();
    (container, stream, locus)
}

/// The parallel reader must deliver exactly what the serial reader delivers,
/// on a container whose reorder window actually fills.
///
/// Compares the *slice sequence*, not the final digest. A digest can match
/// while boundaries differ, and a reordering that happens to compensate would
/// be invisible at the digest but would break the block-hash cut, which is
/// defined on chunk boundaries.
#[test]
fn ten_thousand_bevies_deliver_in_order_on_every_plan() {
    let (_dir, path) = fixture();
    let (mut container, stream, locus) = open_stream(&path);
    assert_eq!(stream.bevy_count(), BEVIES);

    let mut serial: Vec<Vec<u8>> = Vec::new();
    let mut serial_bevies: Vec<u64> = Vec::new();
    stream
        .read_all_observed(
            container.volume_mut(),
            aff4tools::arn::NameMapping::Escaped,
            &mut |bytes| {
                serial.push(bytes.to_vec());
                Ok(())
            },
            &mut |n| serial_bevies.push(n),
            &locus,
        )
        .unwrap();
    assert_eq!(
        serial.len() as u64,
        BEVIES,
        "one slice per single-chunk bevy"
    );

    // Lopsided plans included: a reorder-window bug shows most readily when
    // readers and workers are mismatched.
    for (readers, workers) in [(1, 1), (2, 6), (4, 1), (1, 4), (3, 5), (8, 2)] {
        let plan = ThreadPlan {
            readers,
            workers,
            digesters: 0,
            available: readers + workers,
            budget: readers + workers,
        };

        let mut parallel: Vec<Vec<u8>> = Vec::new();
        let mut parallel_bevies: Vec<u64> = Vec::new();
        read_all_parallel(
            &stream,
            container.volume_mut(),
            aff4tools::arn::NameMapping::Escaped,
            plan,
            &mut |bytes| {
                parallel.push(bytes.to_vec());
                Ok(())
            },
            &mut |n| parallel_bevies.push(n),
            &locus,
        )
        .unwrap_or_else(|e| panic!("parallel read at {plan:?}: {e}"));

        assert!(
            parallel == serial,
            "slice sequence differs from serial at {plan:?}"
        );
        assert_eq!(
            parallel_bevies, serial_bevies,
            "bevy completion sequence differs at {plan:?}"
        );
    }
}

/// The pipeline must finish rather than deadlock when readers outrun the
/// consumer.
///
/// This is the regression test for two deadlocks that a full corpus run could
/// not reach. Both left every thread parked with the run at 0% CPU, so the
/// failure mode is a hang: the test asserts completion under a deadline rather
/// than asserting on any value.
#[test]
fn a_saturated_reorder_window_does_not_deadlock() {
    let (_dir, path) = fixture();
    let (mut container, stream, locus) = open_stream(&path);

    // Many readers against few workers is the shape that fills the window
    // fastest: bevies arrive far quicker than they are consumed.
    let plan = ThreadPlan {
        readers: 8,
        workers: 2,
        digesters: 0,
        available: 10,
        budget: 10,
    };

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let mut delivered: u64 = 0;
            let result = read_all_parallel(
                &stream,
                container.volume_mut(),
                aff4tools::arn::NameMapping::Escaped,
                plan,
                &mut |bytes| {
                    delivered += bytes.len() as u64;
                    Ok(())
                },
                &mut |_| {},
                &locus,
            );
            let _ = tx.send(result.map(|()| delivered));
        });

        // Generous: the work itself is well under a second, so anything near
        // this is a hang rather than a slow machine.
        let outcome = rx
            .recv_timeout(std::time::Duration::from_secs(60))
            .expect("the pipeline deadlocked: no result within 60s");
        assert_eq!(
            outcome.unwrap(),
            CHUNK as u64 * BEVIES,
            "every byte must be delivered exactly once"
        );
    });
}

/// A run that ends early must not hang, and must report the shortfall.
///
/// The consumer stopping before the stream ends leaves readers mid-flight and
/// workers holding bevies nobody will collect. Every one of them has to notice
/// and exit, or the process never returns.
#[test]
fn an_early_stop_unwinds_every_thread() {
    let (_dir, path) = fixture();
    let (mut container, stream, locus) = open_stream(&path);

    let plan = ThreadPlan {
        readers: 4,
        workers: 4,
        digesters: 0,
        available: 8,
        budget: 8,
    };

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let mut seen = 0u64;
            let result = read_all_parallel(
                &stream,
                container.volume_mut(),
                aff4tools::arn::NameMapping::Escaped,
                plan,
                &mut |_| {
                    seen += 1;
                    if seen > 50 {
                        // Abandon the read a long way from the end.
                        return Err(aff4tools::Error::malformed(
                            Locus::new("test"),
                            "stopping early".to_owned(),
                        ));
                    }
                    Ok(())
                },
                &mut |_| {},
                &locus,
            );
            let _ = tx.send(result.is_err());
        });

        let errored = rx
            .recv_timeout(std::time::Duration::from_secs(60))
            .expect("an abandoned read deadlocked: no result within 60s");
        assert!(errored, "abandoning the read must surface as an error");
    });
}

/// A chunk that decompresses short of `aff4:chunkSize` before the end of its
/// stream is refused, by the serial and the parallel reader alike.
///
/// The fixture is the case that would otherwise pass unnoticed: chunk 2 is 12
/// bytes short and an extra 12-byte chunk at the end makes the total match the
/// declared size, so the length check alone is satisfied while every byte
/// after chunk 2 sits 12 bytes early.
#[test]
fn a_short_chunk_before_the_end_of_a_stream_is_malformed() {
    let full = |n: u64| chunk_bytes(n);
    let mut short = chunk_bytes(2);
    short.truncate(CHUNK - 12);
    let bevies = vec![
        vec![full(0), full(1)],
        vec![short, full(3)],
        vec![full(4), full(5)],
        vec![full(6), vec![0x55; 12]],
    ];
    // Seven chunks' worth: the last bevy declares one chunk and lists two.
    let (_dir, path) = volume("short-chunk.aff4", &bevies, 2, 7 * CHUNK as u64, None);
    let (mut container, stream, locus) = open_stream(&path);

    let err = stream
        .read_all_observed(
            container.volume_mut(),
            aff4tools::arn::NameMapping::Escaped,
            &mut |_| Ok(()),
            &mut |_| {},
            &locus,
        )
        .unwrap_err();
    assert!(err.is_integrity_finding(), "serial: {err}");
    assert!(err.to_string().contains("chunk 2 "), "serial: {err}");

    for (readers, workers) in [(1, 1), (2, 3)] {
        let plan = ThreadPlan {
            readers,
            workers,
            digesters: 0,
            available: readers + workers,
            budget: readers + workers,
        };
        let err = read_all_parallel(
            &stream,
            container.volume_mut(),
            aff4tools::arn::NameMapping::Escaped,
            plan,
            &mut |_| Ok(()),
            &mut |_| {},
            &locus,
        )
        .unwrap_err();
        assert!(err.is_integrity_finding(), "{plan:?}: {err}");
        assert!(err.to_string().contains("chunk 2 "), "{plan:?}: {err}");
    }
}

/// A short final chunk is the one v1.0a §3.2 allows, and still reads.
#[test]
fn a_short_final_chunk_is_accepted() {
    let mut last = chunk_bytes(2);
    last.truncate(100);
    let bevies = vec![vec![chunk_bytes(0), chunk_bytes(1)], vec![last.clone()]];
    let size = 2 * CHUNK as u64 + 100;
    let (_dir, path) = volume("short-final.aff4", &bevies, 2, size, None);
    let (mut container, stream, locus) = open_stream(&path);

    let mut out = Vec::new();
    stream
        .read_all_observed(
            container.volume_mut(),
            aff4tools::arn::NameMapping::Escaped,
            &mut |b| {
                out.extend_from_slice(b);
                Ok(())
            },
            &mut |_| {},
            &locus,
        )
        .unwrap();
    assert_eq!(out.len() as u64, size);
    assert_eq!(&out[2 * CHUNK..], &last[..]);
}

/// `verify` recomputes a whole-image digest through the parallel read path,
/// and a damaged bevy is caught on that pass.
///
/// `AFF4TOOLS_THREADS` forces a parallel plan whatever the host, and 64 bevies
/// are well past the size below which a stream is read serially.
#[test]
fn verify_recomputes_a_whole_image_digest_in_parallel_and_catches_damage() {
    use md5::{Digest as _, Md5};

    let bevies: Vec<Vec<Vec<u8>>> = (0..64u64)
        .map(|b| vec![chunk_bytes(2 * b), chunk_bytes(2 * b + 1)])
        .collect();
    let image: Vec<u8> = bevies.iter().flatten().flatten().copied().collect();
    let md5 = format!("{:x}", Md5::digest(&image));
    let (dir, path) = volume(
        "image-digest.aff4",
        &bevies,
        2,
        image.len() as u64,
        Some(&md5),
    );

    let verify = |path: &std::path::Path| {
        std::process::Command::new(env!("CARGO_BIN_EXE_aff4tools"))
            .env("AFF4TOOLS_THREADS", "4")
            .args(["verify", "--format", "json"])
            .arg(path)
            .output()
            .unwrap()
    };
    let whole_image = |out: &std::process::Output| -> Vec<serde_json::Value> {
        let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        value["checks"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|c| c["coverage"] == "WholeImage")
            .cloned()
            .collect()
    };

    let clean = verify(&path);
    assert!(clean.status.success(), "{clean:?}");
    let checks = whole_image(&clean);
    assert_eq!(checks.len(), 1, "{checks:#?}");
    assert_eq!(checks[0]["outcome"], "Match", "{checks:#?}");

    // Flip one byte inside chunk 77's data, in a copy; the fixture is unchanged.
    let mut bytes = std::fs::read(&path).unwrap();
    let marker = b"[chunk 00000077] ";
    let at = bytes
        .windows(marker.len())
        .position(|w| w == marker)
        .expect("stored chunk data appears verbatim in the container");
    bytes[at + marker.len() + 3] ^= 0x01;
    let damaged = dir.path().join("damaged.aff4");
    #[allow(clippy::disallowed_methods)]
    std::fs::write(&damaged, &bytes).unwrap();

    let result = verify(&damaged);
    assert!(
        !result.status.success(),
        "a damaged bevy verified clean: {}",
        String::from_utf8_lossy(&result.stdout)
    );
    assert!(
        whole_image(&result).iter().all(|c| c["outcome"] != "Match"),
        "the whole-image digest must not match over damaged data"
    );
}
