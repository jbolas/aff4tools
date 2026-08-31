//! The HDT backend must answer exactly as `Graph` does.
//!
//! A metadata store that is
//! smaller but reports different facts would be worse than the larger one, so
//! this is the test that makes the size figures mean anything.
//!
//! Gated on `hdt-experiment`; the default build compiles none of it.

#![cfg(all(feature = "hdt-experiment", feature = "corpus"))]

use std::path::PathBuf;

use aff4tools::error::Locus;
use aff4tools::metadata::MetadataStore;
use aff4tools::metadata::hdt_store::HdtStore;
use aff4tools::rdf::Graph;

fn corpus(relative: &str) -> PathBuf {
    let root = std::env::var_os("AFF4_TEST_IMAGES").map_or_else(
        || {
            PathBuf::from(std::env::var_os("HOME").expect("HOME must be set"))
                .join(".cache/aff4tools/corpus")
        },
        PathBuf::from,
    );
    root.join(relative)
}

/// Read one container's `information.turtle`.
fn metadata(relative: &str) -> Option<(Vec<u8>, Locus)> {
    use aff4tools::zip::{Volume as _, ZipVolume};
    let path = corpus(relative);
    if !path.is_file() {
        return None;
    }
    let mut volume = ZipVolume::open(&path).ok()?;
    let bytes = volume.read_segment("information.turtle").ok()?;
    Some((bytes, Locus::new(path)))
}

/// Every corpus container, through both backends, compared statement by
/// statement.
///
/// Covers all four generations plus the AFF4-L containers, including
/// `broken-dedupe.aff4` — the one that exercises pyaff4's byte-range ARN
/// extension, which is the deviation the two backends must agree on.
#[test]
fn both_backends_report_identical_metadata() {
    let containers = [
        "pyaff4/test_images/AFF4Std/Base-Linear.aff4",
        "pyaff4/test_images/AFF4Std/Base-Allocated.aff4",
        "pyaff4/test_images/AFF4Std/Base-Linear-AllHashes.aff4",
        "pyaff4/test_images/AFF4Std/Striped/Base-Linear_1.aff4",
        "pyaff4/test_images/AFF4PreStd/Base-Linear.af4",
        "pyaff4/test_images/AFF4-L/dream.aff4",
        "pyaff4/test_images/AFF4-L/unicode.aff4",
        "pyaff4/test_images/AFF4-L/broken-dedupe.aff4",
    ];

    let mut checked = 0;
    for relative in containers {
        let Some((bytes, locus)) = metadata(relative) else {
            continue;
        };
        let graph = Graph::parse(&bytes, &locus).expect("graph parses");
        let hdt = HdtStore::parse(&bytes, &locus).expect("hdt parses");

        assert_eq!(
            MetadataStore::len(&hdt),
            MetadataStore::len(&graph),
            "{relative}: statement count"
        );
        assert_eq!(
            MetadataStore::subjects(&hdt),
            MetadataStore::subjects(&graph),
            "{relative}: subject order"
        );
        assert_eq!(
            MetadataStore::prefixes(&hdt),
            MetadataStore::prefixes(&graph),
            "{relative}: prefix bindings"
        );

        // Deviations must match in kind: `conformance` reads these from the
        // summary, so a backend that dropped one would under-report.
        let kinds = |store: &dyn MetadataStore| -> Vec<String> {
            MetadataStore::deviations(store)
                .into_iter()
                .map(|d| format!("{:?}", d.kind))
                .collect()
        };
        assert_eq!(
            kinds(&hdt),
            kinds(&graph),
            "{relative}: recorded deviations"
        );

        // Every statement of every subject, in order.
        for subject in MetadataStore::subjects(&graph) {
            assert_eq!(
                MetadataStore::statements_for(&hdt, &subject),
                MetadataStore::statements_for(&graph, &subject),
                "{relative}: statements for {subject}"
            );
        }
        checked += 1;
    }

    assert!(checked > 0, "no corpus container was readable");
}
