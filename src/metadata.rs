//! The metadata query surface, and the backends that answer it.
//!
//! [`MetadataStore`] is the set
//! of questions `container::build_objects` and the report path ask of a
//! container's parsed `information.turtle`. [`crate::rdf::Graph`] implements it,
//! and — behind the `hdt-experiment` feature — so does an HDT-backed store.
//!
//! # Why a trait
//!
//! H1 measured HDT at **22× smaller resident** than `Graph` on the same
//! container, with both agreeing on every triple. That is worth having at ten
//! million objects, where `Graph` needs ~142 GB and HDT ~2.8 GB. The trait is
//! what lets the two be compared in one binary, and what keeps the choice
//! reversible: if HDT turns out to be wrong, deleting the backend leaves
//! `Graph` untouched.
//!
//! **The default build is unaffected.** Without `hdt-experiment` there is one
//! implementor, the trait resolves to it statically, and nothing about the
//! tool's behavior changes.
//!
//! # Owned returns
//!
//! `Graph` can hand out `&str` into its own storage; HDT decodes terms from a
//! compressed dictionary and must produce owned `String`s. The trait therefore
//! returns owned values, which costs `Graph` an allocation per result it did
//! not previously make. That is deliberate: the alternative is a lifetime-bound
//! associated type that would force HDT to cache decoded terms, reintroducing
//! exactly the per-term allocation HDT exists to avoid.
//!
//! # Deviations
//!
//! One deviation is raised while parsing rather than while reading values:
//! [`crate::error::DeviationKind::ByteRangeArn`], for pyaff4's
//! `aff4://<uuid>[start:length]` extension. Both backends must report it
//! identically, because `aff4tools conformance` reads
//! `ContainerSummary::deviations` and never parses anything itself — so a
//! backend that dropped it would make `conformance` under-report on a real
//! container. [`MetadataStore::deviations`] is what carries it across.
//!
//! Every other deviation is raised later, by `as_u64` and `as_timestamp` in
//! [`crate::rdf`], from values this trait returns. Those are backend-agnostic
//! already.

use crate::error::Deviation;
use crate::rdf::{Graph, RDF_TYPE, Statement, Value};

/// The questions the summary builder asks of a container's metadata.
///
/// Deliberately narrow: exactly the methods `container.rs` and `report.rs` call
/// today, and nothing speculative. A backend that answers these can stand in
/// for [`Graph`] wherever a summary is built.
pub trait MetadataStore {
    /// Every subject, in first-appearance order.
    ///
    /// Order is part of the contract, not an implementation detail: the
    /// report's tier-3 fallback presents objects in turtle order when a
    /// container declares no `aff4:contains` manifest, so a backend that
    /// returned subjects in dictionary order would silently reorder the output
    /// of `info` on every pre-standard container.
    fn subjects(&self) -> Vec<String>;

    /// Every statement about `subject`, in the order the container states them.
    fn statements_for(&self, subject: &str) -> Vec<Statement>;

    /// Every object of `subject`'s `predicate`.
    fn objects(&self, subject: &str, predicate: &str) -> Vec<Value>;

    /// The single object of `subject`'s `predicate`, if exactly one exists.
    ///
    /// [`None`] when the predicate is absent **or** repeated: a caller asking
    /// for one value cannot be handed an arbitrary member of several without
    /// choosing on the caller's behalf, which is the kind of silent decision
    /// this project refuses.
    fn object(&self, subject: &str, predicate: &str) -> Option<Value> {
        let objects = self.objects(subject, predicate);
        (objects.len() == 1)
            .then(|| objects.into_iter().next())
            .flatten()
    }

    /// Every `rdf:type` IRI declared by `subject`.
    fn types(&self, subject: &str) -> Vec<String> {
        self.objects(subject, RDF_TYPE)
            .into_iter()
            .filter_map(|value| value.as_iri().map(ToOwned::to_owned))
            .collect()
    }

    /// Every subject declaring `type_iri`, in first-appearance order.
    fn subjects_of_type(&self, type_iri: &str) -> Vec<String> {
        self.subjects()
            .into_iter()
            .filter(|subject| self.types(subject).iter().any(|t| t == type_iri))
            .collect()
    }

    /// `@prefix` bindings, in declaration order.
    fn prefixes(&self) -> Vec<(String, String)>;

    /// Departures from the standard observed while parsing.
    ///
    /// Carries `ByteRangeArn` from the backend to `ContainerSummary`, which is
    /// where `conformance` reads it. See the module documentation.
    fn deviations(&self) -> Vec<Deviation>;

    /// How many statements the store holds.
    fn len(&self) -> usize;

    /// Whether the store holds no statements.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl MetadataStore for Graph {
    fn subjects(&self) -> Vec<String> {
        Graph::subjects(self)
            .iter()
            .map(std::string::ToString::to_string)
            .collect()
    }

    fn statements_for(&self, subject: &str) -> Vec<Statement> {
        Graph::statements_for(self, subject)
            .into_iter()
            .cloned()
            .collect()
    }

    fn objects(&self, subject: &str, predicate: &str) -> Vec<Value> {
        Graph::objects(self, subject, predicate)
            .into_iter()
            .cloned()
            .collect()
    }

    fn prefixes(&self) -> Vec<(String, String)> {
        Graph::prefixes(self).to_vec()
    }

    fn deviations(&self) -> Vec<Deviation> {
        Graph::deviations(self).to_vec()
    }

    fn len(&self) -> usize {
        Graph::len(self)
    }
}

#[cfg(feature = "hdt-experiment")]
pub mod hdt_store;

/// Which metadata backend to use, read once from the environment.
///
/// `AFF4TOOLS_METADATA=hdt` selects the HDT backend in a build that has the
/// `hdt-experiment` feature. Anything else, and every build without the
/// feature, uses [`Graph`].
///
/// An environment variable rather than a CLI flag: this is an experiment that
/// may be reverted, and a flag would put it in `--help` and in every user's
/// mental model of the tool. A variable is enough to A/B the two backends in a
/// benchmark, which is all H2 needs.
#[cfg(feature = "hdt-experiment")]
#[must_use]
pub fn hdt_requested() -> bool {
    std::env::var("AFF4TOOLS_METADATA").is_ok_and(|value| value.eq_ignore_ascii_case("hdt"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::error::Locus;

    fn graph(turtle: &str) -> Graph {
        Graph::parse(
            turtle.as_bytes(),
            &Locus::new(std::path::PathBuf::from("t.aff4")),
        )
        .expect("valid turtle")
    }

    const SAMPLE: &str = r#"@prefix aff4: <http://aff4.org/Schema#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
<aff4://a> a aff4:FileImage, aff4:Image ;
    aff4:size 42 ;
    aff4:originalFileName "/x.txt"^^xsd:string .
<aff4://b> a aff4:FolderImage ;
    aff4:size 0 .
"#;

    /// The trait must answer exactly what the inherent methods answer.
    ///
    /// `Graph` is the reference implementation, so a divergence here would mean
    /// the trait had changed behavior while claiming only to abstract it.
    #[test]
    fn the_trait_agrees_with_graphs_own_methods() {
        let g = graph(SAMPLE);

        assert_eq!(
            MetadataStore::subjects(&g),
            Graph::subjects(&g)
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
        );
        assert_eq!(MetadataStore::len(&g), Graph::len(&g));

        for subject in Graph::subjects(&g) {
            assert_eq!(
                MetadataStore::statements_for(&g, subject).len(),
                Graph::statements_for(&g, subject).len(),
                "statement count for {subject}"
            );
            assert_eq!(
                MetadataStore::types(&g, subject),
                Graph::types(&g, subject)
                    .into_iter()
                    .map(ToOwned::to_owned)
                    .collect::<Vec<String>>(),
                "types for {subject}"
            );
        }
    }

    /// Subject order is first-appearance, which the report's fallback relies on.
    #[test]
    fn subject_order_is_first_appearance() {
        let g = graph(SAMPLE);
        assert_eq!(MetadataStore::subjects(&g), vec!["aff4://a", "aff4://b"]);
    }

    /// A repeated predicate has no single object, and must not yield an
    /// arbitrary one.
    #[test]
    fn a_repeated_predicate_has_no_single_object() {
        let g = graph(SAMPLE);
        // `a` (rdf:type) is stated twice for aff4://a.
        assert!(MetadataStore::object(&g, "aff4://a", RDF_TYPE).is_none());
        assert_eq!(MetadataStore::objects(&g, "aff4://a", RDF_TYPE).len(), 2);
    }

    /// `subjects_of_type` finds every declarer, in first-appearance order.
    #[test]
    fn subjects_of_type_preserves_order() {
        let g = graph(SAMPLE);
        assert_eq!(
            MetadataStore::subjects_of_type(&g, "http://aff4.org/Schema#FileImage"),
            vec!["aff4://a"]
        );
    }
}
