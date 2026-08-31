//! An HDT-backed [`MetadataStore`], behind the `hdt-experiment` feature.
//!
//! Holds the same statements as
//! [`crate::rdf::Graph`] in a compressed, indexed form: H1 measured **22×
//! smaller resident** on identical containers — 115.6 MiB against ~2.5 GB at
//! 400,000 objects — with both representations agreeing on every triple.
//!
//! Nothing is written to disk. The paper this follows (Schatz 2019, §4–§6)
//! caches an HDT beside the container; this does not, because H1 showed the
//! build cost does not justify a derived copy of evidence metadata that could
//! go stale. See the plan's "Caching is not required".
//!
//! # Streaming construction
//!
//! Triples are fed to the builder from the Turtle parser without collecting a
//! `Vec<[String; 3]>` first. H1 measured that vector as most of HDT's 1.45×
//! peak-memory penalty: the intermediate copy and the growing HDT were live at
//! once. `Hdt::from_triples` takes an `IntoIterator`, so the parser's own
//! iterator can be adapted straight into it and no intermediate exists.
//!
//! # Term encoding
//!
//! HDT's dictionary stores IRIs bare and literals in their N-Triples lexical
//! form (`"value"^^<datatype>`). [`Graph`](crate::rdf::Graph) stores a parsed
//! [`Value`] instead, so terms are encoded on the way in and decoded on the way
//! out. **Byte-range ARNs are unescaped before storage**, not on each query:
//! doing it once at build time keeps both backends returning identical lexical
//! forms and keeps the query path free of per-call string work.

use std::collections::{HashMap, HashSet};

use hdt::Hdt;

use crate::arn::unescape;
use crate::error::{Deviation, DeviationKind, Error, Locus, Result};
use crate::metadata::MetadataStore;
use crate::rdf::{Statement, Value, escape_byte_ranges};

/// A container's metadata, held as HDT.
pub struct HdtStore {
    hdt: Hdt,
    /// Subjects in first-appearance order.
    ///
    /// HDT's dictionary is sorted, but the report's tier-3 fallback presents
    /// objects in turtle order when no `aff4:contains` manifest exists. Storing
    /// the order separately is what keeps `info` output identical between
    /// backends; it costs one `String` per subject, which is negligible beside
    /// the statements themselves.
    subject_order: Vec<String>,
    /// Per subject, the `(predicate, object)` pairs in the order the container
    /// states them.
    ///
    /// HDT returns a subject's triples in dictionary order, but the trait
    /// promises source order and `info` prints statements in the order it
    /// receives them — so without this the two backends produce the same facts
    /// in a different sequence, and every `info` output differs. Recorded
    /// during the same pass that feeds the builder, so no second parse.
    ///
    /// This is the one place the HDT backend keeps owned strings per statement,
    /// which costs back part of the compression saving. Measured against the
    /// alternative — reordering query results against a stored index — this is
    /// simpler and the H2 benchmark reports the real figure either way.
    statement_order: HashMap<String, Vec<(String, String)>>,
    prefixes: Vec<(String, String)>,
    deviations: Vec<Deviation>,
    len: usize,
}

/// Manual rather than derived: `hdt::Hdt` implements no `Debug`, and dumping a
/// compressed dictionary of millions of terms would be unreadable anyway. The
/// counts are what a reader of a debug line actually wants.
impl std::fmt::Debug for HdtStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HdtStore")
            .field("statements", &self.len)
            .field("subjects", &self.subject_order.len())
            .field("prefixes", &self.prefixes.len())
            .field("deviations", &self.deviations.len())
            .finish_non_exhaustive()
    }
}

impl HdtStore {
    /// Parse `information.turtle` into an HDT-backed store.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if the metadata is not valid Turtle, or if the HDT
    /// builder rejects the triples.
    pub fn parse(bytes: &[u8], locus: &Locus) -> Result<Self> {
        let source = String::from_utf8_lossy(bytes);
        let (prepared, escaped_ranges) = escape_byte_ranges(&source);

        let mut deviations = Vec::new();
        if escaped_ranges > 0 {
            // Identical to `Graph::parse`'s wording: `conformance` reports this
            // and the two backends must not differ in what an examiner reads.
            deviations.push(Deviation::new(
                locus.clone(),
                DeviationKind::ByteRangeArn,
                format!(
                    "{escaped_ranges} IRI(s) use pyaff4's byte-range extension \
                     aff4://<uuid>[start:length]; square brackets are not permitted \
                     in RDF IRIs, so these were percent-encoded to parse and \
                     restored afterwards"
                ),
            ));
        }

        let prefixes = crate::rdf::prefix_bindings(&source);

        // Two things are needed that the triple stream alone does not give:
        // the count, and first-appearance subject order. Both are gathered
        // during the single pass that feeds the builder, so the parser is not
        // run twice and no intermediate triple vector exists.
        let mut subject_order: Vec<String> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        let mut len = 0usize;
        let mut statement_order: HashMap<String, Vec<(String, String)>> = HashMap::new();
        let mut parse_error: Option<String> = None;

        let rows = oxttl::TurtleParser::new()
            .for_reader(prepared.as_bytes())
            .filter_map(|result| {
                match result {
                    Ok(triple) => encode(&triple),
                    Err(e) => {
                        // The iterator cannot fail the whole build, so the
                        // first error is captured and raised after the pass.
                        if parse_error.is_none() {
                            parse_error = Some(e.to_string());
                        }
                        None
                    }
                }
            })
            .inspect(|row: &[String; 3]| {
                len += 1;
                if seen.insert(row[0].clone()) {
                    subject_order.push(row[0].clone());
                }
                statement_order
                    .entry(row[0].clone())
                    .or_default()
                    .push((row[1].clone(), row[2].clone()));
            });

        let hdt = Hdt::from_triples(rows, "aff4://container").map_err(|e| {
            Error::malformed(locus.clone(), format!("could not build HDT index: {e}"))
        })?;

        if let Some(detail) = parse_error {
            return Err(Error::malformed(
                locus.clone(),
                format!("information.turtle is not valid Turtle: {detail}"),
            ));
        }

        Ok(Self {
            hdt,
            subject_order,
            statement_order,
            prefixes,
            deviations,
            len,
        })
    }
}

/// One oxrdf triple as HDT dictionary strings, or [`None`] for a blank node.
///
/// Blank nodes carry no ARN and cannot be addressed by the summary; none appear
/// in the corpus. `Graph::parse` skips them, and so does this.
fn encode(triple: &oxrdf::Triple) -> Option<[String; 3]> {
    use oxrdf::{NamedOrBlankNode, Term};

    let subject = match &triple.subject {
        NamedOrBlankNode::NamedNode(node) => unescape(node.as_str()),
        NamedOrBlankNode::BlankNode(_) => return None,
    };

    let predicate = triple.predicate.as_str().to_owned();

    let object = match &triple.object {
        Term::NamedNode(node) => unescape(node.as_str()),
        Term::Literal(literal) => {
            // N-Triples lexical form, which is what HDT's dictionary expects
            // and what `decode` reads back.
            format!(
                "\"{}\"^^<{}>",
                escape_literal(literal.value()),
                literal.datatype().as_str()
            )
        }
        Term::BlankNode(_) => return None,
    };

    Some([subject, predicate, object])
}

/// Escape a literal's lexical form for the N-Triples quoting HDT stores.
fn escape_literal(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(ch),
        }
    }
    out
}

/// Reverse [`escape_literal`].
fn unescape_literal(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some(c @ ('\\' | '"')) => out.push(c),
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// An HDT dictionary term as the [`Value`] the summary builder expects.
///
/// A literal is `"lexical"^^<datatype>`; anything else is an IRI. The datatype
/// is always present because [`encode`] always writes one — oxrdf reports
/// `xsd:string` for untyped literals, and that distinction is preserved rather
/// than normalised away.
fn decode(term: &str) -> Value {
    if let Some(rest) = term.strip_prefix('"')
        && let Some(close) = rest.rfind("\"^^<")
        && term.ends_with('>')
    {
        let lexical = unescape_literal(&rest[..close]);
        let datatype = &rest[close + 4..rest.len() - 1];
        return Value::Literal {
            lexical,
            datatype: Some(std::sync::Arc::from(datatype)),
        };
    }
    Value::Iri {
        iri: term.to_owned(),
    }
}

impl MetadataStore for HdtStore {
    fn subjects(&self) -> Vec<String> {
        self.subject_order.clone()
    }

    fn statements_for(&self, subject: &str) -> Vec<Statement> {
        // Source order, from the recorded index rather than from HDT's
        // dictionary order — see `statement_order`.
        self.statement_order
            .get(subject)
            .map(|pairs| {
                pairs
                    .iter()
                    .map(|(predicate, object)| Statement {
                        subject: std::sync::Arc::from(subject),
                        predicate: std::sync::Arc::from(predicate.as_str()),
                        object: decode(object),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn objects(&self, subject: &str, predicate: &str) -> Vec<Value> {
        self.statement_order
            .get(subject)
            .map(|pairs| {
                pairs
                    .iter()
                    .filter(|(p, _)| p == predicate)
                    .map(|(_, o)| decode(o))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn subjects_of_type(&self, type_iri: &str) -> Vec<String> {
        // The one query HDT's index answers better than a scan: at 400,000
        // subjects H1 measured 123 ms against `Graph`'s 302 ms. Results come
        // back in dictionary order, so they are filtered through
        // `subject_order` to preserve first-appearance order, which the report
        // depends on.
        let matching: HashSet<String> = self
            .hdt
            .triples_with_pattern(None, Some(crate::rdf::RDF_TYPE), Some(type_iri))
            .map(|[s, _, _]| s.to_string())
            .collect();
        self.subject_order
            .iter()
            .filter(|subject| matching.contains(*subject))
            .cloned()
            .collect()
    }

    fn prefixes(&self) -> Vec<(String, String)> {
        self.prefixes.clone()
    }

    fn deviations(&self) -> Vec<Deviation> {
        self.deviations.clone()
    }

    fn len(&self) -> usize {
        self.len
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::rdf::Graph;

    fn locus() -> Locus {
        Locus::new(std::path::PathBuf::from("t.aff4"))
    }

    const SAMPLE: &str = r#"@prefix aff4: <http://aff4.org/Schema#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
<aff4://a> a aff4:FileImage, aff4:Image ;
    aff4:size 42 ;
    aff4:originalFileName "/x.txt"^^xsd:string ;
    aff4:birthTime "2026-03-01T00:00:00Z"^^xsd:dateTime .
<aff4://b> a aff4:FolderImage ;
    aff4:size 0 .
"#;

    /// The two backends must answer identically, or the size saving is
    /// meaningless — a smaller store that lost or altered a triple would be
    /// worse than the larger one.
    #[test]
    fn hdt_answers_exactly_as_the_graph_does() {
        let graph = Graph::parse(SAMPLE.as_bytes(), &locus()).unwrap();
        let store = HdtStore::parse(SAMPLE.as_bytes(), &locus()).unwrap();

        assert_eq!(
            MetadataStore::len(&store),
            MetadataStore::len(&graph),
            "statement counts must match"
        );
        assert_eq!(
            MetadataStore::subjects(&store),
            MetadataStore::subjects(&graph),
            "subject order must match"
        );

        for subject in MetadataStore::subjects(&graph) {
            let mut from_graph = MetadataStore::statements_for(&graph, &subject);
            let mut from_hdt = MetadataStore::statements_for(&store, &subject);
            // HDT returns a subject's statements in dictionary order; only the
            // set matters here, since `build_objects` reads them by predicate.
            from_graph.sort_by(|a, b| a.predicate.cmp(&b.predicate));
            from_hdt.sort_by(|a, b| a.predicate.cmp(&b.predicate));
            assert_eq!(from_hdt, from_graph, "statements for {subject}");
        }
    }

    /// A typed literal round-trips with its datatype and lexical form intact.
    ///
    /// The lexical form is never reformatted, so a timestamp
    /// must come back byte-identical.
    #[test]
    fn literals_round_trip_with_their_datatype() {
        let store = HdtStore::parse(SAMPLE.as_bytes(), &locus()).unwrap();
        let value = MetadataStore::object(&store, "aff4://a", "http://aff4.org/Schema#birthTime")
            .expect("birthTime is stated once");
        assert_eq!(
            value,
            Value::Literal {
                lexical: "2026-03-01T00:00:00Z".to_owned(),
                datatype: Some(std::sync::Arc::from(
                    "http://www.w3.org/2001/XMLSchema#dateTime",
                )),
            }
        );
    }

    /// Quotes and backslashes inside a literal survive the N-Triples encoding.
    #[test]
    fn awkward_literals_survive_encoding() {
        let turtle = r#"@prefix aff4: <http://aff4.org/Schema#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
<aff4://a> aff4:originalFileName "a\"b\\c\nd"^^xsd:string .
"#;
        let graph = Graph::parse(turtle.as_bytes(), &locus()).unwrap();
        let store = HdtStore::parse(turtle.as_bytes(), &locus()).unwrap();
        let predicate = "http://aff4.org/Schema#originalFileName";
        assert_eq!(
            MetadataStore::object(&store, "aff4://a", predicate),
            MetadataStore::object(&graph, "aff4://a", predicate)
        );
    }

    /// `ByteRangeArn` must be reported by both backends, since `conformance`
    /// reads it from the summary and never parses anything itself.
    #[test]
    fn byte_range_arns_are_reported_by_both_backends() {
        let turtle = "@prefix aff4: <http://aff4.org/Schema#> .\n\
             <aff4://5aea2dd0-32b4-4c61-a9db-677654be6f83[0x0:0x8000]> \
             aff4:size 32768 .\n";
        let graph = Graph::parse(turtle.as_bytes(), &locus()).unwrap();
        let store = HdtStore::parse(turtle.as_bytes(), &locus()).unwrap();

        let kinds =
            |ds: Vec<Deviation>| -> Vec<DeviationKind> { ds.into_iter().map(|d| d.kind).collect() };
        assert_eq!(
            kinds(MetadataStore::deviations(&store)),
            kinds(MetadataStore::deviations(&graph)),
            "both backends must record the byte-range extension"
        );
        assert!(
            MetadataStore::deviations(&store)
                .iter()
                .any(|d| d.kind == DeviationKind::ByteRangeArn)
        );
    }

    /// Malformed Turtle is refused rather than silently yielding a short store.
    #[test]
    fn invalid_turtle_is_malformed() {
        let err = HdtStore::parse(b"this is not turtle", &locus()).unwrap_err();
        assert!(matches!(err, Error::Malformed { .. }), "{err:?}");
    }
}
