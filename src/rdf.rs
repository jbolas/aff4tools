//! Parsing `information.turtle` into a queryable graph.
//!
//! AFF4 metadata is RDF in Turtle syntax. This module parses it with `oxttl`,
//! indexes the triples by subject, and coerces typed literals leniently —
//! recording every departure from the standard rather than normalising it away.
//!
//! # Byte-range ARNs
//!
//! pyaff4 emits IRIs like `aff4://<uuid>[0x4f8000:0x8000]` to name a byte range
//! of a stream. Square brackets are excluded from Turtle's `IRIREF` production,
//! so a conformant parser rejects them: `broken-dedupe.aff4` yields 16 triples
//! and 437 errors when handed to `oxttl` directly.
//!
//! Since these are deliberate (pyaff4's `ByteRangeARN`) rather than corruption,
//! [`escape_byte_ranges`] percent-encodes the suffix before parsing, and the
//! lexical form is restored on the way out via [`crate::arn::unescape`]. With
//! that pre-pass the same container yields 453 triples and no errors.
//!
//! The escaping covers the whole suffix, not just the brackets. `oxttl` reads
//! `%` followed by two characters as a percent-escape and requires uppercase
//! hex, so a half-escaped `…%5B0x4f8000…` fails on the lowercase `x` of `0x`.
//!
//! # Lenient literals
//!
//! Real containers deviate in ways that are legal RDF but not what the standard
//! writes. Both of these are common in the corpus:
//!
//! - `aff4:size 8688` — an untyped integer, where `AFF4Std` writes
//!   `"8688"^^xsd:long`. 22 occurrences across two containers.
//! - `xsd:datetime` — lowercase, where XSD defines `xsd:dateTime`. 44
//!   occurrences, all in the three AFF4-L containers, against 45
//!   correctly-spelled ones in the physical containers.
//!
//! Both are accepted **in silence**: each is a writer's stylistic choice that
//! no reading of the evidence turns on, so reporting either would dilute the
//! deviation list rather than inform it.
//! Anything genuinely ambiguous still returns [`None`] rather than a guess, and
//! a datatype that is neither known spelling is still reported.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use oxrdf::{NamedOrBlankNode, Term};
use oxttl::TurtleParser;

use crate::arn::unescape_byte_range;
use crate::error::{Deviation, DeviationKind, Error, Locus, Result};

/// The XSD namespace.
const XSD: &str = "http://www.w3.org/2001/XMLSchema#";

/// `rdf:type`, the predicate declaring an object's classes.
pub const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";

/// A parsed metadata graph, indexed by subject.
///
/// Backed by a flat `Vec` plus a subject index: these graphs run from 950 bytes
/// to 99 KB, and subject lookup is the only access pattern the summary needs.
#[derive(Debug, Default)]
pub struct Graph {
    triples: Vec<Statement>,
    by_subject: HashMap<Arc<str>, Vec<usize>>,
    subject_order: Vec<Arc<str>>,
    deviations: Vec<Deviation>,
    /// `@prefix` bindings, in declaration order.
    ///
    /// Kept so a report can render a vendor IRI as `bbt:APFSContainerImage`
    /// rather than in full. Without them an extension term is indistinguishable
    /// from an AFF4 one once the namespace is stripped.
    prefixes: Vec<(String, String)>,
}

/// Extract every `@prefix` (or SPARQL `PREFIX`) binding from Turtle source.
///
/// A deliberately narrow scan rather than a parse, for the same reason
/// `container::aff4_namespace` is: prefix bindings are needed before and
/// independently of the triple store, and a malformed directive should be
/// skipped rather than guessed at.
#[must_use]
pub fn prefix_bindings(turtle: &str) -> Vec<(String, String)> {
    let mut bindings = Vec::new();

    for line in turtle.lines() {
        let line = line.trim();
        let Some(rest) = line
            .strip_prefix("@prefix")
            .or_else(|| line.strip_prefix("@PREFIX"))
            .or_else(|| line.strip_prefix("PREFIX"))
            .or_else(|| line.strip_prefix("prefix"))
        else {
            continue;
        };

        let rest = rest.trim_start();
        let Some((name, tail)) = rest.split_once(':') else {
            continue;
        };
        let name = name.trim();

        // Reject a "prefix" that is really part of a longer word, and anything
        // with whitespace in the name.
        if name.contains(char::is_whitespace) {
            continue;
        }

        if let Some(open) = tail.find('<')
            && let Some(close) = tail[open..].find('>')
        {
            let iri = &tail[open + 1..open + close];
            if !bindings
                .iter()
                .any(|(existing, _): &(String, String)| existing == name)
            {
                bindings.push((name.to_owned(), iri.to_owned()));
            }
        }
    }

    bindings
}

/// One triple, with terms reduced to the lexical forms this crate works in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    /// Subject IRI, unescaped back to its original lexical form.
    ///
    /// `Arc<str>` rather than `String`: a subject is repeated once per triple
    /// that mentions it — 15 times on average in an AFF4-L container — and a
    /// predicate is drawn from a vocabulary of about a dozen terms. Sharing one
    /// allocation per distinct value instead of one per statement is worth
    /// ~1.5 GB at a million described objects; see docs/RDF-scalability.md.
    pub subject: Arc<str>,
    /// Predicate IRI.
    pub predicate: Arc<str>,
    /// Object, either an IRI or a literal.
    pub object: Value,
}

/// An RDF object: a reference to another resource, or a literal value.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Value {
    /// An IRI naming another resource.
    Iri {
        /// The IRI, unescaped to its original lexical form.
        iri: String,
    },
    /// A literal value.
    Literal {
        /// The lexical form, exactly as written in the container.
        lexical: String,
        /// The datatype IRI, if the literal carried one.
        ///
        /// `Arc<str>` rather than `String`: a container draws every typed
        /// literal from a handful of datatype IRIs — **three** across a
        /// million-object AFF4-L container, against 8.1 million literals — so
        /// one shared allocation per distinct IRI replaces one per literal.
        /// Worth ~0.9 GB at that size; see `docs/RDF-scalability.md`.
        datatype: Option<Arc<str>>,
    },
}

impl Value {
    /// The IRI, if this is a resource reference.
    #[must_use]
    pub fn as_iri(&self) -> Option<&str> {
        match self {
            Self::Iri { iri } => Some(iri),
            Self::Literal { .. } => None,
        }
    }

    /// The lexical form, whether IRI or literal.
    #[must_use]
    pub fn lexical(&self) -> &str {
        match self {
            Self::Iri { iri } => iri,
            Self::Literal { lexical, .. } => lexical,
        }
    }

    /// The datatype IRI, if this is a typed literal.
    #[must_use]
    pub fn datatype(&self) -> Option<&str> {
        match self {
            Self::Literal { datatype, .. } => datatype.as_deref(),
            Self::Iri { .. } => None,
        }
    }
}

impl Graph {
    /// Parse `information.turtle`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Malformed`] if the metadata is not valid Turtle, naming
    /// the position the parser reported.
    pub fn parse(bytes: &[u8], locus: &Locus) -> Result<Self> {
        let source = String::from_utf8_lossy(bytes);
        let (prepared, escaped_ranges) = escape_byte_ranges(&source);

        let mut graph = Self {
            prefixes: prefix_bindings(&source),
            ..Self::default()
        };

        if escaped_ranges > 0 {
            graph
                .deviations
                .push(byte_range_deviation(locus, escaped_ranges));
        }

        for statement in parse_statements(prepared.as_bytes(), locus) {
            graph.push(statement?);
        }

        Ok(graph)
    }

    /// Parse `information.turtle`, handing each subject to `emit` as it
    /// completes, and never holding more than one subject's statements.
    ///
    /// [`Graph::parse`] retains all 15.1 million statements of a million-object
    /// container — 2.26 GB — so that any subject can be looked up later. A
    /// consumer that reads each subject once and discards it does not need
    /// that. `conformance` is the case this exists for; see
    /// `docs/RDF-scalability.md`.
    ///
    /// `emit` receives a [`Graph`] holding exactly one subject, so the same
    /// per-subject code can run against either form. The prefix bindings and
    /// the parse deviations are carried on it, since a caller needs both to
    /// render a vendor IRI and to report what parsing found.
    ///
    /// # Subject contiguity
    ///
    /// A subject is closed when the next statement names a different one. Every
    /// writer in the corpus emits a subject's statements contiguously, but
    /// Turtle permits a subject to reappear, so a repeat is **recorded as a
    /// deviation** and emitted as a second, partial subject rather than
    /// silently merged or silently dropped. Splitting an object in two is
    /// visible in the output; quietly losing half of it would not be.
    ///
    /// # Errors
    ///
    /// As [`Graph::parse`], plus anything `emit` returns.
    pub fn stream_by_subject(
        bytes: &[u8],
        locus: &Locus,
        mut emit: impl FnMut(&Graph) -> Result<()>,
    ) -> Result<Vec<Deviation>> {
        let source = String::from_utf8_lossy(bytes);
        let (prepared, escaped_ranges) = escape_byte_ranges(&source);

        let prefixes = prefix_bindings(&source);
        let mut deviations = Vec::new();
        if escaped_ranges > 0 {
            deviations.push(byte_range_deviation(locus, escaped_ranges));
        }

        // One subject at a time. `seen` exists only to detect a subject that
        // reappears after being closed; it holds ARNs the caller already has,
        // so it is the caller's `HashSet` that bounds memory, not this one.
        let mut seen: std::collections::HashSet<Arc<str>> = std::collections::HashSet::new();
        let mut current: Option<Graph> = None;
        let mut repeats = 0usize;

        for statement in parse_statements(prepared.as_bytes(), locus) {
            let statement = statement?;

            let is_new = current.as_ref().is_none_or(|g| {
                g.subject_order
                    .first()
                    .is_none_or(|s| *s != statement.subject)
            });

            if is_new {
                if let Some(finished) = current.take() {
                    emit(&finished)?;
                }
                if !seen.insert(Arc::clone(&statement.subject)) {
                    repeats += 1;
                }
                current = Some(Graph {
                    prefixes: prefixes.clone(),
                    ..Self::default()
                });
            }

            if let Some(graph) = current.as_mut() {
                graph.push(statement);
            }
        }

        if let Some(finished) = current.take() {
            emit(&finished)?;
        }

        if repeats > 0 {
            deviations.push(Deviation::new(
                locus.clone(),
                DeviationKind::UnexpectedDatatype,
                format!(
                    "{repeats} subject(s) are described in more than one place in                      information.turtle rather than in one contiguous block; each                      later block was read as a separate partial description, so                      properties of one resource may be reported split across two"
                ),
            ));
        }

        Ok(deviations)
    }

    fn push(&mut self, statement: Statement) {
        let index = self.triples.len();
        let indices = self
            .by_subject
            .entry(statement.subject.clone())
            .or_default();
        if indices.is_empty() {
            // First statement about this subject: record it for stable ordering.
            self.subject_order.push(statement.subject.clone());
        }
        indices.push(index);
        self.triples.push(statement);
    }

    /// Total number of triples.
    #[must_use]
    pub fn len(&self) -> usize {
        self.triples.len()
    }

    /// Whether the graph holds no triples.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.triples.is_empty()
    }

    /// Every subject, in first-appearance order.
    ///
    /// Ordered so output is stable across runs — a summary that reshuffles
    /// between invocations is hard to diff and hard to trust.
    #[must_use]
    pub fn subjects(&self) -> &[Arc<str>] {
        &self.subject_order
    }

    /// Every statement about `subject`.
    #[must_use]
    pub fn statements_for(&self, subject: &str) -> Vec<&Statement> {
        self.by_subject
            .get(subject)
            .map(|indices| {
                indices
                    .iter()
                    .filter_map(|i| self.triples.get(*i))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Every object of `predicate` on `subject`.
    #[must_use]
    pub fn objects(&self, subject: &str, predicate: &str) -> Vec<&Value> {
        self.statements_for(subject)
            .into_iter()
            .filter(|s| &*s.predicate == predicate)
            .map(|s| &s.object)
            .collect()
    }

    /// The single object of `predicate` on `subject`, if there is exactly one.
    #[must_use]
    pub fn object(&self, subject: &str, predicate: &str) -> Option<&Value> {
        let objects = self.objects(subject, predicate);
        (objects.len() == 1).then(|| objects[0]).or(None)
    }

    /// Every `rdf:type` of `subject`.
    ///
    /// v1.0a §2.1 requires multiple types (a disk image is `DiskImage` **and**
    /// `ContiguousImage` **and** `Image`), so this always returns the full set.
    #[must_use]
    pub fn types(&self, subject: &str) -> Vec<&str> {
        self.objects(subject, RDF_TYPE)
            .into_iter()
            .filter_map(Value::as_iri)
            .collect()
    }

    /// Subjects carrying `rdf:type` `type_iri`.
    #[must_use]
    pub fn subjects_of_type(&self, type_iri: &str) -> Vec<&str> {
        self.subject_order
            .iter()
            .filter(|s| self.types(s).contains(&type_iri))
            .map(|s| &**s)
            .collect()
    }

    /// Every `@prefix` binding the source declared, in declaration order.
    #[must_use]
    pub fn prefixes(&self) -> &[(String, String)] {
        &self.prefixes
    }

    /// Render an IRI in prefixed form, if a declared prefix covers it.
    ///
    /// `https://blackbagtech.com/aff4/Schema#APFSContainerImage` becomes
    /// `bbt:APFSContainerImage`. Returns [`None`] when no binding matches, so a
    /// caller shows the full IRI rather than a bare local name — an extension
    /// term stripped of its namespace is indistinguishable from a standard one.
    ///
    /// The longest matching namespace wins, so overlapping bindings resolve to
    /// the most specific.
    #[must_use]
    pub fn to_prefixed(&self, iri: &str) -> Option<String> {
        self.prefixes
            .iter()
            .filter(|(_, namespace)| iri.starts_with(namespace.as_str()))
            .max_by_key(|(_, namespace)| namespace.len())
            .map(|(name, namespace)| format!("{name}:{}", &iri[namespace.len()..]))
    }

    /// Deviations recorded while parsing.
    #[must_use]
    pub fn deviations(&self) -> &[Deviation] {
        &self.deviations
    }

    /// Record a deviation found by a caller inspecting this graph.
    pub fn record(&mut self, deviation: Deviation) {
        self.deviations.push(deviation);
    }
}

/// The deviation recorded when pyaff4 byte-range IRIs had to be escaped to parse.
///
/// Shared by [`Graph::parse`] and [`Graph::stream_by_subject`] so the two forms
/// cannot report the escaping differently.
fn byte_range_deviation(locus: &Locus, escaped_ranges: usize) -> Deviation {
    Deviation::new(
        locus.clone(),
        DeviationKind::ByteRangeArn,
        format!(
            "{escaped_ranges} IRI(s) use pyaff4's byte-range extension \
             aff4://<uuid>[start:length]; square brackets are not permitted \
             in RDF IRIs, so these were percent-encoded to parse and \
             restored afterwards"
        ),
    )
}

/// Parse prepared Turtle into [`Statement`]s, interning subjects and predicates.
///
/// The single decoding path behind both [`Graph::parse`] and
/// [`Graph::stream_by_subject`]. Kept as one iterator rather than duplicated so
/// the streaming form cannot decode a literal, unescape an IRI, or skip a blank
/// node differently from the retained form — a divergence there would make
/// `conformance` and `info` disagree about the same container.
///
/// Blank nodes are skipped: they carry no ARN, cannot be addressed by the
/// summary, and none appear in the corpus.
fn parse_statements<'a>(
    prepared: &'a [u8],
    locus: &'a Locus,
) -> impl Iterator<Item = Result<Statement>> + 'a {
    // Shared copies of subject and predicate IRIs. A subject recurs once per
    // triple about it and a predicate is one of about a dozen terms, so this
    // replaces ~15.1M allocations with ~1.01M at a million objects.
    let mut pool: HashMap<Box<str>, Arc<str>> = HashMap::new();
    let intern = move |text: &str, pool: &mut HashMap<Box<str>, Arc<str>>| -> Arc<str> {
        if let Some(shared) = pool.get(text) {
            return Arc::clone(shared);
        }
        let shared: Arc<str> = Arc::from(text);
        pool.insert(Box::from(text), Arc::clone(&shared));
        shared
    };

    TurtleParser::new()
        .for_reader(prepared)
        .filter_map(move |result| {
            let triple = match result {
                Ok(triple) => triple,
                Err(e) => {
                    return Some(Err(Error::malformed(
                        locus.clone(),
                        format!("information.turtle is not valid Turtle: {e}"),
                    )));
                }
            };

            let subject = match triple.subject {
                NamedOrBlankNode::NamedNode(node) => {
                    intern(&unescape_byte_range(node.as_str()), &mut pool)
                }
                NamedOrBlankNode::BlankNode(_) => return None,
            };

            let predicate = intern(triple.predicate.as_str(), &mut pool);

            let object = match triple.object {
                Term::NamedNode(node) => Value::Iri {
                    iri: unescape_byte_range(node.as_str()),
                },
                Term::Literal(literal) => Value::Literal {
                    lexical: literal.value().to_string(),
                    // oxrdf reports xsd:string for untyped literals; keep that
                    // distinction visible so `size 8688` (xsd:integer) can be
                    // told from `"8688"^^xsd:long`.
                    datatype: Some(intern(literal.datatype().as_str(), &mut pool)),
                },
                Term::BlankNode(_) => return None,
            };

            Some(Ok(Statement {
                subject,
                predicate,
                object,
            }))
        })
}

/// XSD datatypes accepted as an unsigned integer.
const NUMERIC_DATATYPES: [&str; 7] = [
    "long",
    "int",
    "unsignedLong",
    "unsignedInt",
    "short",
    "byte",
    "integer",
];

/// Read a literal as an unsigned integer, recording any deviation.
///
/// - `xsd:long`, `xsd:int`, `xsd:integer`, `xsd:unsignedLong` — accepted.
/// - Untyped (`xsd:integer` after Turtle's implicit typing) — accepted
///   silently. See below.
/// - Anything else, or an unparseable lexical form — [`None`] plus
///   [`DeviationKind::UnexpectedDatatype`]. Never a guess.
#[must_use]
pub fn as_u64(value: &Value, locus: &Locus, deviations: &mut Vec<Deviation>) -> Option<u64> {
    let Value::Literal { lexical, datatype } = value else {
        return None;
    };

    let local = datatype.as_deref().and_then(|d| d.strip_prefix(XSD));
    if !local.is_some_and(|name| NUMERIC_DATATYPES.contains(&name)) {
        deviations.push(Deviation::new(
            locus.clone(),
            DeviationKind::UnexpectedDatatype,
            format!(
                "expected a numeric datatype but found {}",
                datatype.as_deref().unwrap_or("none")
            ),
        ));
        return None;
    }

    let Ok(number) = lexical.parse() else {
        deviations.push(Deviation::new(
            locus.clone(),
            DeviationKind::UnexpectedDatatype,
            format!("{lexical:?} is not a non-negative integer"),
        ));
        return None;
    };
    Some(number)
}

/// Read a literal as a timestamp, keeping its lexical form.
///
/// The value is never reformatted: reserialising a timestamp is a lossy
/// conversion of something that may be quoted in a report.
///
/// `xsd:dateTime` and the lowercase `xsd:datetime` are both accepted silently.
/// The lowercase spelling is pyaff4's logical writer's, and appears 44 times in
/// the corpus — every occurrence in the three AFF4-L containers, none in a
/// physical one. It no longer raises [`DeviationKind::NonstandardDatatype`]:
/// the lexical form is preserved verbatim either way, so no reading of the
/// evidence turns on the spelling — the same test applied to untyped
/// integers.
#[must_use]
pub fn as_timestamp(
    value: &Value,
    locus: &Locus,
    deviations: &mut Vec<Deviation>,
) -> Option<String> {
    let Value::Literal { lexical, datatype } = value else {
        return None;
    };

    match datatype.as_deref().and_then(|d| d.strip_prefix(XSD)) {
        // Only these two spellings. A blanket case-insensitive compare would
        // also accept `DATETIME` and `DaTeTiMe`, which no writer emits and
        // which would be worth reporting if one ever did.
        Some("dateTime" | "datetime") => {}
        other => {
            deviations.push(Deviation::new(
                locus.clone(),
                DeviationKind::UnexpectedDatatype,
                format!(
                    "expected a timestamp but found datatype {}",
                    other.unwrap_or("none")
                ),
            ));
            return None;
        }
    }

    Some(lexical.clone())
}

/// Percent-encode bracketed byte-range suffixes so `oxttl` accepts the IRI.
///
/// Only brackets *inside* an IRI (`<…>`) are touched; Turtle uses `[` and `]`
/// for blank-node syntax elsewhere. The whole suffix is encoded, not just the
/// delimiters — see the module documentation for why partial escaping fails.
///
/// Returns the rewritten source and how many suffixes were escaped.
#[must_use]
pub fn escape_byte_ranges(source: &str) -> (Cow<'_, str>, usize) {
    // A source with no bracket of either kind carries neither a byte-range ARN
    // nor a filename that needs one escaped, so there is nothing to do and the
    // input can be handed on borrowed. This is the ordinary
    // case: across the reference corpus only `broken-dedupe.aff4` uses the
    // extension, and no container this project writes does.
    //
    // The copy this avoids is the size of the whole metadata segment. At a
    // million described objects that is 0.75 GB allocated, filled, and then
    // held alongside the original for the length of the parse — see
    // docs/RDF-scalability.md.
    if !source.contains(['[', ']', '"']) {
        return (Cow::Borrowed(source), 0);
    }

    let mut out = String::with_capacity(source.len());
    let mut rest = source;
    let mut count = 0usize;

    while let Some(open) = rest.find(['[', ']', '"']) {
        // Look back over everything consumed so far, not just the current
        // `rest`. The loop stops at every quote, so on a statement carrying
        // literals — which is nearly all of them, `originalFileName` alone
        // puts one on each — `rest` has already advanced past the `<` that
        // opens the IRI by the time a later character in it is reached.
        // Measuring only within `rest` then read "outside an IRI" for a
        // character plainly inside one, and the escape was skipped.
        let consumed = source.len() - rest.len();
        let before = &source[..consumed + open];
        // Inside an IRI when the nearest '<' comes after the nearest '>'.
        let inside_iri = match (before.rfind('<'), before.rfind('>')) {
            (Some(lt), Some(gt)) => lt > gt,
            (Some(_), None) => true,
            _ => false,
        };

        // Bounded to the IRI that holds the bracket. A Slice Map closes inside
        // its own `<...>`; a filename containing a bare `[` does not, and an
        // unbounded search then matched a `]` in some later statement and
        // percent-encoded everything between — angle brackets, newlines and
        // following subjects alike — collapsing them into one huge IRI. A real
        // `/Library` acquisition produced a 364 MiB IRI that way and died on
        // the parser's 16 MiB token buffer.
        //
        // A newline bounds it too: an IRI cannot span lines, so a `]` beyond
        // one was never part of this IRI whatever the writer intended.
        let limit = rest[open..].find(['>', '\n']).unwrap_or(rest.len() - open);
        // A quote is never part of a byte range and is illegal in an IRI, so
        // it is escaped wherever it appears inside one. Outside an IRI it is
        // a literal's delimiter and must be left exactly as written.
        if rest.as_bytes().get(open) == Some(&b'"') {
            use std::fmt::Write as _;
            out.push_str(&rest[..open]);
            if inside_iri {
                let _ = write!(out, "%{:02X}", b'"');
            } else {
                out.push('"');
            }
            rest = &rest[open + 1..];
            continue;
        }

        // A closing bracket reached first is a filename's: a byte range always
        // opens before it closes. Escape it in place and move on.
        if rest.as_bytes().get(open) == Some(&b']') {
            use std::fmt::Write as _;
            out.push_str(&rest[..open]);
            if inside_iri {
                let _ = write!(out, "%{:02X}", b']');
            } else {
                out.push(']');
            }
            rest = &rest[open + 1..];
            continue;
        }

        let Some(close_offset) = rest[open..open + limit].find(']') else {
            // No closing bracket in this IRI: this is a filename's bracket,
            // not a byte range. It is still invalid in an `IRIREF`, so escape
            // the one character and carry on. Containers written before the
            // writer escaped these hold evidence, and one man page named `[.1`
            // would otherwise make the whole file unreadable. `Arn::parse`
            // decodes the escape, so nothing downstream sees a difference.
            use std::fmt::Write as _;
            out.push_str(&rest[..open]);
            if inside_iri {
                let _ = write!(out, "%{:02X}", b'[');
            } else {
                out.push('[');
            }
            rest = &rest[open + 1..];
            continue;
        };
        let close = open + close_offset;

        if inside_iri {
            use std::fmt::Write as _;
            out.push_str(&rest[..open]);
            for byte in rest[open..=close].bytes() {
                // Writing to a String is infallible; the crate denies unwrap.
                let _ = write!(out, "%{byte:02X}");
            }
            count += 1;
        } else {
            out.push_str(&rest[..=close]);
        }
        rest = &rest[close + 1..];
    }

    out.push_str(rest);
    (Cow::Owned(out), count)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn locus() -> Locus {
        Locus::new("/evidence/test.aff4").segment("information.turtle")
    }

    const STD_PREFIXES: &str = "@prefix aff4: <http://aff4.org/Schema#> .\n\
                                @prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\
                                @prefix xsd: <http://www.w3.org/2001/XMLSchema#> .\n";

    fn parse(body: &str) -> Graph {
        Graph::parse(format!("{STD_PREFIXES}{body}").as_bytes(), &locus()).unwrap()
    }

    #[test]
    fn parses_subjects_predicates_and_objects() {
        let g = parse(
            "<aff4://abc> a aff4:ImageStream ;\n  aff4:size \"3964928\"^^xsd:long ;\n  aff4:stored <aff4://vol> .\n",
        );
        assert_eq!(g.len(), 3);
        assert_eq!(
            g.subjects().iter().map(|s| &**s).collect::<Vec<_>>(),
            ["aff4://abc"]
        );
        assert_eq!(
            g.object("aff4://abc", "http://aff4.org/Schema#size")
                .unwrap()
                .lexical(),
            "3964928"
        );
        assert_eq!(
            g.object("aff4://abc", "http://aff4.org/Schema#stored")
                .unwrap()
                .as_iri(),
            Some("aff4://vol")
        );
    }

    /// v1.0a §2.1 mandates multiple rdf:type values; collapsing to one would
    /// discard information the standard requires.
    #[test]
    fn keeps_every_rdf_type() {
        let g = parse("<aff4://img> a aff4:DiskImage, aff4:ContiguousImage, aff4:Image .\n");
        let mut types = g.types("aff4://img");
        types.sort_unstable();
        assert_eq!(
            types,
            [
                "http://aff4.org/Schema#ContiguousImage",
                "http://aff4.org/Schema#DiskImage",
                "http://aff4.org/Schema#Image",
            ]
        );
    }

    #[test]
    fn finds_subjects_by_type() {
        let g = parse(
            "<aff4://a> a aff4:ImageStream .\n\
             <aff4://b> a aff4:Map .\n\
             <aff4://c> a aff4:ImageStream .\n",
        );
        assert_eq!(
            g.subjects_of_type("http://aff4.org/Schema#ImageStream"),
            ["aff4://a", "aff4://c"]
        );
    }

    /// Output must be stable across runs; a reshuffling summary is hard to diff.
    #[test]
    fn subject_order_follows_first_appearance() {
        let g =
            parse("<aff4://z> a aff4:Map .\n<aff4://a> a aff4:Map .\n<aff4://z> aff4:size 1 .\n");
        assert_eq!(
            g.subjects().iter().map(|s| &**s).collect::<Vec<_>>(),
            ["aff4://z", "aff4://a"]
        );
    }

    /// A predicate may repeat (aff4:hash carries MD5 and SHA1 on one subject).
    #[test]
    fn multi_valued_predicates_are_all_returned() {
        let g = parse("<aff4://s> aff4:hash \"aa\"^^aff4:MD5, \"bb\"^^aff4:SHA1 .\n");
        let hashes = g.objects("aff4://s", "http://aff4.org/Schema#hash");
        assert_eq!(hashes.len(), 2);
        assert!(
            g.object("aff4://s", "http://aff4.org/Schema#hash")
                .is_none(),
            "object() must decline when the predicate is multi-valued"
        );
    }

    // --- byte-range ARNs -------------------------------------------------

    /// The construct from `broken-dedupe.aff4`, which plain oxttl rejects.
    #[test]
    fn parses_pyaff4_byte_range_arns() {
        let g = parse(
            "<aff4://sub> aff4:dataStream <aff4://6a1e6a1a-8d78-43c7-bd5a-b5d800e4d552[0x4f8000:0x8000]> .\n",
        );
        assert_eq!(g.len(), 1);
        let target = g
            .object("aff4://sub", "http://aff4.org/Schema#dataStream")
            .unwrap();
        assert_eq!(
            target.as_iri(),
            Some("aff4://6a1e6a1a-8d78-43c7-bd5a-b5d800e4d552[0x4f8000:0x8000]"),
            "the lexical form must survive the escape/unescape round trip"
        );
    }

    /// A bracket in a filename must be escaped, not left to break the parse.
    ///
    /// The writer escapes these now, but containers written before it did are
    /// on disk and still hold evidence. A raw `[` is invalid in an `IRIREF`,
    /// so `oxttl` rejects the statement and the whole container becomes
    /// unreadable over one man page named `[.1`.
    ///
    /// Escaping it here costs nothing — `Arn::parse` decodes the escape back —
    /// and turns an unreadable container into a readable one.
    #[test]
    fn a_filename_bracket_is_escaped_rather_than_left_to_fail() {
        let source = "<aff4://v//usr/man/[.1> a <http://x#F> .\n";
        let (prepared, _) = escape_byte_ranges(source);
        assert!(
            !prepared.contains("/[.1"),
            "a raw bracket must not reach the parser:\n{prepared}"
        );
        assert!(
            prepared.contains("%5B.1"),
            "the bracket must be escaped in place:\n{prepared}"
        );
        // And the statement is otherwise untouched.
        assert!(prepared.ends_with("> a <http://x#F> .\n"), "{prepared}");

        // It must parse, and the subject must decode back to the real name.
        let graph = Graph::parse(prepared.as_bytes(), &Locus::new("x")).unwrap();
        let subjects = graph.subjects();
        assert!(
            subjects.iter().any(|s| s.contains("%5B.1")),
            "got {subjects:?}"
        );
    }

    /// A quote inside an IRI is escaped; a quote delimiting a literal is not.
    ///
    /// `IRIREF` excludes `"`, and AFF4-L 2019 §3.2 does not name it, so
    /// `About "Convert" Scripts.scpt` in `/Library` produced an unparseable
    /// subject. Escaping it must not touch the quotes that delimit literals —
    /// `originalFileName` is a quoted string on almost every statement, so a
    /// pass that escaped those would corrupt the whole graph rather than fix
    /// one name.
    #[test]
    fn a_quote_is_escaped_inside_an_iri_and_left_alone_in_a_literal() {
        let (iri, _) = escape_byte_ranges("<aff4://v//a\"b.scpt> a <http://x#F> .\n");
        assert!(iri.contains("a%22b.scpt"), "{iri}");

        let literal = "<aff4://v//x> <http://p> \"a literal\" .\n";
        let (out, _) = escape_byte_ranges(literal);
        assert_eq!(out, literal, "a literal's delimiters must survive verbatim");

        // Both together, which is the shape every real statement has.
        let mixed = "<aff4://v//a\"b> <http://p> \"name\" .\n";
        let (out, _) = escape_byte_ranges(mixed);
        assert!(out.contains("a%22b"), "{out}");
        assert!(out.contains("\"name\""), "{out}");
        assert!(Graph::parse(out.as_bytes(), &Locus::new("x")).is_ok());
    }

    /// A preceding literal must not hide that a later character is in an IRI.
    ///
    /// The scan stops at every quote, so a statement carrying literals — and
    /// `originalFileName` puts one on nearly every subject — advances past the
    /// `<` that opens a following IRI. Judging "inside an IRI" from the
    /// remaining text alone then said no, and the escape was skipped: a real
    /// `/Library` container still failed to parse after the quote handling was
    /// added, on exactly this shape.
    #[test]
    fn a_preceding_literal_does_not_hide_a_later_iri() {
        let source = concat!(
            "<aff4://v//dir>\n",
            "        aff4:originalFileName \"/Library/Scripts\"^^xsd:string ;\n",
            "        aff4:child <aff4://v//About%20\"Convert\"%20Scripts.scpt> .\n"
        );
        let (prepared, _) = escape_byte_ranges(source);
        assert!(
            prepared.contains("About%20%22Convert%22%20Scripts.scpt"),
            "the IRI's quotes must be escaped despite the literal before it:\n{prepared}"
        );
        assert!(
            prepared.contains("\"/Library/Scripts\"^^xsd:string"),
            "the literal itself must be untouched:\n{prepared}"
        );
    }

    /// An unclosed `[` must not consume the statements after it.
    ///
    /// `escape_byte_ranges` assumed a `[` inside an IRI always has its `]` in
    /// the same IRI — true of a Slice Map, false of a filename. Searching
    /// forward without a bound, a bare `[` matched a `]` thousands of
    /// characters later and percent-encoded everything between: closing
    /// angle brackets, newlines and following subjects all became `%3E`,
    /// `%0A`, `%3C`, collapsing many statements into one enormous IRI.
    ///
    /// On a real `/Library` acquisition that turned 185 MB of metadata into
    /// 440 MB containing a single 364 MiB IRI, and the parse died on its
    /// 16 MiB token buffer — an error that named a size limit while the cause
    /// was a runaway rewrite.
    ///
    /// The writer now escapes brackets, so this input should not arise from
    /// this tool; a container from another writer still must not detonate.
    #[test]
    fn an_unclosed_bracket_does_not_swallow_later_statements() {
        let source = concat!(
            "<aff4://v//usr/man/[.1> a <http://x#F> .\n",
            "<aff4://v//b.txt> a <http://x#F> .\n",
            "<aff4://v//c[0x0:0x10]> a <http://x#F> .\n"
        );
        let (prepared, _) = escape_byte_ranges(source);

        assert!(
            prepared.len() < source.len() * 2,
            "the rewrite must not balloon: {} -> {}",
            source.len(),
            prepared.len()
        );
        // The statements after the bare bracket must survive intact.
        assert!(
            prepared.contains("<aff4://v//b.txt> a <http://x#F> ."),
            "a following statement was consumed:\n{prepared}"
        );
        // A real Slice Map suffix is still escaped whole, which is the point of
        // the pass: the suffix is encoded byte by byte, brackets included, so
        // `oxttl` sees no bracket and no lowercase `0x` to reject.
        assert!(
            prepared.contains("c%5B") && prepared.ends_with("%5D> a <http://x#F> .\n"),
            "the byte-range suffix must still be escaped:\n{prepared}"
        );
        assert!(
            !prepared.contains("c[0x0:0x10]"),
            "the raw suffix must not survive:\n{prepared}"
        );
    }

    /// A percent-escape that belongs to the *path* must survive parsing.
    ///
    /// `escape_byte_ranges` exists to smuggle pyaff4's `[0x0:0x400]` suffix
    /// past a conformant Turtle parser, and the unescape on the way out was
    /// undoing it. Applied to the whole IRI it also undid escapes the ARN
    /// legitimately carries: AFF4-L 2019 §3.2 encodes the forbidden `>` as `%3E`,
    /// and the segment name keeps that escape, so decoding it here produced a
    /// subject whose `member_name` matched nothing in the archive.
    ///
    /// Measured on a real acquisition: `0002 LFO>pick pad.pst` was written
    /// correctly and then declined at verification as "names no data stream",
    /// and skipped by `export`, because the parsed subject and the stored
    /// member disagreed about one character.
    #[test]
    fn a_path_escape_is_not_decoded_when_parsing_a_subject() {
        let turtle = concat!(
            "<aff4://11111111-2222-3333-4444-555555555555//tmp/a%3Eb.pst>\n",
            "    <http://aff4.org/Schema#size> \"7\"^^",
            "<http://www.w3.org/2001/XMLSchema#long> .\n"
        );
        let graph = Graph::parse(turtle.as_bytes(), &Locus::new("x")).unwrap();
        let subjects = graph.subjects();
        assert!(
            subjects.iter().any(|s| s.contains("a%3Eb.pst")),
            "the %3E must survive, got {subjects:?}"
        );
    }

    #[test]
    fn byte_range_arns_raise_a_deviation() {
        let g = parse("<aff4://s> aff4:dataStream <aff4://x[0x0:0x10]> .\n");
        assert!(
            g.deviations()
                .iter()
                .any(|d| d.kind == DeviationKind::ByteRangeArn),
            "a non-standard IRI form must be reported, not silently accepted"
        );
    }

    /// Escaping must be confined to IRIs; `[` also begins Turtle blank nodes.
    #[test]
    fn escaping_leaves_brackets_outside_iris_alone() {
        let (out, n) = escape_byte_ranges("<http://a[1:2]> \"text [not an iri]\" .");
        assert_eq!(n, 1);
        // Every byte of the suffix is encoded, so `1` becomes %31 and `:` %3A.
        assert!(out.contains("%5B%31%3A%32%5D"), "{out}");
        assert!(
            out.contains("[not an iri]"),
            "brackets in a literal must be untouched: {out}"
        );
    }

    #[test]
    fn escaping_is_a_no_op_without_byte_ranges() {
        let source = "<aff4://plain> a aff4:Map .";
        let (out, n) = escape_byte_ranges(source);
        assert_eq!(n, 0);
        assert_eq!(out, source);
    }

    /// Half-escaping fails: oxttl reads `%` plus two chars as an escape and
    /// requires uppercase hex, so `%5B0x…` chokes on the lowercase `x`.
    #[test]
    fn escapes_the_whole_suffix_not_just_the_brackets() {
        let (out, _) = escape_byte_ranges("<aff4://x[0x4f8000:0x8000]>");
        assert!(
            !out.contains("0x"),
            "the payload must be encoded too: {out}"
        );
        assert!(out.contains("%5B"), "{out}");
        assert!(out.contains("%5D"), "{out}");
    }

    // --- literal coercion ------------------------------------------------

    /// The Cellebrite case: a `bbt` vendor namespace alongside the AFF4 one.
    #[test]
    fn captures_every_prefix_binding() {
        let bindings = prefix_bindings(
            "@base <aff4://e2568fd4> .\n\
             @prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\
             @prefix aff4: <http://aff4.org/Schema#> .\n\
             @prefix bbt: <https://blackbagtech.com/aff4/Schema#> .\n",
        );

        assert_eq!(bindings.len(), 3, "{bindings:?}");
        assert_eq!(
            bindings
                .iter()
                .find(|(p, _)| p == "bbt")
                .map(|(_, i)| i.as_str()),
            Some("https://blackbagtech.com/aff4/Schema#")
        );
    }

    /// A vendor IRI must render prefixed, or an extension term is
    /// indistinguishable from a standard one once the namespace is stripped.
    #[test]
    fn renders_vendor_iris_in_prefixed_form() {
        let g = parse("<aff4://s> aff4:size 1 .\n");
        assert_eq!(
            g.to_prefixed("http://aff4.org/Schema#DiskImage").as_deref(),
            Some("aff4:DiskImage")
        );
        // An unbound namespace has no prefixed form, and must not be guessed.
        assert_eq!(g.to_prefixed("https://example.com/Other#Thing"), None);
    }

    /// The longest matching namespace wins, so overlapping bindings resolve to
    /// the most specific.
    #[test]
    fn the_most_specific_prefix_wins() {
        let bindings = vec![
            ("short".to_owned(), "http://example.com/".to_owned()),
            ("long".to_owned(), "http://example.com/deep/".to_owned()),
        ];
        let g = Graph {
            prefixes: bindings,
            ..Graph::default()
        };
        assert_eq!(
            g.to_prefixed("http://example.com/deep/Thing").as_deref(),
            Some("long:Thing")
        );
    }

    #[test]
    fn reads_typed_integers_without_complaint() {
        let g = parse("<aff4://s> aff4:size \"3964928\"^^xsd:long .\n");
        let value = g.object("aff4://s", "http://aff4.org/Schema#size").unwrap();
        let mut deviations = Vec::new();
        assert_eq!(as_u64(value, &locus(), &mut deviations), Some(3_964_928));
        assert!(deviations.is_empty());
    }

    /// `dream.aff4` writes `aff4:size 8688`. Turtle types a bare integer as `xsd:integer`, so
    /// the value is identical to `"8688"^^xsd:long` — accepted **silently**.
    ///
    /// This asserts the absence deliberately: it once produced a deviation, and
    /// on a container where every size is untyped that buried real findings.
    #[test]
    fn accepts_untyped_integers_silently() {
        let g = parse("<aff4://s> aff4:size 8688 .\n");
        let value = g.object("aff4://s", "http://aff4.org/Schema#size").unwrap();
        let mut deviations = Vec::new();
        assert_eq!(as_u64(value, &locus(), &mut deviations), Some(8688));
        assert!(
            deviations.is_empty(),
            "an untyped integer is a writer's style, not a finding: {deviations:#?}"
        );
    }

    /// The value must be identical whichever way it is written. That equality
    /// is *why* the deviation was dropped, so it is worth asserting.
    #[test]
    fn typed_and_untyped_integers_parse_identically() {
        let typed = parse("<aff4://s> aff4:size \"268435456\"^^xsd:long .\n");
        let untyped = parse("<aff4://s> aff4:size 268435456 .\n");

        let mut deviations = Vec::new();
        let a = as_u64(
            typed
                .object("aff4://s", "http://aff4.org/Schema#size")
                .unwrap(),
            &locus(),
            &mut deviations,
        );
        let b = as_u64(
            untyped
                .object("aff4://s", "http://aff4.org/Schema#size")
                .unwrap(),
            &locus(),
            &mut deviations,
        );

        assert_eq!(a, Some(268_435_456));
        assert_eq!(a, b);
        assert!(deviations.is_empty());
    }

    #[test]
    fn declines_a_non_numeric_datatype() {
        let g = parse("<aff4://s> aff4:size \"8688\"^^xsd:string .\n");
        let value = g.object("aff4://s", "http://aff4.org/Schema#size").unwrap();
        let mut deviations = Vec::new();
        assert_eq!(as_u64(value, &locus(), &mut deviations), None);
        assert_eq!(deviations[0].kind, DeviationKind::UnexpectedDatatype);
    }

    #[test]
    fn declines_an_iri_where_a_number_was_expected() {
        let g = parse("<aff4://s> aff4:size <aff4://not-a-number> .\n");
        let value = g.object("aff4://s", "http://aff4.org/Schema#size").unwrap();
        let mut deviations = Vec::new();
        assert_eq!(as_u64(value, &locus(), &mut deviations), None);
    }

    #[test]
    fn reads_correctly_typed_timestamps_silently() {
        let g = parse("<aff4://s> aff4:timestamp \"2016-12-07T03:40:14.127Z\"^^xsd:dateTime .\n");
        let value = g
            .object("aff4://s", "http://aff4.org/Schema#timestamp")
            .unwrap();
        let mut deviations = Vec::new();
        assert_eq!(
            as_timestamp(value, &locus(), &mut deviations).as_deref(),
            Some("2016-12-07T03:40:14.127Z")
        );
        assert!(deviations.is_empty());
    }

    /// Lowercase `xsd:datetime` appears 44 times in the corpus, outnumbering
    /// the correctly-spelled form. Both spellings are accepted in silence
    ///: the lexical form is preserved either way, so no
    /// reading of the evidence turns on the capital `T`.
    #[test]
    fn accepts_lowercase_datetime_without_a_deviation() {
        let g = parse("<aff4://s> aff4:birthTime \"2018-09-17T13:42:20+10:00\"^^xsd:datetime .\n");
        let value = g
            .object("aff4://s", "http://aff4.org/Schema#birthTime")
            .unwrap();
        let mut deviations = Vec::new();
        assert_eq!(
            as_timestamp(value, &locus(), &mut deviations).as_deref(),
            Some("2018-09-17T13:42:20+10:00"),
            "the lexical form must be preserved verbatim"
        );
        assert!(
            deviations.is_empty(),
            "the spelling is a writer's style, not a finding: {deviations:#?}"
        );
    }

    /// Tolerating the lowercase spelling must not turn into tolerating any
    /// spelling. A datatype that is neither of the two known forms is still an
    /// unexpected datatype, and the timestamp is refused rather than guessed.
    #[test]
    fn an_unrecognised_datetime_spelling_is_still_reported() {
        let g = parse("<aff4://s> aff4:birthTime \"2018-09-17T13:42:20+10:00\"^^xsd:DATETIME .\n");
        let value = g
            .object("aff4://s", "http://aff4.org/Schema#birthTime")
            .unwrap();
        let mut deviations = Vec::new();
        assert_eq!(as_timestamp(value, &locus(), &mut deviations), None);
        assert_eq!(deviations.len(), 1);
        assert_eq!(deviations[0].kind, DeviationKind::UnexpectedDatatype);
    }

    // --- failure modes ---------------------------------------------------

    #[test]
    fn invalid_turtle_is_malformed() {
        let err = Graph::parse(b"this is not turtle at all {{{", &locus()).unwrap_err();
        assert!(err.is_integrity_finding(), "{err}");
        assert!(err.to_string().contains("information.turtle"), "{err}");
    }

    #[test]
    fn an_empty_graph_is_valid() {
        let g = Graph::parse(STD_PREFIXES.as_bytes(), &locus()).unwrap();
        assert!(g.is_empty());
        assert_eq!(g.len(), 0);
        assert!(g.subjects().is_empty());
    }

    #[test]
    fn absent_subjects_and_predicates_yield_nothing() {
        let g = parse("<aff4://s> a aff4:Map .\n");
        assert!(g.statements_for("aff4://absent").is_empty());
        assert!(
            g.objects("aff4://s", "http://aff4.org/Schema#absent")
                .is_empty()
        );
        assert!(
            g.object("aff4://s", "http://aff4.org/Schema#absent")
                .is_none()
        );
        assert!(g.types("aff4://absent").is_empty());
    }

    /// The empty prefix binds to the volume ARN in `AFF4Std` containers.
    #[test]
    fn resolves_the_empty_volume_prefix() {
        let g = Graph::parse(
            b"@prefix : <aff4://685e15cc-d0fb-4dbc-ba47-48117fc77044> .\n\
              @prefix aff4: <http://aff4.org/Schema#> .\n\
              <aff4://s> aff4:stored : .\n",
            &locus(),
        )
        .unwrap();
        assert_eq!(
            g.object("aff4://s", "http://aff4.org/Schema#stored")
                .unwrap()
                .as_iri(),
            Some("aff4://685e15cc-d0fb-4dbc-ba47-48117fc77044")
        );
    }

    #[test]
    fn non_utf8_metadata_degrades_without_failing() {
        let mut bytes = STD_PREFIXES.as_bytes().to_vec();
        bytes.extend_from_slice(b"<aff4://s> aff4:notes \"bad\xffbyte\" .\n");
        let g = Graph::parse(&bytes, &locus()).unwrap();
        assert_eq!(g.len(), 1);
    }
}
