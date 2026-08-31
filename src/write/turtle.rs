//! Serializing the metadata graph to Turtle.
//!
//! Output follows the shape Evimetry produces: `@prefix` declarations, triples
//! grouped one block per subject, predicate objects aligned in a column, and
//! repeated predicates collapsed onto a single line. A fully-expanded form is
//! also valid, but costs roughly three times the bytes per triple and reads
//! worst of the shapes measured.
//!
//! Abbreviation is conservative: an IRI whose local part is not a bare name
//! falls back to `<full-iri>`, because a metadata segment no reader can parse
//! would be a far worse outcome than a long line.
//!
//! Every literal carries an explicit datatype. `aff4:size 8688` and
//! `"8688"^^xsd:long` parse identically, but the untyped form is what corpus
//! writers emit and what CLAUDE.md's strict-output rule forbids.
//!
//! Note the datatype spellings here are case-correct: `xsd:dateTime`, not
//! pyaff4's `xsd:datetime`, which is not an XSD type. This crate *reads* both
//! spellings in silence but must only ever *write* the
//! correct one — the leniency is strictly one-directional.

use std::fmt::Write as _;

/// The XSD `long` datatype IRI, for sizes and counts.
pub const XSD_LONG: &str = "http://www.w3.org/2001/XMLSchema#long";

/// The XSD `int` datatype IRI.
pub const XSD_INT: &str = "http://www.w3.org/2001/XMLSchema#int";

/// The XSD `string` datatype IRI.
pub const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";

/// The XSD `dateTime` datatype IRI — capital `T`, unlike pyaff4's output.
pub const XSD_DATE_TIME: &str = "http://www.w3.org/2001/XMLSchema#dateTime";

/// The `rdf:type` predicate IRI.
pub const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";

/// The object of a triple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TurtleTerm {
    /// An IRI, written `<...>`.
    Iri(String),
    /// A literal with an explicit datatype IRI.
    TypedLiteral {
        /// The lexical form, exactly as it should appear.
        lexical: String,
        /// The datatype IRI.
        datatype: String,
    },
}

impl TurtleTerm {
    /// An IRI object.
    #[must_use]
    pub fn iri(value: impl Into<String>) -> Self {
        Self::Iri(value.into())
    }

    /// A typed literal object.
    #[must_use]
    pub fn typed(lexical: impl Into<String>, datatype: impl Into<String>) -> Self {
        Self::TypedLiteral {
            lexical: lexical.into(),
            datatype: datatype.into(),
        }
    }

    /// An `xsd:long` literal, the form AFF4 uses for sizes.
    #[must_use]
    pub fn long(value: u64) -> Self {
        Self::typed(value.to_string(), XSD_LONG)
    }

    /// An `xsd:int` literal.
    #[must_use]
    pub fn int(value: u32) -> Self {
        Self::typed(value.to_string(), XSD_INT)
    }

    /// An `xsd:string` literal.
    #[must_use]
    pub fn string(value: impl Into<String>) -> Self {
        Self::typed(value, XSD_STRING)
    }
}

/// Escape a literal's lexical form for Turtle.
fn escape_literal(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str(r"\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str(r"\n"),
            '\r' => out.push_str(r"\r"),
            '\t' => out.push_str(r"\t"),
            other => out.push(other),
        }
    }
    out
}

/// The AFF4 schema namespace.
const AFF4_NS: &str = "http://aff4.org/Schema#";

/// The RDF namespace.
const RDF_NS: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#";

/// The XSD namespace.
const XSD_NS: &str = "http://www.w3.org/2001/XMLSchema#";

/// Column the predicate's object starts at within a subject block.
///
/// Evimetry aligns objects this way and pyaff4 does not; the aligned form is
/// measurably easier to scan down. Wide enough for the longest AFF4 predicate
/// in use (`acquisitionCompletionState`, 27 characters plus the `aff4:`
/// prefix) without wrapping the common ones.
const OBJECT_COLUMN: usize = 32;

/// Indent for each predicate line inside a subject block.
const INDENT: &str = "        ";

/// Accumulates triples and renders them as Turtle.
///
/// Rendering follows the shape Evimetry produces.
/// # Scaling
///
/// Both `add` and `serialize` are linear in the number of triples, and must
/// stay that way. A quadratic `add` that linear-scans `order` per triple, or a
/// `serialize` that rescans every triple once per subject, measured 0.13 s at
/// 2,000 files and 6.88 s at 16,000 on a synthetic tree — about 3.2× per
/// doubling, extrapolating to roughly **30 hours at 2 million files**. A
/// logical acquisition of a large volume is exactly the case that
/// makes triple count grow with file count, and §6 of the AFF4-L paper warns
/// this becomes problematic in the millions.
#[derive(Debug, Default)]
pub struct TurtleWriter {
    triples: Vec<(String, String, TurtleTerm)>,
    /// The volume ARN, bound to the base prefix `:` when set.
    volume: Option<String>,
    /// Subject render order, by first `add` for each subject.
    order: Vec<String>,
    /// Subject → its index in `order`. Membership test for `add`, and the
    /// bucket key for `serialize`; without it both are quadratic.
    subject_index: std::collections::HashMap<String, usize>,
    /// Positions in `triples` belonging to each subject, parallel to `order`.
    ///
    /// Built as triples arrive rather than by scanning at serialize time, which
    /// is what keeps rendering linear.
    by_subject: Vec<Vec<usize>>,
}

impl TurtleWriter {
    /// An empty graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind the volume ARN to the base prefix `:`.
    ///
    /// Every object in a volume carries `aff4:stored`, making the volume ARN
    /// the most repeated IRI in the file. Evimetry writes `aff4:stored :` for
    /// exactly this reason.
    pub fn set_volume(&mut self, volume_arn: &str) {
        self.volume = Some(volume_arn.to_owned());
    }

    /// Add one triple.
    ///
    /// Subjects keep first-mention order, so two containers over the same
    /// evidence render identically.
    pub fn add(&mut self, subject: &str, predicate: &str, object: TurtleTerm) {
        let position = self.triples.len();
        let slot = if let Some(slot) = self.subject_index.get(subject) {
            *slot
        } else {
            let slot = self.order.len();
            self.order.push(subject.to_owned());
            self.subject_index.insert(subject.to_owned(), slot);
            self.by_subject.push(Vec::new());
            slot
        };
        self.by_subject[slot].push(position);
        self.triples
            .push((subject.to_owned(), predicate.to_owned(), object));
    }

    /// Add an `rdf:type` triple.
    pub fn add_type(&mut self, subject: &str, type_iri: &str) {
        self.add(subject, RDF_TYPE, TurtleTerm::iri(type_iri));
    }

    /// How many triples the graph holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.triples.len()
    }

    /// Whether any triple has been added.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.triples.is_empty()
    }

    /// Abbreviate an IRI against the bound prefixes, or return it in brackets.
    fn shorten(&self, iri: &str) -> String {
        if let Some(volume) = &self.volume
            && iri == volume
        {
            return ":".to_owned();
        }
        for (prefix, namespace) in [("aff4", AFF4_NS), ("rdf", RDF_NS), ("xsd", XSD_NS)] {
            if let Some(local) = iri.strip_prefix(namespace) {
                // Only abbreviate when the local part is a bare name; anything
                // else could produce a token Turtle would not parse back.
                if is_pname_local(local) {
                    return format!("{prefix}:{local}");
                }
            }
        }
        format!("<{iri}>")
    }

    /// Render one object term with prefixes applied.
    fn render_term(&self, term: &TurtleTerm) -> String {
        match term {
            TurtleTerm::Iri(iri) => self.shorten(iri),
            TurtleTerm::TypedLiteral { lexical, datatype } => {
                format!(
                    "\"{}\"^^{}",
                    escape_literal(lexical),
                    self.shorten(datatype)
                )
            }
        }
    }

    /// Render the graph as prefixed, subject-grouped Turtle.
    ///
    /// Subjects appear in first-mention order, which the writer controls, so
    /// two containers over the same evidence differ only where the evidence
    /// does. Neither reference implementation is deterministic here.
    ///
    /// **First-mention order is a contract, not a presentation choice.** A
    /// split part lists its own stream before its siblings' stubs, and
    /// `FusedImage::prepare` uses that grouping to tell which stream a volume
    /// owns. Emitting subjects in any other order — sorted, for instance —
    /// leaves it unable to trust the layout, so it declines the fused
    /// traversal and every image is read twice: once per part's stream, once
    /// more through the map. Verification stays correct and takes about twice
    /// as long. `tests/split_acquire.rs` holds the guard.
    #[must_use]
    pub fn serialize(&self) -> String {
        let mut out = String::new();

        if let Some(volume) = &self.volume {
            let _ = writeln!(out, "@prefix :      <{volume}> .");
        }
        let _ = writeln!(out, "@prefix rdf:   <{RDF_NS}> .");
        let _ = writeln!(out, "@prefix xsd:   <{XSD_NS}> .");
        let _ = writeln!(out, "@prefix aff4:  <{AFF4_NS}> .");

        for (slot, subject) in self.order.iter().enumerate() {
            let _ = writeln!(out);
            let _ = writeln!(out, "{}", self.shorten(subject));

            // Group by predicate, preserving first-seen order, so repeated
            // predicates collapse onto one line: `aff4:hash "a" , "b" ;`.
            //
            // Only this subject's own triples are visited. Scanning all of them
            // per subject is what made serialization quadratic.
            let mut predicates: Vec<(&str, Vec<String>)> = Vec::new();
            for &position in &self.by_subject[slot] {
                let (_, predicate, object) = &self.triples[position];
                let rendered = self.render_term(object);
                if let Some(entry) = predicates.iter_mut().find(|(p, _)| *p == predicate) {
                    entry.1.push(rendered);
                } else {
                    predicates.push((predicate, vec![rendered]));
                }
            }

            // `rdf:type` renders as Turtle's `a` keyword and leads the block,
            // matching both references and reading as a definition.
            predicates.sort_by_key(|(p, _)| usize::from(*p != RDF_TYPE));

            for (index, (predicate, objects)) in predicates.iter().enumerate() {
                let name = if *predicate == RDF_TYPE {
                    "a".to_owned()
                } else {
                    self.shorten(predicate)
                };
                let terminator = if index + 1 == predicates.len() {
                    '.'
                } else {
                    ';'
                };
                let padding = OBJECT_COLUMN.saturating_sub(name.len()).max(1);
                let _ = writeln!(
                    out,
                    "{INDENT}{name}{:padding$}{} {terminator}",
                    "",
                    objects.join(" , "),
                    padding = padding
                );
            }
        }

        out
    }
}

/// Whether `local` is safe as the local part of a prefixed name.
///
/// Turtle's `PN_LOCAL` grammar is broader than this, but a conservative test is
/// the right call: abbreviating something unparseable would produce a metadata
/// segment no reader could load. Anything rejected here falls back to the
/// unambiguous `<full-iri>` form.
fn is_pname_local(local: &str) -> bool {
    !local.is_empty()
        && local
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && local
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const SUBJECT: &str = "aff4://11111111-2222-3333-4444-555555555555/data";

    /// **Scaling regression.** Both `add` and `serialize` must stay linear in
    /// the triple count.
    ///
    /// A quadratic `add` (linear-scanning `order` per triple) or `serialize`
    /// (rescanning every triple per subject) extrapolates to roughly 30 hours
    /// for a 2-million-file logical acquisition. No other test catches it,
    /// because every other test graph holds a handful of subjects.
    ///
    /// Measured by **growth ratio**, not wall-clock: rendering a graph with 8×
    /// the subjects must cost close to 8× the time, not 64×. A structural check
    /// that the index merely *exists* is not enough — it would still pass if
    /// `serialize` ignored the index and rescanned every triple, which is
    /// exactly the defect. The ratio is generous (< 24× for an 8× input) so it
    /// fails only on a genuine complexity change, never on machine noise.
    #[test]
    fn subject_lookup_and_rendering_stay_linear() {
        // Times `add` and `serialize` together: both were quadratic, and timing
        // only one leaves the other free to regress.
        fn build_and_render(subjects: usize) -> std::time::Duration {
            let start = std::time::Instant::now();
            let mut w = TurtleWriter::new();
            for i in 0..subjects {
                for p in 0..8 {
                    w.add(
                        &format!("aff4://vol//path/to/file{i}.txt"),
                        &format!("{AFF4_NS}p{p}"),
                        TurtleTerm::typed("v", XSD_STRING),
                    );
                }
            }
            let rendered = w.serialize();
            let elapsed = start.elapsed();
            assert!(!rendered.is_empty());
            elapsed
        }

        // Warm up so the first allocation does not land inside a measurement.
        let _ = build_and_render(500);

        let small = build_and_render(1_000);
        let large = build_and_render(8_000);

        // The quadratic form cost ~64x here; the linear form costs ~8x.
        assert!(
            large.as_secs_f64() < small.as_secs_f64() * 24.0,
            "rendering 8x the subjects took {large:?} against {small:?} for the \
             smaller graph — that growth is superlinear, so serialize is \
             rescanning all triples per subject again"
        );
    }

    /// The per-subject index must partition the triples exactly: every triple
    /// in exactly one bucket, and each bucket holding only its own subject's.
    #[test]
    fn the_subject_index_partitions_every_triple() {
        let mut w = TurtleWriter::new();
        let subjects = 50;
        let per_subject = 8;

        for i in 0..subjects {
            for p in 0..per_subject {
                w.add(
                    &format!("aff4://vol//path/to/file{i}.txt"),
                    &format!("{AFF4_NS}p{p}"),
                    TurtleTerm::typed("v", XSD_STRING),
                );
            }
        }

        assert_eq!(w.by_subject.len(), subjects, "one bucket per subject");
        assert_eq!(
            w.subject_index.len(),
            subjects,
            "index covers every subject"
        );
        let visited: usize = w.by_subject.iter().map(Vec::len).sum();
        assert_eq!(visited, w.triples.len(), "no triple missed or duplicated");
        for (slot, positions) in w.by_subject.iter().enumerate() {
            assert_eq!(positions.len(), per_subject);
            for &p in positions {
                assert_eq!(
                    w.triples[p].0, w.order[slot],
                    "a bucket must hold only its own subject's triples"
                );
            }
        }
    }

    /// Subjects must keep first-mention order once indexed, so two containers
    /// over the same evidence still render identically.
    #[test]
    fn the_subject_index_preserves_first_mention_order() {
        let mut w = TurtleWriter::new();
        for s in ["aff4://vol/c", "aff4://vol/a", "aff4://vol/b"] {
            w.add(
                s,
                &format!("{AFF4_NS}size"),
                TurtleTerm::typed("1", XSD_LONG),
            );
        }
        // Revisiting a subject must not move it.
        w.add(
            "aff4://vol/c",
            &format!("{AFF4_NS}other"),
            TurtleTerm::typed("2", XSD_LONG),
        );
        assert_eq!(w.order, ["aff4://vol/c", "aff4://vol/a", "aff4://vol/b"]);
        assert_eq!(w.by_subject[0].len(), 2, "both of c's triples land in c");
    }

    /// Output must be parseable by the same reader this crate uses, and must
    /// type its literals: an untyped integer is a deviation this crate records
    /// on read and must never write.
    #[test]
    fn serialized_turtle_round_trips_through_the_reader() {
        let mut w = TurtleWriter::new();
        w.add(
            SUBJECT,
            "http://aff4.org/Schema#size",
            TurtleTerm::long(8688),
        );
        w.add_type(SUBJECT, "http://aff4.org/Schema#ImageStream");

        let text = w.serialize();
        assert!(text.contains("^^"), "literals must be typed: {text}");

        let locus = crate::error::Locus::new("/synthetic/information.turtle");
        let graph = crate::rdf::Graph::parse(text.as_bytes(), &locus)
            .expect("our own reader must parse what we write");
        let types = graph.types(SUBJECT);
        assert!(
            types.iter().any(|t| t.ends_with("ImageStream")),
            "type triple lost in round trip: {types:?}"
        );
    }

    /// A graph we write must produce **zero** deviations when read back. This
    /// is the strict-output rule made executable.
    #[test]
    fn our_own_output_records_no_deviations() {
        let mut w = TurtleWriter::new();
        w.add(
            SUBJECT,
            "http://aff4.org/Schema#size",
            TurtleTerm::long(8688),
        );
        w.add(
            SUBJECT,
            "http://aff4.org/Schema#birthTime",
            TurtleTerm::typed("2018-09-17T13:42:20+10:00", XSD_DATE_TIME),
        );
        w.add_type(SUBJECT, "http://aff4.org/Schema#ImageStream");

        let locus = crate::error::Locus::new("/synthetic/information.turtle");
        let graph = crate::rdf::Graph::parse(w.serialize().as_bytes(), &locus).unwrap();
        assert!(
            graph.deviations().is_empty(),
            "our output must be deviation-free: {:#?}",
            graph.deviations()
        );
    }

    /// The rendered form uses prefixes and groups by subject (§5.2.5).
    #[test]
    fn output_is_prefixed_and_grouped_by_subject() {
        let mut w = TurtleWriter::new();
        w.set_volume("aff4://11111111-2222-3333-4444-555555555555");
        w.add_type(SUBJECT, "http://aff4.org/Schema#ImageStream");
        w.add(
            SUBJECT,
            "http://aff4.org/Schema#size",
            TurtleTerm::long(8688),
        );
        w.add(
            SUBJECT,
            "http://aff4.org/Schema#stored",
            TurtleTerm::iri("aff4://11111111-2222-3333-4444-555555555555"),
        );

        let text = w.serialize();

        assert!(text.contains("@prefix aff4:"), "R1 prefixes:\n{text}");
        assert!(text.contains("aff4:size"), "R1 abbreviation:\n{text}");
        assert!(
            !text.contains("<http://aff4.org/Schema#size>"),
            "R1: no expanded IRI should remain:\n{text}"
        );
        assert!(text.contains("aff4:stored"), "predicate present:\n{text}");
        assert!(
            text.contains("aff4:stored") && text.contains(" : "),
            "R3 base prefix for the volume:\n{text}"
        );
        assert!(
            text.contains("        a "),
            "rdf:type renders as `a`:\n{text}"
        );

        // R2: the subject appears once, at the head of its block.
        let heads = text
            .lines()
            .filter(|l| l.starts_with('<') && l.ends_with('>'))
            .count();
        assert_eq!(heads, 1, "R2 subject stated once:\n{text}");
    }

    /// R5: repeated predicates collapse onto one line.
    #[test]
    fn repeated_predicates_collapse() {
        let mut w = TurtleWriter::new();
        w.add(
            SUBJECT,
            "http://aff4.org/Schema#hash",
            TurtleTerm::typed("aaa", "http://aff4.org/Schema#MD5"),
        );
        w.add(
            SUBJECT,
            "http://aff4.org/Schema#hash",
            TurtleTerm::typed("bbb", "http://aff4.org/Schema#SHA1"),
        );

        let text = w.serialize();
        assert_eq!(
            text.matches("aff4:hash").count(),
            1,
            "R5: one aff4:hash line carrying both values:\n{text}"
        );
        assert!(text.contains(" , "), "R5 object list:\n{text}");
    }

    /// R6: subject order is deterministic across runs.
    #[test]
    fn subject_order_is_deterministic() {
        let build = || {
            let mut w = TurtleWriter::new();
            w.set_volume("aff4://vol");
            for subject in ["aff4://c", "aff4://a", "aff4://b"] {
                w.add(subject, "http://aff4.org/Schema#size", TurtleTerm::long(1));
            }
            w.serialize()
        };
        assert_eq!(build(), build(), "R6: identical input, identical output");
    }

    /// The whole point: the new rendering must parse back to the same triples.
    #[test]
    fn the_prefixed_form_round_trips_through_the_reader() {
        let mut w = TurtleWriter::new();
        w.set_volume("aff4://11111111-2222-3333-4444-555555555555");
        w.add_type(SUBJECT, "http://aff4.org/Schema#ImageStream");
        w.add(
            SUBJECT,
            "http://aff4.org/Schema#size",
            TurtleTerm::long(8688),
        );
        w.add(
            SUBJECT,
            "http://aff4.org/Schema#chunkSize",
            TurtleTerm::int(32768),
        );
        w.add(
            SUBJECT,
            "http://aff4.org/Schema#stored",
            TurtleTerm::iri("aff4://11111111-2222-3333-4444-555555555555"),
        );
        w.add(
            SUBJECT,
            "http://aff4.org/Schema#hash",
            TurtleTerm::typed("abc", "http://aff4.org/Schema#MD5"),
        );

        let locus = crate::error::Locus::new("/synthetic/information.turtle");
        let graph = crate::rdf::Graph::parse(w.serialize().as_bytes(), &locus)
            .expect("the prefixed form must parse with our own reader");

        assert!(
            graph
                .types(SUBJECT)
                .iter()
                .any(|t| t.ends_with("ImageStream")),
            "type survived"
        );
        assert!(
            graph.deviations().is_empty(),
            "prefixed output must stay deviation-free: {:#?}",
            graph.deviations()
        );
    }

    /// An IRI whose local part is not a bare name falls back to `<...>` rather
    /// than producing a token Turtle cannot parse.
    #[test]
    fn unsafe_local_names_are_not_abbreviated() {
        let mut w = TurtleWriter::new();
        w.add(
            SUBJECT,
            "http://aff4.org/Schema#has/slash",
            TurtleTerm::long(1),
        );
        let text = w.serialize();
        assert!(
            text.contains("<http://aff4.org/Schema#has/slash>"),
            "an unsafe local name must stay expanded:\n{text}"
        );

        let locus = crate::error::Locus::new("/synthetic/information.turtle");
        crate::rdf::Graph::parse(text.as_bytes(), &locus)
            .expect("the fallback form must still parse");
    }

    /// Quotes, backslashes and newlines in a value must not break the syntax —
    /// a filename can contain any of them.
    #[test]
    fn literals_with_special_characters_survive() {
        let mut w = TurtleWriter::new();
        w.add(
            SUBJECT,
            "http://aff4.org/Schema#originalFileName",
            TurtleTerm::string("a \"quoted\"\\path\nwith\tcontrols"),
        );

        let locus = crate::error::Locus::new("/synthetic/information.turtle");
        let graph = crate::rdf::Graph::parse(w.serialize().as_bytes(), &locus)
            .expect("escaped literals must still parse");
        assert!(!graph.is_empty());
    }
}
