//! The conformance rule registry.

/// A normative document this project cites. Now citations consist of
/// document, clause, and test ordinal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Document {
    /// AFF4 Standard v1.0a (Schatz, rev. 2022). The base document.
    Aff4Standard10a,
    /// AFF4-L (Schatz, DFRWS USA 2019). Governs pyaff4-era logical constructs.
    Aff4LPaper2019,
    /// AFF4-L Standard v1.0-ALPHA (Schatz, Apple Inc., September 2026).
    Aff4LStandard10Alpha,
}

impl Document {
    /// Every document, for exhaustive iteration in tests and the renderer.
    pub const ALL: [Self; 3] = [
        Self::Aff4Standard10a,
        Self::Aff4LPaper2019,
        Self::Aff4LStandard10Alpha,
    ];

    /// The document's full name, as printed in a report.
    ///
    /// These strings are what `conformance` output contains today, so they are
    /// fixed: changing one changes every report and breaks the phase gate.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Aff4Standard10a => "AFF4 Specification 1.0a",
            Self::Aff4LPaper2019 => {
                "AFF4-L (Schatz, DFRWS USA 2019, Digital Investigation 29, S143-S149)"
            }
            Self::Aff4LStandard10Alpha => "AFF4-L Standard v1.0-ALPHA",
        }
    }

    /// A short identifier-safe name, used in rule IDs.
    #[must_use]
    pub const fn short_name(self) -> &'static str {
        match self {
            Self::Aff4Standard10a => "AFF4_V1_0A",
            Self::Aff4LPaper2019 => "AFF4L_PAPER_2019",
            Self::Aff4LStandard10Alpha => "AFF4L_V1_ALPHA",
        }
    }
}

impl std::fmt::Display for Document {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// A rule's identity: which document, which clause, and which requirement
/// within that clause.
///
/// The ordinal distinguishes multiple testable requirements stated in one
/// clause. It is assigned when the rule is declared and never reused, so a
/// rule ID that appears in an archived report keeps its meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub struct RuleId {
    /// The document that states the requirement.
    pub document: Document,
    /// The clause within it, with its section sign — e.g. v1.0a's `"§5.4"`.
    ///
    /// The document is [`Self::document`], so the stored clause is bare.
    ///
    /// Stored with the sign because that is the form a report prints, and
    /// callers require `&'static str`: adding a sign would need an allocation
    /// with nowhere to live, while stripping one is a borrow. The sentinel
    /// `"none"` marks a condition no clause legislates.
    pub clause: &'static str,
    /// Which requirement within the clause, starting at 1.
    pub ordinal: u16,
}

impl RuleId {
    /// Name a rule.
    #[must_use]
    pub const fn new(document: Document, clause: &'static str, ordinal: u16) -> Self {
        Self {
            document,
            clause,
            ordinal,
        }
    }

    /// The clause without its section sign, for use in a rule ID.
    ///
    /// Rule IDs stay ASCII so they can be grepped, typed, and used as
    /// identifiers; the section sign is presentation.
    #[must_use]
    pub fn clause_number(&self) -> &'static str {
        self.clause.strip_prefix('§').unwrap_or(self.clause)
    }
}

impl std::fmt::Display for RuleId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}/{}/{}",
            self.document.short_name(),
            self.clause_number(),
            self.ordinal
        )
    }
}

/// What the document demands. A property of the specification, fixed for the
/// life of the rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Requirement {
    /// The document requires it.
    Must,
    /// The document prohibits it.
    MustNot,
    /// The document recommends it.
    Should,
    /// The document recommends against it.
    ShouldNot,
    /// The document permits it.
    May,
}

impl Requirement {
    /// Rendered in the specification's own case, so a reader recognizes it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Must => "MUST",
            Self::MustNot => "MUST NOT",
            Self::Should => "SHOULD",
            Self::ShouldNot => "SHOULD NOT",
            Self::May => "MAY",
        }
    }
}

/// What aff4tools can currently do about a rule. Changes as phases land.
///
/// The distinction between the last two matters to a reader:
/// [`Self::NotImplemented`] is work this project has not done, while
/// [`Self::NotCheckable`] is a question the standard has not answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleState {
    /// A checker exists and runs.
    Detected,
    /// Declared, but no checker exists yet.
    NotImplemented,
    /// No checker can exist yet, because the requirement itself is unsettled.
    NotCheckable,
}

impl RuleState {
    /// Rendered for the generated catalog and the coverage block.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Detected => "detected",
            Self::NotImplemented => "not implemented",
            Self::NotCheckable => "not checkable",
        }
    }
}

/// Everything known about one conformance rule.
///
/// One declaration replaces what used to be five coordinated edits in
/// `error.rs`: a `DeviationKind` variant plus arms in `spec_section`,
/// `other_specification`, `is_routine`, and `Display`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct RuleInfo {
    /// Which document, clause, and requirement this is.
    pub id: RuleId,
    /// What the document demands.
    pub requirement: Requirement,
    /// What aff4tools can currently do about it.
    pub state: RuleState,
    /// A one-line statement of the requirement, in this project's own words.
    ///
    /// Written rather than quoted: transcribing the document would redistribute
    /// it and trigger its license terms. See the licensing boundary in
    /// `CLAUDE.md`.
    pub statement: &'static str,
    /// The deviation this rule raises when violated, where one exists.
    ///
    /// [`None`] for a rule that is declared but raises no deviation yet —
    /// every rule in the `NotImplemented` or `NotCheckable` state.
    pub kind: Option<crate::error::DeviationKind>,
    /// Whether this condition is one the format routinely produces.
    ///
    /// A routine deviation is worth recording but does not by itself mean the
    /// container is questionable, so `--strict` ignores it. Frequency alone
    /// does not make a condition routine: the test is whether it can affect
    /// interpretation.
    pub routine: bool,
}

/// Declare one conformance rule.
///
/// Every field is required, so adding a field to [`RuleInfo`] forces every
/// declaration to be revisited rather than silently defaulting.
#[macro_export]
macro_rules! declare_rule {
    (
        id: ($document:expr, $clause:literal, $ordinal:literal),
        requirement: $requirement:ident,
        state: $state:ident,
        statement: $statement:literal,
        kind: $kind:expr,
        routine: $routine:literal,
    ) => {
        $crate::rules::RuleInfo {
            id: $crate::rules::RuleId::new($document, $clause, $ordinal),
            requirement: $crate::rules::Requirement::$requirement,
            state: $crate::rules::RuleState::$state,
            statement: $statement,
            kind: $kind,
            routine: $routine,
        }
    };
}

// Declared below the macro rather than at the top of the file: a
// `macro_rules!` macro is only in scope textually after its definition, so
// `catalog` cannot see `declare_rule!` from above it.
mod catalog;
mod coverage;
mod render;

pub use coverage::Coverage;
pub use render::render_catalog;

/// Every declared rule, across all documents.
///
/// Looking a rule up by [`crate::error::DeviationKind`] alone is not enough
/// to cite it. Which document governs a container is decided by its
/// [`crate::lexicon::Generation`], not by the deviation that was raised, so a
/// citation needs both. The registry answers "what does this rule say"; the
/// generation answers "does that document apply here". They are separate
/// questions, and [`rules_for_generation`] answers the second.
///
/// So this function is the whole catalog and not a scoped view of it. A rule
/// it returns may cite a document that does not govern the container in hand:
/// a caller building a citation narrows by generation first.
#[must_use]
pub fn all_rules() -> &'static [RuleInfo] {
    // Concatenated at first use rather than as a const, because slice
    // concatenation is not a const operation.
    static ALL: std::sync::OnceLock<Vec<RuleInfo>> = std::sync::OnceLock::new();
    ALL.get_or_init(|| {
        let mut rules = Vec::new();
        rules.extend_from_slice(catalog::AFF4_V1_0A);
        rules.extend_from_slice(catalog::AFF4L_PAPER_2019);
        rules.extend_from_slice(catalog::AFF4L_V1_ALPHA);
        rules.extend_from_slice(catalog::UNLEGISLATED);
        rules
    })
}

/// Every rule in scope for a container of this generation.
///
/// Scope follows [`crate::lexicon::Generation::governing_spec`]: the base
/// document always, plus the layered document where one applies. A rule from a
/// document that does not govern the container is not merely unevaluated — it
/// never applied, and citing it would misstate what the container was required
/// to do.
pub fn rules_for_generation(
    generation: crate::lexicon::Generation,
) -> impl Iterator<Item = &'static RuleInfo> {
    let (base, layered) = generation.governing_spec();
    all_rules()
        .iter()
        .filter(move |rule| rule.id.document == base || Some(rule.id.document) == layered)
}

/// The rule a deviation kind belongs to.
///
/// [`None`] only if a kind was added without a declaration, which
/// `every_deviation_kind_has_exactly_one_rule` prevents.
///
/// This answers only "what does this rule say". Whether the document it cites
/// governs a given container is a separate question, decided by the
/// container's [`crate::lexicon::Generation`]; see the doc comment on
/// [`all_rules`]. Any citation built from this lookup must apply that gate
/// itself.
#[must_use]
pub fn rule_for_kind(kind: crate::error::DeviationKind) -> Option<&'static RuleInfo> {
    all_rules().iter().find(|rule| rule.kind == Some(kind))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The names are what an examiner reads in a report, so they are asserted
    /// exactly rather than merely being non-empty.
    #[test]
    fn documents_name_themselves_exactly() {
        assert_eq!(Document::Aff4Standard10a.name(), "AFF4 Specification 1.0a");
        assert_eq!(
            Document::Aff4LPaper2019.name(),
            "AFF4-L (Schatz, DFRWS USA 2019, Digital Investigation 29, S143-S149)"
        );
        assert_eq!(
            Document::Aff4LStandard10Alpha.name(),
            "AFF4-L Standard v1.0-ALPHA"
        );
    }

    /// Short names are for rule IDs, where the full name would be unusable.
    #[test]
    fn short_names_are_identifier_safe() {
        for document in Document::ALL {
            let short = document.short_name();
            assert!(!short.is_empty(), "{document:?}");
            assert!(
                short
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'),
                "{document:?} short name {short} must be usable in a rule ID"
            );
        }
    }

    #[test]
    fn rule_ids_render_as_the_documented_triple() {
        let id = RuleId::new(Document::Aff4LStandard10Alpha, "§6.1", 3);
        assert_eq!(id.to_string(), "AFF4L_V1_ALPHA/6.1/3");
    }

    /// The clause is stored with its section sign, because that is the form a
    /// report prints; the rule ID strips it so IDs stay ASCII.
    #[test]
    fn rule_ids_strip_the_section_sign() {
        let id = RuleId::new(Document::Aff4Standard10a, "§5.4", 1);
        assert_eq!(id.clause, "§5.4", "the stored clause keeps its sign");
        assert_eq!(id.clause_number(), "5.4");
        assert_eq!(id.to_string(), "AFF4_V1_0A/5.4/1");
        assert!(!id.to_string().contains('§'), "{id}");
    }

    /// The sentinel for a condition no clause legislates must survive stripping.
    #[test]
    fn the_unlegislated_sentinel_is_left_alone() {
        let id = RuleId::new(Document::Aff4Standard10a, "none", 1);
        assert_eq!(id.clause_number(), "none");
        assert_eq!(id.to_string(), "AFF4_V1_0A/none/1");
    }

    /// The three states mean different things to a reader and must not collapse.
    #[test]
    fn rule_states_are_distinct() {
        assert_eq!(RuleState::Detected.as_str(), "detected");
        assert_eq!(RuleState::NotImplemented.as_str(), "not implemented");
        assert_eq!(RuleState::NotCheckable.as_str(), "not checkable");
    }

    #[test]
    fn requirement_levels_render_in_spec_case() {
        assert_eq!(Requirement::Must.as_str(), "MUST");
        assert_eq!(Requirement::Should.as_str(), "SHOULD");
        assert_eq!(Requirement::May.as_str(), "MAY");
    }

    #[test]
    fn a_declared_rule_carries_all_its_metadata() {
        const SAMPLE: RuleInfo = declare_rule! {
            id: (Document::Aff4Standard10a, "§5.4", 1),
            requirement: Must,
            state: Detected,
            statement: "The ZIP comment carries the volume ARN starting at offset 0.",
            kind: Some(crate::error::DeviationKind::NulPaddedComment),
            routine: true,
        };

        assert_eq!(SAMPLE.id.to_string(), "AFF4_V1_0A/5.4/1");
        assert_eq!(SAMPLE.requirement, Requirement::Must);
        assert_eq!(SAMPLE.state, RuleState::Detected);
        assert!(SAMPLE.statement.ends_with('.'), "statements are sentences");
        const { assert!(SAMPLE.routine) };
    }

    /// Every deviation kind the crate can emit must have exactly one rule.
    ///
    /// Without this, a kind could be raised at a call site while the registry
    /// knows nothing about it, and the report would cite no document at all.
    #[test]
    fn every_deviation_kind_has_exactly_one_rule() {
        use crate::error::DeviationKind as K;

        // Every variant, listed explicitly. A new variant added without a rule
        // fails to compile here, which is the point.
        let all_kinds = [
            K::UntypedNumericLiteral,
            K::NonstandardDatatype,
            K::UnexpectedDatatype,
            K::DigestLengthMismatch,
            K::NulPaddedComment,
            K::InconsistentVolumeArn,
            K::ByteRangeArn,
            K::ContentAddressedSubject,
            K::MapGap,
            K::DuplicateSegmentName,
            K::MissingZipSegmentType,
            K::ExternalReference,
            K::ConflictingStreamValue,
            K::DanglingReference,
            K::UndeclaredObject,
        ];

        for kind in all_kinds {
            let matches: Vec<_> = all_rules()
                .iter()
                .filter(|rule| rule.kind == Some(kind))
                .collect();
            assert_eq!(
                matches.len(),
                1,
                "{kind:?} must have exactly one rule, found {}",
                matches.len()
            );
        }
    }

    /// Rule IDs are the stable name a report may quote, so collisions are fatal.
    #[test]
    fn rule_ids_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for rule in all_rules() {
            assert!(
                seen.insert(rule.id.to_string()),
                "duplicate rule ID {}",
                rule.id
            );
        }
    }

    /// A rule claiming to be checked must have a deviation to raise. Without this,
    /// a rule could sit in the Detected state with no way to report anything.
    #[test]
    fn detected_rules_have_a_deviation_kind() {
        for rule in all_rules() {
            if rule.state == RuleState::Detected {
                assert!(
                    rule.kind.is_some(),
                    "{} is Detected but raises no deviation",
                    rule.id
                );
            }
        }
    }

    /// Statements are written prose, not transcriptions, and a reader needs them
    /// to be complete sentences.
    #[test]
    fn statements_are_sentences() {
        for rule in all_rules() {
            assert!(
                rule.statement.ends_with('.'),
                "{} statement must end with a period",
                rule.id
            );
            assert!(
                rule.statement.len() > 20,
                "{} statement is too short to be useful",
                rule.id
            );
        }
    }

    /// The catalog is a complete inventory of the standard, not only of what is
    /// implemented. A rule missing here would understate the coverage gap.
    #[test]
    fn the_alpha_standard_is_fully_declared() {
        let alpha: Vec<_> = all_rules()
            .iter()
            .filter(|rule| rule.id.document == Document::Aff4LStandard10Alpha)
            .collect();
        assert_eq!(
            alpha.len(),
            24,
            "the standard states 24 normative requirements; {} are declared",
            alpha.len()
        );
    }

    /// Nothing from the new standard is checkable yet: the rules are declared
    /// and reported as coverage gaps. A `Detected` rule here would claim a
    /// checker that does not exist.
    #[test]
    fn no_alpha_rule_claims_to_be_checked() {
        for rule in all_rules() {
            if rule.id.document == Document::Aff4LStandard10Alpha {
                assert_ne!(
                    rule.state,
                    RuleState::Detected,
                    "{} claims a checker, but none is implemented",
                    rule.id
                );
            }
        }
    }

    /// A container is measured against the documents that govern it, and no
    /// others. Citing a rule from a document that does not apply would misstate
    /// what the container was required to do.
    #[test]
    fn rules_in_scope_follow_the_governing_documents() {
        use crate::lexicon::Generation;

        let standard: Vec<_> = rules_for_generation(Generation::Standard10).collect();
        assert!(
            standard
                .iter()
                .all(|r| r.id.document == Document::Aff4Standard10a),
            "a v1.0 container is governed by v1.0a alone"
        );

        let logical: Vec<_> = rules_for_generation(Generation::PyAff4Logical).collect();
        assert!(
            logical
                .iter()
                .any(|r| r.id.document == Document::Aff4LPaper2019),
            "a v1.1 container is also governed by the 2019 paper"
        );
        assert!(
            !logical
                .iter()
                .any(|r| r.id.document == Document::Aff4LStandard10Alpha),
            "the new standard does not govern a pyaff4-era container"
        );

        let alpha: Vec<_> = rules_for_generation(Generation::Aff4L10).collect();
        assert!(
            alpha
                .iter()
                .any(|r| r.id.document == Document::Aff4LStandard10Alpha),
            "a v2.1 container is governed by the new standard"
        );
        assert!(
            alpha
                .iter()
                .any(|r| r.id.document == Document::Aff4Standard10a),
            "v2.1 is base-plus-delta: v1.0a still governs the container layer"
        );
    }
}
