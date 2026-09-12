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
/// The distinction between [`Self::NotImplemented`] and [`Self::NotCheckable`]
/// matters to a reader: the first is work this project has not done, while the
/// second is a question the standard has not answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleState {
    /// A violation refuses the container rather than producing a deviation.
    ///
    /// The check runs, but outside the conformance pass: a failure is
    /// `Error::Malformed` (exit 5) or `Error::Unsupported` (exit 6), and the
    /// container never opens. v1.0a §1.1's reader obligation is the case —
    /// `container.rs`'s `identify` refuses a missing or invalid version before
    /// any rule is evaluated.
    ///
    /// Distinct from [`Self::Detected`], where the container opens and a
    /// departure becomes a deviation in the report. An `Enforced` rule is not a
    /// coverage gap: the check exists.
    Enforced,
    /// A checker exists and runs during the conformance pass.
    Detected,
    /// Satisfied by construction, so there is nothing for a checker to find.
    ///
    /// Two ways a rule reaches this state:
    ///
    /// - **The rule binds aff4tools, not the container.** A reader- or
    ///   writer-side obligation is satisfied by how this build behaves —
    ///   AFF4-L v1.0-ALPHA §4.1's leave to accept either namespace is one.
    /// - **It is a permission, and nothing can violate it.** A `MAY` is met by
    ///   taking it or leaving it.
    ///
    /// Reporting such a rule as an unevaluated gap would misstate the
    /// position: the rule is met, and no container could show otherwise.
    ///
    /// Distinct from [`Self::Detected`], which is a claim about the container
    /// ("checked, and here is the result"); `Honored` is a claim about
    /// aff4tools ("this holds without checking"). Distinct too from
    /// [`Self::NotCheckable`], which is a question the standard has not
    /// answered.
    Honored,
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
            Self::Enforced => "enforced",
            Self::Detected => "detected",
            Self::Honored => "honored",
            Self::NotImplemented => "not implemented",
            Self::NotCheckable => "not checkable",
        }
    }
}

/// What a rule binds: the content of a container, or the behavior of a reader
/// or a writer.
///
/// This is a separate axis from [`RuleState`]. `Governs` says *whose* obligation
/// the rule is; `RuleState` says what aff4tools does about it. Only a container
/// rule can be [`RuleState::Detected`], because only a container carries a
/// departure a conformance pass could observe; reader and writer rules bind
/// aff4tools' own behavior, so they are `Enforced`, `Honored`, or
/// `NotImplemented`, never `Detected`.
///
/// A rule may govern more than one actor, but only when its state is the same
/// for each. Where a clause binds a writer and a reader with different states
/// or requirement levels, it becomes separate rules — as AFF4-L v1.0-ALPHA §4.4
/// and AFF4-L v1.0-ALPHA §6.3.1 do.
///
/// A [`RuleState::NotCheckable`] rule carries no governed actor: the question
/// the standard leaves open includes whom it binds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Governs {
    /// The content of a container.
    Container,
    /// The behavior of a reader.
    Reader,
    /// The behavior of a writer.
    Writer,
    /// Both a reader and a writer, at the same state and requirement level.
    ReaderWriter,
    /// No actor, for a [`RuleState::NotCheckable`] rule.
    Unsettled,
}

impl Governs {
    /// Rendered for the generated catalog, matching the proposal's spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Container => "container",
            Self::Reader => "reader",
            Self::Writer => "writer",
            Self::ReaderWriter => "reader, writer",
            Self::Unsettled => "-",
        }
    }

    /// Whether this governance includes a reader.
    #[must_use]
    pub fn includes_reader(self) -> bool {
        matches!(self, Self::Reader | Self::ReaderWriter)
    }

    /// Whether this governance names a reader or a writer, as opposed to the
    /// container or nothing.
    #[must_use]
    pub fn is_behavioral(self) -> bool {
        matches!(self, Self::Reader | Self::Writer | Self::ReaderWriter)
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
    /// Whose obligation the rule is: the container, a reader, or a writer.
    pub governs: Governs,
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
        governs: $governs:ident,
        statement: $statement:literal,
        kind: $kind:expr,
        routine: $routine:literal,
    ) => {
        $crate::rules::RuleInfo {
            id: $crate::rules::RuleId::new($document, $clause, $ordinal),
            requirement: $crate::rules::Requirement::$requirement,
            state: $crate::rules::RuleState::$state,
            governs: $crate::rules::Governs::$governs,
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

    /// The five states mean different things to a reader and must not collapse.
    #[test]
    fn rule_states_are_distinct() {
        assert_eq!(RuleState::Enforced.as_str(), "enforced");
        assert_eq!(RuleState::Detected.as_str(), "detected");
        assert_eq!(RuleState::Honored.as_str(), "honored");
        assert_eq!(RuleState::NotImplemented.as_str(), "not implemented");
        assert_eq!(RuleState::NotCheckable.as_str(), "not checkable");
    }

    /// The governed actors render as the catalog spells them.
    #[test]
    fn governs_renders_each_actor() {
        assert_eq!(Governs::Container.as_str(), "container");
        assert_eq!(Governs::Reader.as_str(), "reader");
        assert_eq!(Governs::Writer.as_str(), "writer");
        assert_eq!(Governs::ReaderWriter.as_str(), "reader, writer");
        assert_eq!(Governs::Unsettled.as_str(), "-");
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
            governs: Container,
            statement: "The ZIP comment carries the volume ARN starting at offset 0.",
            kind: Some(crate::error::DeviationKind::NulPaddedComment),
            routine: true,
        };

        assert_eq!(SAMPLE.id.to_string(), "AFF4_V1_0A/5.4/1");
        assert_eq!(SAMPLE.requirement, Requirement::Must);
        assert_eq!(SAMPLE.state, RuleState::Detected);
        assert_eq!(SAMPLE.governs, Governs::Container);
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
            K::MissingMapSegmentDigest,
            K::ExternalReference,
            K::ConflictingStreamValue,
            K::DanglingReference,
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

    /// A `Detected` rule states a claim about container content — it must
    /// govern exactly the container, because only a container carries a
    /// departure a conformance pass could observe. This is the invariant that
    /// forces "which clause requires this of a container?" for every checker.
    #[test]
    fn detected_rules_govern_the_container() {
        for rule in all_rules() {
            if rule.state == RuleState::Detected {
                assert_eq!(
                    rule.governs,
                    Governs::Container,
                    "{} is Detected but does not govern the container",
                    rule.id
                );
            }
        }
    }

    /// An `Enforced` rule refuses the container, which is reader behavior, so
    /// its governance must include the reader.
    #[test]
    fn enforced_rules_govern_a_reader() {
        for rule in all_rules() {
            if rule.state == RuleState::Enforced {
                assert!(
                    rule.governs.includes_reader(),
                    "{} is Enforced but does not govern a reader",
                    rule.id
                );
            }
        }
    }

    /// A rule that binds a reader or a writer describes aff4tools' behavior, not
    /// a container's content, so it can carry no deviation kind — a
    /// `DeviationKind` is a departure a container makes.
    #[test]
    fn behavioral_rules_raise_no_deviation() {
        for rule in all_rules() {
            if rule.governs.is_behavioral() {
                assert!(
                    rule.kind.is_none(),
                    "{} governs a reader or writer but names a deviation kind",
                    rule.id
                );
            }
        }
    }

    /// A `NotCheckable` rule leaves open what a container must do, which
    /// includes whom the requirement binds, so it names no governed actor. Every
    /// other state does name one.
    #[test]
    fn only_not_checkable_rules_are_unsettled() {
        for rule in all_rules() {
            let unsettled = rule.governs == Governs::Unsettled;
            let not_checkable = rule.state == RuleState::NotCheckable;
            assert_eq!(
                unsettled, not_checkable,
                "{} pairs governs={:?} with state={:?}; `-` is for not-checkable rules alone",
                rule.id, rule.governs, rule.state
            );
        }
    }

    /// Rules are declared in the order the document reads: a section's own
    /// rules first, then its subsections in numerical order. This is the order
    /// the generated catalog and the `info`/`conformance` reports present, so a
    /// rule slipped in out of place would read wrongly to an examiner.
    ///
    /// The `none/*` sentinel rules are excluded — they legislate nothing and
    /// are appended after the document's real rules by design.
    #[test]
    fn rules_are_declared_in_reading_order() {
        // A clause's sort key: its dotted section parts, then the ordinal.
        // Section 6 sorts before 6.1; 6.1 before 6.2; each before 6.3.1. A
        // shorter prefix sorts first, which is exactly "the section's own rules
        // before its subsections".
        //
        // A part may carry a trailing letter — clause 9a exists in one standard,
        // sorting after 9 and before 10. Each part is therefore split into its
        // leading number and any letter suffix, so 9 < 9a < 10 all hold.
        fn part_key(part: &str) -> (u32, &str) {
            let split = part
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(part.len());
            let (digits, suffix) = part.split_at(split);
            // Every real clause part begins with a digit; a `0` for a malformed
            // one would sort it first and trip the ordering assertion loudly,
            // which is the behavior a test wants over a panic in a closure.
            (digits.parse::<u32>().unwrap_or(0), suffix)
        }

        fn key(rule: &RuleInfo) -> (Vec<(u32, &'static str)>, u16) {
            let parts = rule.id.clause_number().split('.').map(part_key).collect();
            (parts, rule.id.ordinal)
        }

        for document in Document::ALL {
            let keys: Vec<_> = all_rules()
                .iter()
                .filter(|r| r.id.document == document && r.id.clause != "none")
                .map(key)
                .collect();
            for window in keys.windows(2) {
                assert!(
                    window[0] <= window[1],
                    "{document:?} rules are out of reading order: {:?} precedes {:?}",
                    window[0],
                    window[1]
                );
            }
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
            51,
            "every normative statement in the standard needs a declaration; {} are declared",
            alpha.len()
        );
    }

    /// A rule that claims a checker must carry the deviation that checker
    /// raises.
    ///
    /// This is what keeps a declared rule and an implemented one from drifting
    /// apart: `Detected` without a kind would be a rule the report counts as
    /// evaluated that nothing evaluates.
    ///
    /// The converse does not hold, and deliberately so. Two v1.0a rules carry
    /// a kind while sitting in `NotImplemented`, because the condition is
    /// recognized but reporting it was judged to bury real findings — see
    /// [`crate::error::DeviationKind::UntypedNumericLiteral`]. Their variants
    /// are public and appear in archived reports, so the kinds stay.
    #[test]
    fn a_detected_rule_carries_the_deviation_it_raises() {
        for rule in all_rules() {
            if rule.state == RuleState::Detected {
                assert!(
                    rule.kind.is_some(),
                    "{} claims a checker but names no deviation for it to raise",
                    rule.id
                );
            }
        }
    }

    /// Which rules of the new standard have checkers. The rest are still
    /// coverage gaps. Naming them here means a later phase cannot quietly
    /// claim a rule it has not written.
    ///
    /// Phase 3 moved the four identity rules of AFF4-L v1.0-ALPHA (§1.1, §1.2
    /// and AFF4-L v1.0-ALPHA §2); Phase 4 moved that standard's five §5 name-normalization
    /// rules; Phase 6 moved its two AFF4-L v1.0-ALPHA §10.1 metadata-integrity
    /// rules. Phase 8 added no checker: AFF4-L v1.0-ALPHA §4.2 and §4.3 state
    /// no requirement to check, only a vocabulary to draw on. Phase 9a added
    /// the two AFF4-L v1.0-ALPHA §6 dispatch rules, which are what a container
    /// owes a reader that selects a storage form by declared type. Phase 9c
    /// added the AFF4-L v1.0-ALPHA §6.2 size cap, the standard's only
    /// prohibition. A later pass added the three AFF4-L v1.0-ALPHA §6.1
    /// requirements, read from the ZIP central directory rather than the
    /// metadata, and the AFF4-L v1.0-ALPHA §8 naming scheme, read from the file
    /// names beside the container.
    #[test]
    fn the_checked_rules_of_the_alpha_standard_are_these() {
        let detected: Vec<String> = all_rules()
            .iter()
            .filter(|rule| {
                rule.id.document == Document::Aff4LStandard10Alpha
                    && rule.state == RuleState::Detected
            })
            .map(|rule| rule.id.to_string())
            .collect();
        assert_eq!(
            detected,
            [
                "AFF4L_V1_ALPHA/1.1/1",
                "AFF4L_V1_ALPHA/1.1/2",
                "AFF4L_V1_ALPHA/1.2/1",
                "AFF4L_V1_ALPHA/2/1",
                "AFF4L_V1_ALPHA/4.1/1",
                "AFF4L_V1_ALPHA/5/1",
                "AFF4L_V1_ALPHA/5/2",
                "AFF4L_V1_ALPHA/5/3",
                "AFF4L_V1_ALPHA/5/4",
                "AFF4L_V1_ALPHA/5/5",
                "AFF4L_V1_ALPHA/6/3",
                "AFF4L_V1_ALPHA/6/4",
                "AFF4L_V1_ALPHA/6.1/1",
                "AFF4L_V1_ALPHA/6.1/2",
                "AFF4L_V1_ALPHA/6.1/3",
                "AFF4L_V1_ALPHA/6.2/1",
                "AFF4L_V1_ALPHA/8/1",
                "AFF4L_V1_ALPHA/10.1/1",
                "AFF4L_V1_ALPHA/10.1/2",
            ]
        );
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
