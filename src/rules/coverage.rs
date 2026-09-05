//! What a conformance scan could not evaluate.
//!
//! A rule aff4tools cannot check says nothing about whether the container
//! departs from it. These are recorded separately from deviations, to keep
//! the two claims distinct. I.e., a deviation is an observed departure, and
//! an unevaluated rule is remains an unknown.

use crate::lexicon::Generation;
use crate::rules::{Requirement, RuleInfo, RuleState, rules_for_generation};

/// The rules in scope for a container that the scan did not evaluate.
#[derive(Debug, Clone)]
pub struct Coverage {
    generation: Generation,
}

impl Coverage {
    /// The coverage a scan of this generation achieves.
    ///
    /// Derived from the registry rather than accumulated during the scan:
    /// whether a rule has a checker is a property of the build, not of the
    /// container, so a scan cannot discover it.
    #[must_use]
    pub fn for_generation(generation: Generation) -> Self {
        Self { generation }
    }

    /// The generation whose rule set this coverage describes.
    #[must_use]
    pub fn generation(&self) -> Generation {
        self.generation
    }

    /// Rules in scope that no checker evaluated, in catalog order.
    pub fn unevaluated(&self) -> impl Iterator<Item = &'static RuleInfo> + '_ {
        rules_for_generation(self.generation).filter(|rule| rule.state != RuleState::Detected)
    }

    /// Whether any unevaluated rule is binding — a MUST or a MUST NOT.
    ///
    /// This is what `--strict` acts on. A SHOULD or MAY left unchecked means
    /// the tool is incomplete; an unchecked binding rule means the container
    /// was not shown to conform, which is what a strict caller is asking
    /// about. A prohibition binds as tightly as a requirement: doing what the
    /// standard forbids is as non-conformant as omitting what it demands, so
    /// [`Requirement::MustNot`] counts here alongside [`Requirement::Must`].
    #[must_use]
    pub fn has_unevaluated_must(&self) -> bool {
        self.unevaluated()
            .any(|rule| matches!(rule.requirement, Requirement::Must | Requirement::MustNot))
    }

    /// Whether every rule in scope was evaluated.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.unevaluated().next().is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexicon::Generation;

    /// A v1.0 container's rules are almost all implemented; the few that are
    /// not are recommendations, so the scan still shows conformance can be
    /// judged on every binding rule.
    #[test]
    fn a_v1_0_container_has_almost_full_coverage() {
        let coverage = Coverage::for_generation(Generation::Standard10);
        // Two v1.0a rules are declared but deliberately never emitted.
        assert_eq!(coverage.unevaluated().count(), 2);
        assert!(
            !coverage.is_complete(),
            "some v1.0a rules are declared but not yet emitted"
        );
        assert!(
            !coverage.has_unevaluated_must(),
            "every unevaluated v1.0a rule is a recommendation, not a binding rule"
        );
    }

    /// Every rule of the new standard is currently unevaluated, and most are
    /// binding, so a v2.1 container cannot be shown to conform.
    #[test]
    fn a_v2_1_container_is_almost_entirely_unevaluated() {
        let coverage = Coverage::for_generation(Generation::Aff4L10);
        assert!(coverage.unevaluated().count() >= 26);
        assert!(
            coverage.has_unevaluated_must(),
            "unevaluated MUST requirements cause --strict to fail on a v2.1 container"
        );
    }

    /// A SHOULD or MAY left unevaluated says the tool is incomplete, not that
    /// the container is questionable, so no exit code.
    #[test]
    fn only_binding_rules_drive_the_exit_code() {
        let coverage = Coverage::for_generation(Generation::Standard10);
        assert!(
            coverage
                .unevaluated()
                .all(|rule| !matches!(rule.requirement, Requirement::Must | Requirement::MustNot))
        );
        assert!(!coverage.has_unevaluated_must());
    }

    /// A prohibition is mandatory like a requirement. Were `MustNot` left
    /// out of the binding set, a container doing what the standard forbids
    /// would go unreported by `--strict`.
    #[test]
    fn a_prohibition_counts_as_binding() {
        let coverage = Coverage::for_generation(Generation::Aff4L10);
        let unevaluated: Vec<_> = coverage.unevaluated().collect();

        assert!(
            unevaluated
                .iter()
                .any(|rule| rule.requirement == Requirement::MustNot),
            "the v1.0-ALPHA rule set declares at least one unevaluated prohibition"
        );

        // Every rule reported unevaluated is genuinely uncheckable in this
        // build.
        assert!(
            unevaluated
                .iter()
                .all(|rule| rule.state != RuleState::Detected)
        );
    }

    /// Coverage is a property of the rule set, so a scope that layers a second
    /// document over the base is never narrower than the base alone.
    #[test]
    fn a_layered_scope_is_never_narrower_than_its_base() {
        let base = Coverage::for_generation(Generation::Standard10)
            .unevaluated()
            .count();
        for layered in [Generation::PyAff4Logical, Generation::Aff4L10] {
            assert!(
                Coverage::for_generation(layered).unevaluated().count() >= base,
                "{layered} layers a document over v1.0a, so it cannot evaluate more"
            );
        }
    }
}
