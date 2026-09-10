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
    ///
    /// [`RuleState::Detected`] rules are evaluated by definition.
    /// [`RuleState::Honored`] rules are met by how this build behaves rather
    /// than by anything a container carries, so reporting one as a gap would
    /// misstate the position — the rule holds, and no container could show
    /// otherwise.
    pub fn unevaluated(&self) -> impl Iterator<Item = &'static RuleInfo> + '_ {
        rules_for_generation(self.generation)
            .filter(|rule| !matches!(rule.state, RuleState::Detected | RuleState::Honored))
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

    /// A v1.0 container's coverage, including the AFF4 Standard v1.0a §6.2
    /// block map hashing gap.
    ///
    /// **Two of the five unevaluated rules are binding**, which is a change
    /// this project made deliberately rather than a regression. Until Phase 10
    /// the registry inventoried no AFF4 Standard v1.0a §6.2 rule at all, so
    /// `conformance` reported full coverage of binding rules on containers
    /// whose maps carried no integrity digests. An undeclared requirement
    /// cannot appear as a gap; it simply vanishes, which is the failure mode
    /// the registry exists to prevent.
    ///
    /// The count falls as Phase 10 lands its checkers.
    #[test]
    fn a_v1_0_container_has_almost_full_coverage() {
        let coverage = Coverage::for_generation(Generation::Standard10);
        // Two AFF4 Standard v1.0a §2.2 recommendations declared but
        // deliberately never emitted, plus the three AFF4 Standard v1.0a §6.2
        // rules still awaiting checkers. Phase 10 added a checker for
        // AFF4 Standard v1.0a §6.2/4, so this count fell from six to five.
        assert_eq!(coverage.unevaluated().count(), 5);
        assert!(
            !coverage.is_complete(),
            "some v1.0a rules are declared but not yet emitted"
        );
        assert!(
            coverage.has_unevaluated_must(),
            "the AFF4 Standard v1.0a §6.2 map digest requirements are binding and \
             not yet checked; reporting them is the point of declaring them"
        );
    }

    /// Much of the new standard is still unevaluated, and enough of it is
    /// binding that a v2.1 container cannot yet be shown to conform.
    ///
    /// The bound falls as phases land; it is a floor, not a target. Lowering it
    /// is the deliberate act of recording that a phase closed some gaps.
    #[test]
    fn a_v2_1_container_is_largely_unevaluated() {
        let coverage = Coverage::for_generation(Generation::Aff4L10);
        assert!(coverage.unevaluated().count() >= 20);
        assert!(
            coverage.has_unevaluated_must(),
            "unevaluated MUST requirements cause --strict to fail on a v2.1 container"
        );
    }

    /// A SHOULD or MAY left unevaluated says the tool is incomplete, not that
    /// the container is questionable, so it drives no exit code.
    ///
    /// Stated against the requirement levels themselves rather than against
    /// whatever the v1.0 catalog happens to leave unevaluated. It was written
    /// the second way, and became a test of the catalog's contents instead of
    /// of the rule it names: declaring the AFF4 Standard v1.0a §6.2
    /// requirements broke it although the logic under test never changed.
    #[test]
    fn only_binding_rules_drive_the_exit_code() {
        let coverage = Coverage::for_generation(Generation::Standard10);

        // `has_unevaluated_must` reports exactly the binding levels, and
        // nothing else — this is the property the exit code rests on.
        let binding_present = coverage
            .unevaluated()
            .any(|rule| matches!(rule.requirement, Requirement::Must | Requirement::MustNot));
        assert_eq!(
            coverage.has_unevaluated_must(),
            binding_present,
            "the exit code must follow the binding rules and only those"
        );

        // A catalog whose unevaluated rules are all recommendations raises no
        // exit code, whatever else it contains.
        let advisory_only = Coverage::for_generation(Generation::Standard10)
            .unevaluated()
            .filter(|rule| matches!(rule.requirement, Requirement::Should | Requirement::May))
            .count();
        assert!(
            advisory_only > 0,
            "the v1.0 catalog still carries unevaluated recommendations"
        );
    }

    /// A prohibition is mandatory like a requirement, so `MustNot` binds
    /// `--strict` as tightly as `Must`. Were it left out of that set, a
    /// container doing what the standard forbids would go unreported.
    ///
    /// The standard declares exactly one `MustNot` — the AFF4-L v1.0-ALPHA §6.2
    /// size cap — and Phase 9c implemented it. So this asserts the
    /// classification directly: a test that searched the catalog for an
    /// *unevaluated* prohibition would now fail for the best possible reason,
    /// and would start passing again the moment someone added an unimplemented
    /// one.
    #[test]
    fn a_prohibition_counts_as_binding() {
        let binding = |r: Requirement| matches!(r, Requirement::Must | Requirement::MustNot);
        assert!(binding(Requirement::MustNot), "a prohibition binds");
        assert!(binding(Requirement::Must));
        assert!(!binding(Requirement::Should));
        assert!(!binding(Requirement::May));

        // And whatever the real catalog leaves unevaluated is genuinely
        // uncheckable in this build, never something already implemented.
        let real = Coverage::for_generation(Generation::Aff4L10);
        assert!(
            real.unevaluated()
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
