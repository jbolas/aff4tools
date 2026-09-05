//! Renders the rule registry as markdown.
//!
//! This is the only place the catalog's format is decided. The output is
//! committed as `docs/conformance-rules.md`, and a test asserts the two match.

use std::fmt::Write as _;

use crate::rules::{Document, RuleState, all_rules};

/// Render the whole catalog: a section per document, a table per clause.
#[must_use]
pub fn render_catalog() -> String {
    let mut out = String::new();

    out.push_str("# Conformance rules\n\n");
    out.push_str(
        "This is a catalog of every AFF4 and AFF4-L specification rule that \
         `aff4tools conformance` knows about, generated from the rule\n\
         registry in `src/rules/catalog.rs`.\n\n\
         **This file is generated.** Edit the rule registry, not this document.\n\n",
    );

    out.push_str("## Rule states\n\n");
    out.push_str("| State | Meaning |\n|---|---|\n");
    out.push_str("| detected | A checker exists and runs. |\n");
    out.push_str(
        "| not implemented | Declared, but no checker exists yet. Reported as a coverage gap. |\n",
    );
    out.push_str(
        "| not checkable | No checker can exist yet, because the requirement itself is unsettled. |\n\n",
    );

    for document in Document::ALL {
        let rules: Vec<_> = all_rules()
            .iter()
            .filter(|rule| rule.id.document == document)
            .collect();
        if rules.is_empty() {
            continue;
        }

        let _ = writeln!(out, "## {}\n", document.name());
        out.push_str("| Rule | Level | State | Requirement |\n|---|---|---|---|\n");
        for rule in rules {
            let clause = if rule.id.clause == "none" {
                "not legislated"
            } else {
                rule.id.clause
            };
            let _ = writeln!(
                out,
                "| `{}` ({}) | {} | {} | {} |",
                rule.id,
                clause,
                rule.requirement.as_str(),
                rule.state.as_str(),
                rule.statement
            );
        }
        out.push('\n');
    }

    let detected = all_rules()
        .iter()
        .filter(|rule| rule.state == RuleState::Detected)
        .count();
    let _ = writeln!(
        out,
        "## Coverage\n\n{} of {} declared rules are checked.",
        detected,
        all_rules().len()
    );

    out
}
