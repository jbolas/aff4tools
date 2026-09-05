//! The generated rule catalog must match the committed document exactly.
//!
//! Without this, `docs/conformance-rules.md` drifts from what's in the rule registry.

use aff4tools::rules;

#[test]
fn the_committed_catalog_matches_the_renderer() {
    let rendered = rules::render_catalog();
    let committed = std::fs::read_to_string("docs/conformance-rules.md")
        .expect("docs/conformance-rules.md must exist");

    if rendered == committed {
        return;
    }

    const FIX: &str = "Regenerate with: cargo run --example render-rules > docs/conformance-rules.md\n\
         If the committed wording is the one you want, copy it into the header \
         text in src/rules/render.rs instead, so the renderer produces it.";

    // Compare including line endings, so a difference in trailing whitespace or
    // a missing final newline is reported where it happens.
    let mut offset = 0;
    for (index, (a, b)) in rendered
        .split_inclusive('\n')
        .zip(committed.split_inclusive('\n'))
        .enumerate()
    {
        if a != b {
            panic!(
                "docs/conformance-rules.md differs from the renderer at line {}.\n\
                 rendered:  {a:?}\n\
                 committed: {b:?}\n\
                 {FIX}",
                index + 1
            );
        }
        offset += a.len();
    }

    // Every shared line matched, so one side has trailing content the other
    // lacks — including the case where the only difference is a final newline.
    let (longer, which) = if rendered.len() > committed.len() {
        (&rendered[offset..], "renderer produces")
    } else {
        (&committed[offset..], "committed file has")
    };
    panic!(
        "docs/conformance-rules.md and the renderer agree for the first {offset} bytes, \
         then the {which} {} extra bytes: {longer:?}\n{FIX}",
        longer.len()
    );
}

/// Every rule must reach the rendered document, or the catalog understates
/// what the tool checks.
#[test]
fn every_rule_appears_in_the_rendered_catalog() {
    let rendered = rules::render_catalog();
    for rule in rules::all_rules() {
        assert!(
            rendered.contains(&rule.id.to_string()),
            "{} is declared but absent from the catalog",
            rule.id
        );
    }
}
