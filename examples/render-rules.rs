//! Regenerate `docs/conformance-rules.md` from the rule registry.
//!
//! Run: `cargo run --example render-rules > docs/conformance-rules.md`

fn main() {
    print!("{}", aff4tools::rules::render_catalog());
}
