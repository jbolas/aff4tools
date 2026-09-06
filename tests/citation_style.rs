//! Every specification citation must name its document.

use std::path::Path;

/// Files whose module doc comment names one governing document, so bare
/// sections inside them are unambiguous.
///
/// Each of these cites the AFF4-L 2019 paper and nothing else, and each says
/// so at the top of the file. Adding an entry here is a claim about the whole
/// file, so `single_document_modules_cite_only_their_document` re-checks it.
/// Each entry is a file and the document its bare sections cite.
///
/// Adding an entry is a claim about the whole file, which
/// `single_document_modules_cite_only_their_document` re-checks.
const SINGLE_DOCUMENT_MODULES: &[(&str, Document)] = &[
    ("src/naming.rs", Document::Alpha),
    ("src/write/dedupe.rs", Document::Paper2019),
    ("tests/logical_acquire.rs", Document::Paper2019),
    ("tests/dedupe_acquire.rs", Document::Paper2019),
];

/// A document a single-document module may cite.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Document {
    /// AFF4-L (Schatz, DFRWS USA 2019).
    Paper2019,
    /// AFF4-L Standard v1.0-ALPHA.
    Alpha,
}

impl Document {
    /// The sentence the module doc comment must carry.
    fn statement(self) -> &'static str {
        match self {
            Self::Paper2019 => "**Every bare section number below cites that paper**",
            Self::Alpha => "**Every bare section number below cites that standard.**",
        }
    }

    /// Whether a section number could not belong to this document.
    ///
    /// The 2019 paper stops at section 4, so a higher number means the file has
    /// started citing something else and the exemption no longer holds. The
    /// v1.0-ALPHA standard runs to §10, so nothing is out of range there and
    /// the guard falls to the qualified-citation rule instead.
    fn is_foreign_section(self, section: &str) -> bool {
        match self {
            Self::Paper2019 => {
                section.starts_with("§5") || section.starts_with("§6") || section.starts_with("§7")
            }
            Self::Alpha => false,
        }
    }
}

/// The sentence an exempt file must carry, so a reader who lands mid-file
/// knows which document its bare sections belong to.
fn source_files() -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    for dir in ["src", "tests", "examples"] {
        collect(Path::new(dir), &mut files);
    }
    files.sort();
    files
}

fn collect(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn every_citation_names_its_document() {
    let mut offenders = Vec::new();

    for path in source_files() {
        let display = path.to_string_lossy().replace('\\', "/");
        if SINGLE_DOCUMENT_MODULES
            .iter()
            .any(|(name, _)| *name == display)
        {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for (index, line) in text.lines().enumerate() {
            if !line.contains('§') {
                continue;
            }
            // Only comments are audited. A section sign inside a string
            // literal is text the tool prints, and rewording it would change
            // observable output — a separate decision from citation style.
            if !line.trim_start().starts_with("//") {
                continue;
            }
            // Every citation on the line, not just the first: a line may cite
            // two documents, and checking only the first would let the second
            // through unqualified.
            for (position, _) in line.match_indices('§') {
                // A citation is qualified if a document is named on the same
                // line, before the section sign.
                let prefix = &line[..position];
                let qualified = prefix.contains("v1.0a")
                    || prefix.contains("AFF4-L 2019")
                    || prefix.contains("v1.0-ALPHA")
                    || prefix.contains("Standard v1.0");
                if !qualified {
                    offenders.push(format!("{display}:{}: {}", index + 1, line.trim()));
                    break;
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "unqualified citations found; name the document (see CLAUDE.md):\n{}",
        offenders.join("\n")
    );
}

/// An exemption is only sound while the file really cites one document.
///
/// Without this, a v1.0a citation added later to an exempt file would be
/// waved through by the very list meant to keep citations honest.
#[test]
fn single_document_modules_cite_only_their_document() {
    for (name, document) in SINGLE_DOCUMENT_MODULES {
        let text = std::fs::read_to_string(name)
            .unwrap_or_else(|e| panic!("{name} is listed as exempt but cannot be read: {e}"));

        assert!(
            text.contains(document.statement()),
            "{name} is exempt but its module doc comment does not say which \
             document its bare sections cite"
        );

        // A section number the named document does not have means the file has
        // started citing something else, and the exemption no longer holds.
        for (index, line) in text.lines().enumerate() {
            let Some(position) = line.find('§') else {
                continue;
            };
            if !line.trim_start().starts_with("//") {
                continue;
            }
            let section = &line[position..];
            let foreign = document.is_foreign_section(section);
            assert!(
                !foreign || line[..position].contains("v1.0a"),
                "{name}:{}: cites a section outside the document it names, so \
                 the file is no longer single-document; qualify every citation \
                 in it and drop it from SINGLE_DOCUMENT_MODULES:\n{}",
                index + 1,
                line.trim()
            );
        }
    }
}
