//! Every specification citation must name its document.

use std::path::Path;

/// Files whose module doc comment names one governing document, so bare
/// sections inside them are unambiguous.
///
/// Each of these cites the AFF4-L 2019 paper and nothing else, and each says
/// so at the top of the file. Adding an entry here is a claim about the whole
/// file, so `single_document_modules_cite_only_their_document` re-checks it.
const SINGLE_DOCUMENT_MODULES: &[&str] = &[
    "src/write/logical.rs",
    "src/write/dedupe.rs",
    "tests/logical_acquire.rs",
    "tests/dedupe_acquire.rs",
];

/// The sentence an exempt file must carry, so a reader who lands mid-file
/// knows which document its bare sections belong to.
const SINGLE_DOCUMENT_STATEMENT: &str = "**Every bare section number below cites that paper**";

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
        if SINGLE_DOCUMENT_MODULES.contains(&display.as_str()) {
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
    for name in SINGLE_DOCUMENT_MODULES {
        let text = std::fs::read_to_string(name)
            .unwrap_or_else(|e| panic!("{name} is listed as exempt but cannot be read: {e}"));

        assert!(
            text.contains(SINGLE_DOCUMENT_STATEMENT),
            "{name} is exempt but its module doc comment does not say which \
             document its bare sections cite"
        );

        // The paper has no section 5 or above, so a citation to one is a
        // citation to some other document and the exemption no longer holds.
        for (index, line) in text.lines().enumerate() {
            let Some(position) = line.find('§') else {
                continue;
            };
            if !line.trim_start().starts_with("//") {
                continue;
            }
            let section = &line[position..];
            let foreign =
                section.starts_with("§5") || section.starts_with("§6") || section.starts_with("§7");
            assert!(
                !foreign || line[..position].contains("v1.0a"),
                "{name}:{}: cites a section outside the AFF4-L 2019 paper, so \
                 the file is no longer single-document; qualify every citation \
                 in it and drop it from SINGLE_DOCUMENT_MODULES:\n{}",
                index + 1,
                line.trim()
            );
        }
    }
}
