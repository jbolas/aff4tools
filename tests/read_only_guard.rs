//! Guards the read-only contract by scanning the library source.
//!
//! aff4tools must never modify evidence. `clippy.toml` denies the write APIs,
//! but clippy only runs when someone invokes it — this runs on every
//! `cargo test`, so a write path reintroduced by a future change (or a future
//! agent session) fails the build rather than shipping.
//!
//! Scope is `src/*.rs` outside `#[cfg(test)]` modules. Tests legitimately
//! create synthetic archives and temp fixtures; the library never does.

use std::path::{Path, PathBuf};

/// APIs that would let the crate modify a file.
const FORBIDDEN_APIS: &[&str] = &[
    "ZipWriter",
    "File::create",
    "fs::write",
    "fs::create_dir",
    "fs::remove_file",
    "fs::remove_dir",
    "fs::rename",
    "fs::copy",
    "fs::set_permissions",
    "OpenOptions",
    "set_len",
];

/// Every `.rs` file under `src/`.
fn library_sources() -> Vec<PathBuf> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut out = Vec::new();
    collect(&src, &mut out);
    out.sort();
    assert!(!out.is_empty(), "found no sources under {}", src.display());
    out
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        // `src/write/` is the one module allowed to write; see write/mod.rs.
        // It has its own chokepoint test rather than this API scan.
        if path.file_name().and_then(|n| n.to_str()) == Some("write") {
            continue;
        }
        if path.is_dir() {
            collect(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

/// Strip `#[cfg(test)] mod tests { ... }` by brace matching.
///
/// Deliberately simple: it only needs to find the one conventional test module
/// per file. If the marker is absent the whole file is scanned, which errs
/// toward more checking rather than less.
fn without_test_module(source: &str) -> String {
    let Some(marker) = source.find("#[cfg(test)]") else {
        return source.to_string();
    };
    let Some(open) = source[marker..].find('{').map(|i| marker + i) else {
        return source[..marker].to_string();
    };

    let mut depth = 0usize;
    for (offset, ch) in source[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    let end = open + offset + 1;
                    return format!("{}{}", &source[..marker], &source[end..]);
                }
            }
            _ => {}
        }
    }
    source[..marker].to_string()
}

/// Yield `(line number, trimmed line)` for real code, skipping comments.
///
/// Doc comments name these APIs when documenting the read-only contract, so
/// scanning them would report the documentation as a violation.
fn code_lines(source: &str) -> impl Iterator<Item = (usize, &str)> {
    source
        .lines()
        .enumerate()
        .map(|(i, l)| (i + 1, l.trim()))
        .filter(|(_, l)| !l.starts_with("//") && !l.starts_with('*'))
}

#[test]
fn library_code_contains_no_write_apis() {
    let mut findings = Vec::new();

    for path in library_sources() {
        let Ok(source) = std::fs::read_to_string(&path) else {
            continue;
        };
        let code = without_test_module(&source);
        let lines: Vec<&str> = code.lines().collect();

        for (number, line) in code_lines(&code) {
            for api in FORBIDDEN_APIS {
                if line.contains(api) {
                    // An explicit `#[allow(clippy::disallowed_methods)]` on the
                    // preceding line is the sanctioned exemption, named in this
                    // test's own failure message. It is deliberately narrow:
                    // one call site, visible in review, and still reported by
                    // the chokepoint test below if it creates a container.
                    let exempted = number
                        .checked_sub(2)
                        .and_then(|i| lines.get(i))
                        .is_some_and(|prev| {
                            prev.trim()
                                .starts_with("#[allow(clippy::disallowed_methods)]")
                        });
                    if exempted {
                        continue;
                    }
                    findings.push(format!(
                        "{}:{number}: {api}\n    {line}",
                        path.file_name().unwrap_or_default().to_string_lossy(),
                    ));
                }
            }
        }
    }

    assert!(
        findings.is_empty(),
        "aff4tools must never modify evidence, but library code references \
         write-capable APIs:\n{}\n\nIf a write is genuinely required, it needs \
         explicit approval and a documented #[allow] at the call site.",
        findings.join("\n")
    );
}

/// The one sanctioned way to open a container must remain `File::open`,
/// reached through a single helper.
///
/// Parallel verification needs several handles onto one container — the
/// volume's own, the central-directory scan, and one per reader thread — so
/// counting handles no longer expresses the rule. What must stay true is that
/// every one of them is created in the same place, by a function that can only
/// open for reading. A second `File::open` elsewhere in the module is the
/// thing to catch: it is how a write-capable handle would arrive unnoticed.
#[test]
fn containers_are_opened_read_only() {
    let zip_rs = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/zip.rs");
    let source = std::fs::read_to_string(&zip_rs).expect("src/zip.rs must exist");
    let code = without_test_module(&source);

    let opens: Vec<&str> = code_lines(&code)
        .filter(|(_, l)| l.contains("File::open"))
        .map(|(_, l)| l)
        .collect();

    assert_eq!(
        opens.len(),
        1,
        "expected exactly one File::open chokepoint in src/zip.rs, found {}: {opens:?}",
        opens.len()
    );

    // And that occurrence must be the helper itself, not an inlined open that
    // happens to be alone today.
    assert!(
        opens[0].contains("File::open(path)"),
        "the sole File::open must be `open_read_only`'s; found {:?}",
        opens[0]
    );
    assert!(
        code.contains("fn open_read_only(path: &Path) -> std::io::Result<File>"),
        "src/zip.rs must route every handle through `open_read_only`"
    );
}

/// The guard must actually detect a violation, or it is decoration.
#[test]
fn the_guard_detects_a_planted_violation() {
    let planted = r#"
        fn innocent() {}
        fn bad() { let f = std::fs::File::create("/tmp/x"); }
        #[cfg(test)]
        mod tests { fn helper() { std::fs::write("/tmp/y", b""); } }
    "#;
    let code = without_test_module(planted);
    assert!(
        code.contains("File::create"),
        "library code must still be scanned"
    );
    assert!(
        !code.contains("fs::write"),
        "the test module must be excluded, but its contents survived"
    );
}

/// The `#[allow]` exemption is narrow: it covers the annotated line only.
///
/// The acquisition log — the binary's own output, not container content —
/// needs `File::create_new`. The risk of an exemption is that it becomes a
/// hole, so this pins both halves: an annotated call is permitted, and an
/// unannotated one two lines later is still caught.
#[test]
fn the_allow_exemption_covers_only_the_line_it_annotates() {
    let source = r"
        fn logged() {
            #[allow(clippy::disallowed_methods)]
            let a = std::fs::File::create_new(path);
            let b = std::fs::File::create(other);
        }
    ";
    let lines: Vec<&str> = source.lines().collect();

    let mut caught = Vec::new();
    for (number, line) in code_lines(source) {
        if FORBIDDEN_APIS.iter().any(|api| line.contains(api)) {
            let exempted = number
                .checked_sub(2)
                .and_then(|i| lines.get(i))
                .is_some_and(|prev| {
                    prev.trim()
                        .starts_with("#[allow(clippy::disallowed_methods)]")
                });
            if !exempted {
                caught.push(line);
            }
        }
    }

    assert_eq!(
        caught.len(),
        1,
        "exactly the unannotated call must be caught, got: {caught:?}"
    );
    assert!(
        caught[0].contains("File::create(other)"),
        "the wrong line was caught: {caught:?}"
    );
}

/// `src/write/` is exempt from the API scan, but nothing else is.
///
/// The exemption is what makes writing possible; the scan that remains is what
/// keeps the read path provably unable to modify evidence.
#[test]
fn the_scan_skips_the_write_module_only() {
    let sources = library_sources();
    assert!(
        !sources
            .iter()
            .any(|p| p.to_string_lossy().contains("/write/")),
        "src/write/ must be exempt from the read-only API scan"
    );
    assert!(
        sources.iter().any(|p| p.ends_with("zip.rs")),
        "every other module must still be scanned"
    );
}

/// `src/write/` must route every file creation through one chokepoint.
///
/// The exemption lets the writer call `File::create`; this keeps it to a single
/// reviewable site that consults the source registry first.
#[test]
fn the_writer_has_exactly_one_create_chokepoint() {
    let write_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/write");
    let mut sources = Vec::new();
    collect_all(&write_dir, &mut sources);
    assert!(!sources.is_empty(), "src/write/ must contain sources");

    let mut hits = Vec::new();
    for path in &sources {
        let text = std::fs::read_to_string(path).unwrap();
        let code = without_test_module(&text);
        if code.contains("File::create") {
            hits.push(path.clone());
        }
    }

    assert_eq!(
        hits.len(),
        1,
        "exactly one file in src/write/ may call File::create, found: {hits:?}"
    );
    assert!(
        hits[0].ends_with("sink.rs"),
        "the chokepoint belongs in sink.rs, found {:?}",
        hits[0]
    );
}

/// Collect `.rs` files without the `src/write/` exemption `collect` applies.
///
/// The write module is exempt from the write-API scan and **not** from the
/// unsafe count: the one audited exception lives there.
fn collect_all(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_all(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

/// The library still denies `unsafe`, and grants exactly one exception.
///
/// The C ABI in `aff4tools-ffi` needs `extern "C"` and raw pointers. It lives
/// in a separate crate precisely so this stays true — `src/lib.rs` says a
/// second proposed exception is the moment to reconsider a wrapper crate, and
/// that is what was done.
///
/// The count is asserted, not just the deny: adding a second `#[allow]` must
/// trip a test rather than pass review unnoticed. The one permitted exception
/// is the geometry ioctl in `write::device`, which reads a block device's size
/// and cannot modify it.
///
/// That function serves macOS and Linux from per-target arms *inside* a single
/// annotated function. The count here is textual and has no `cfg` awareness, so
/// giving each platform its own `#[allow]` would read as several exceptions
/// even though only one can ever compile. Keeping one annotation keeps the
/// audit honest and this count meaningful.
#[test]
fn the_library_still_denies_unsafe_with_one_exception() {
    let lib = std::fs::read_to_string("src/lib.rs").unwrap();
    assert!(
        lib.contains("#![deny(unsafe_code)]"),
        "src/lib.rs must keep denying unsafe; the C ABI belongs in aff4tools-ffi"
    );

    // Every source, including `src/write/`: the write module is exempt from
    // the write-API scan, but not from the unsafe rule.
    let mut all = Vec::new();
    collect_all(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut all);
    all.sort();

    let mut exceptions = Vec::new();
    for path in all {
        let source = std::fs::read_to_string(&path).unwrap();
        for (number, line) in code_lines(&source) {
            if line.contains("#[allow(unsafe_code)]") {
                exceptions.push(format!("{}:{number}", path.display()));
            }
        }
    }

    assert_eq!(
        exceptions.len(),
        1,
        "expected exactly one audited unsafe exception, found: {exceptions:?}\n\
         A new one needs the audit `src/lib.rs` describes, or belongs in aff4tools-ffi."
    );
    assert!(
        exceptions[0].contains("device.rs"),
        "the one exception should be the geometry ioctl in write::device, found {}",
        exceptions[0]
    );
}
