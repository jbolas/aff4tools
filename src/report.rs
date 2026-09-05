//! Formatting for `aff4tools info` output.
//! Nothing here recomputes or verifies anything.

use std::io::Write;

use aff4tools::{
    Aff4Object, ContainerSummary, EdgeKind, HashAlgorithm, Locality, ManifestIssue, ObjectCounts,
    ObjectRole, StoredHash,
};

use crate::{ObjectFilter, human_bytes};

/// Write the output.
pub(crate) fn write_text(
    out: &mut impl Write,
    summary: &ContainerSummary,
    filter: ObjectFilter,
    brief: bool,
) -> std::io::Result<()> {
    if brief {
        return write_brief(out, summary);
    }

    write_identity_block(out, summary)?;
    writeln!(
        out,
        "{:<LABEL_WIDTH$}{} members",
        "Zip segments:", summary.segments.count
    )?;
    write_segment_kinds(out, summary)?;

    write_case_block(out, summary, filter)?;
    write_manifest_block(out, summary)?;

    let ordered = order_objects(summary);
    let listed: Vec<&Aff4Object> = ordered.into_iter().filter(|o| filter.admits(o)).collect();

    if !listed.is_empty() {
        writeln!(out)?;
        // Rule 1: this numeral and "Segments: N members" above must
        // never be readable as the same count. "Objects" on its own line,
        // naming what it counts, is not reusable with "Segments".
        if listed.len() == summary.objects.len() {
            writeln!(out, "Objects ({})", listed.len())?;
        } else {
            writeln!(
                out,
                "Objects ({} of {} described, filtered)",
                listed.len(),
                summary.objects.len()
            )?;
        }
        for object in listed {
            write_object(out, object, &summary.prefixes, &summary.manifest)?;
        }
    }

    write_conformance_pointer(out, summary)?;

    Ok(())
}

/// Column the identity block's values start in.
///
/// Wide enough for the longest label ("Zip segments:") plus a separating space,
/// so every value in the block lines up. Spaces rather than tabs: a tab stop
/// depends on the terminal's tab width, so a label one character longer than a
/// stop pushed its value a whole stop further right than its neighbours.
const LABEL_WIDTH: usize = 14;

/// What the container holds, in one line, before any structural detail.
///
/// A `.aff4` file extension is the same whether the container holds a disk
/// image or a logical file collection, and an examiner handed one cannot tell
/// which from the outside. This line answers that first.
///
/// **It reads the contained objects, not the volume.** The volume ARN names the
/// ZIP itself and carries no `rdf:type` in any of the 20 reference containers —
/// `DiskImage` and `FolderImage` are declared by objects *inside* it, under
/// their own ARNs. Reading types off the volume would print an empty line for
/// every container in the corpus.
///
/// Four cases, in the order they are tried:
///
/// 1. **A disk image.** `DiskImage` leads, with `ContiguousImage` or
///    `DiscontiguousImage` parenthesized as a qualifier rather than listed as a
///    co-equal type — the distinction stays visible without reading as two
///    separate images. `aff4:Image` is omitted throughout: every image declares
///    it, so it distinguishes nothing.
/// 2. **A logical image** (AFF4-L). Counted rather than named, because there is
///    no single root to name: `unicode.aff4` holds two `FolderImage`s and seven
///    `FileImage`s as siblings. Files and folders are counted separately and the
///    wording claims no containment between them.
/// 3. **Neither, but objects carry types.** Their local names, deduplicated in
///    first-appearance order. Pre-standard containers land here — `Base-Linear.af4`
///    types its image `QueryMap, map, Image`, an older vocabulary with no
///    `DiskImage` term. Listing what is there beats asserting an equivalence
///    the spec does not state.
/// 4. **Nothing to report.** Stated as an absence, never left blank.
fn content_type(summary: &ContainerSummary) -> String {
    describe_content(&summary.objects, &summary.counts)
}

/// The body of [`content_type`], over the objects alone.
///
/// Split out so the four cases can be tested directly. `DiscontiguousImage` in
/// particular has **no corpus fixture** — so its branch would otherwise go unproven.
fn describe_content(objects: &[Aff4Object], counts: &ObjectCounts) -> String {
    // File and folder tallies come from `counts`, which is accumulated during
    // the parse: `summarize_brief` drops objects it will not render, so
    // counting `objects` here would report a fraction of an AFF4-L container.
    let files = counts.files;
    let folders = counts.folders;
    let disk_image = objects
        .iter()
        .find(|o| matches!(o.role, ObjectRole::DiskImage));

    if let Some(image) = disk_image {
        // The qualifier is whichever of the two shapes the object declares.
        // Neither is guaranteed: an object may be typed `DiskImage, Image` alone.
        let qualifier = image
            .types
            .iter()
            .map(|t| local_name(t))
            .find(|name| matches!(*name, "ContiguousImage" | "DiscontiguousImage"));

        return match qualifier {
            Some("ContiguousImage") => "DiskImage (contiguous)".to_owned(),
            Some("DiscontiguousImage") => "DiskImage (discontiguous)".to_owned(),
            _ => "DiskImage".to_owned(),
        };
    }

    if files > 0 || folders > 0 {
        return format!(
            "AFF4-L logical image containing {files} {} and {folders} {}",
            plural(files, "file", "files"),
            plural(folders, "folder", "folders"),
        );
    }

    // The types of objects that carry content, deduplicated in first-appearance
    // order. Restricted to objects declaring `aff4:Image` (or the pre-standard
    // lowercase `image`), because an unrestricted sweep pulls in case notes,
    // timestamps, and the acquisition-tool block — `Base-Linear.af4` yields 11
    // types that way, most of them provenance rather than content.
    //
    // `Image` itself is dropped once used as the filter, since every image
    // carries it, and so is the volume's own type.
    let mut named: Vec<&str> = Vec::new();
    for object in objects {
        let is_content = object
            .types
            .iter()
            .any(|t| matches!(local_name(t), "Image" | "image"));
        if !is_content {
            continue;
        }
        for iri in &object.types {
            let name = local_name(iri);
            if matches!(name, "Image" | "image" | "ZipVolume" | "zip_volume") {
                continue;
            }
            if !named.contains(&name) {
                named.push(name);
            }
        }
    }

    if named.is_empty() {
        "not stated by this container".to_owned()
    } else {
        named.join(", ")
    }
}

/// Pick the singular or plural form for `count`.
fn plural<'a>(count: usize, one: &'a str, many: &'a str) -> &'a str {
    if count == 1 { one } else { many }
}

/// The lines that say which container this is, shared by `info` and `verify`.
///
/// Container, volume ARN and where it came from, content type, version, and
/// tool. `verify` opens with the identical block so a reader moving between the
/// two commands is not asked to re-establish what is being reported on — and so
/// the two cannot drift into naming the same container differently.
pub(crate) fn write_identity_block(
    out: &mut impl Write,
    summary: &ContainerSummary,
) -> std::io::Result<()> {
    writeln!(
        out,
        "{:<LABEL_WIDTH$}{}",
        "Container:",
        summary.source_path.display()
    )?;
    writeln!(out, "{:<LABEL_WIDTH$}{}", "Volume ARN:", summary.volume.arn)?;
    writeln!(
        out,
        "{:<LABEL_WIDTH$}({})",
        "",
        describe_arn_source(&summary.volume.arn_source)
    )?;
    writeln!(
        out,
        "{:<LABEL_WIDTH$}{}",
        "Content Type:",
        content_type(summary)
    )?;
    write_version_lines(out, summary)
}

/// Write the version and tool lines.
///
/// `AFF4 Version:` states the declared version as `major.minor` — the form the
/// standard itself uses ("v1.0", "v1.1") and the one an examiner would quote,
/// rather than the `major=1 minor=0` key-value echo of `version.txt`'s on-disk
/// syntax that this replaced.
///
/// `Tool:` is a separate line and is omitted entirely when the container
/// declares no tool. `version.txt`'s `tool` field is optional (v1.0a §1), so
/// an empty `Tool:` line would present an absent declaration as a blank value.
/// Every corpus container that declares a version also declares a tool, so this
/// path is unexercised there — absence is still a fact about the container, not
/// a gap to paper over.
///
/// A pre-Standard container declares no version at all and says so. pyaff4
/// fabricates `0.1` here.
fn write_version_lines(out: &mut impl Write, summary: &ContainerSummary) -> std::io::Result<()> {
    match &summary.version {
        Some(version) => {
            writeln!(
                out,
                "{:<LABEL_WIDTH$}{}.{}",
                "AFF4 Version:", version.major, version.minor
            )?;
            if let Some(tool) = version.tool.as_ref() {
                writeln!(out, "{:<LABEL_WIDTH$}{tool}", "Tool:")?;
            }
        }
        None => writeln!(
            out,
            "{:<LABEL_WIDTH$}not declared (pre-standard container)",
            "AFF4 Version:"
        )?,
    }
    Ok(())
}

/// Write the per-kind segment breakdown as tab-separated columns.
///
/// Kept as a helper because `write_text` and `write_brief` must not drift
/// apart on layout — the header block is the one part of the two reports that
/// is meant to look identical.
fn write_segment_kinds(out: &mut impl Write, summary: &ContainerSummary) -> std::io::Result<()> {
    /// Tab width assumed when padding a label out to a tab stop. Eight is the
    /// terminal default and what `expand` uses without arguments.
    const TAB: usize = 8;

    let widest = summary
        .segments
        .kinds
        .iter()
        .map(|k| k.kind.label().len())
        .max()
        .unwrap_or(0);
    // Round up to the next stop, leaving at least one space after the longest
    // label so two columns never abut.
    let label_width = (widest / TAB + 1) * TAB;

    // Counts are right-aligned to the widest of them, so the column is as
    // narrow as the container allows: a fixed width padded every row out to
    // the largest count any container might hold.
    let count_width = summary
        .segments
        .kinds
        .iter()
        .map(|k| k.count.to_string().len())
        .max()
        .unwrap_or(1);

    for row in &summary.segments.kinds {
        // The single root members are named by their label already; repeating
        // the name as an example would say nothing.
        let example = if row.example == row.kind.label() {
            ""
        } else {
            &row.example
        };
        // Marked "e.g." wherever the name shown is one of several, so it cannot
        // be read as naming the whole row. Bevy rows always are: the example is
        // the alphanumerically last member of a numbered sequence, so even a
        // single bevy names one member of a series rather than the row itself.
        let sample = if example.is_empty() {
            String::new()
        } else if row.count > 1
            || matches!(
                row.kind,
                aff4tools::model::SegmentKind::BevyData | aff4tools::model::SegmentKind::BevyIndex
            )
        {
            format!("e.g. {example}")
        } else {
            example.to_owned()
        };
        let line = format!(
            "    {:>count_width$}  {:<label_width$}{}",
            row.count,
            row.kind.label(),
            sample
        );
        writeln!(out, "{}", line.trim_end())?;
    }
    Ok(())
}

/// Point at `aff4tools conformance` instead of listing deviations.
///
/// Conformance is a question with its own command. Answering it in the middle
/// of a metadata dump would make a finding something the reader happens across
/// rather than something they asked for.
///
/// What stays is the *count*, and only when it is non-zero. Dropping the line
/// entirely would be the worse failure — an examiner reading `info` on a
/// container with a dangling reference would see a clean report and no
/// indication that anything had been recorded at all. A count plus where to
/// get the detail keeps `info` honest without duplicating the listing.
fn write_conformance_pointer(
    out: &mut impl Write,
    summary: &ContainerSummary,
) -> std::io::Result<()> {
    if summary.deviations.is_empty() {
        return Ok(());
    }

    writeln!(out)?;
    let count = summary.deviations.len();
    let plural = if count == 1 {
        "1 deviation"
    } else {
        &format!("{count} deviations")
    };
    writeln!(
        out,
        "Conformance: {plural} from the AFF4 standard recorded. \
         Run `aff4tools conformance` for the detail."
    )?;

    Ok(())
}

/// Write the `--brief` short report.
///
/// Two things this function must never do, regardless of how the
/// layout evolves: hide that a deviation was recorded, or print anything that
/// could read as a checked/verified digest. Per-object properties, edges, the
/// segment-kind breakdown, and the manifest reconciliation are still dropped
/// in favor of counts — but hashes are **not** omitted (reversed from this
/// function's first version): the user asked for linear bitstream hashes and
/// the stored/described sizes they cover, on the same screen, so a brief
/// report stays useful without the examiner reaching for the full one. Every
/// digest printed here is full length (never truncated) and carries
/// [`StoredHash::PROVENANCE`] — brief must not read as verification any more
/// than the full report does.
///
/// The deviation *listing* moved to `aff4tools conformance`; what brief and
/// full both still carry is [`write_conformance_pointer`]'s count, so neither
/// can present a container with recorded deviations as though it had none.
fn write_brief(out: &mut impl Write, summary: &ContainerSummary) -> std::io::Result<()> {
    writeln!(
        out,
        "{:<LABEL_WIDTH$}{}",
        "Container:",
        summary.source_path.display()
    )?;
    writeln!(out, "{:<LABEL_WIDTH$}{}", "Volume ARN:", summary.volume.arn)?;
    // Same position as in the full report: what the container holds is the
    // first question a `.aff4` extension leaves unanswered, and brief exists
    // to answer the first questions.
    writeln!(
        out,
        "{:<LABEL_WIDTH$}{}",
        "Content Type:",
        content_type(summary)
    )?;
    write_version_lines(out, summary)?;
    writeln!(
        out,
        "{:<LABEL_WIDTH$}{} members",
        "Zip segments:", summary.segments.count
    )?;

    if let Some(case_line) = brief_case_line(summary) {
        writeln!(out, "{:<LABEL_WIDTH$}{case_line}", "Case:")?;
    }

    writeln!(
        out,
        "{:<LABEL_WIDTH$}{}",
        "Objects:",
        brief_object_counts(summary)
    )?;

    write_brief_bitstream(out, summary)?;

    if let Some(note) = writer_profile_note(&summary.prefixes) {
        writeln!(out)?;
        writeln!(out, "{note}")?;
    }

    write_conformance_pointer(out, summary)?;

    Ok(())
}

/// The brief `Case:` line: case number / evidence number / examiner,
/// collapsed onto one line. `None` when the container carries none of the
/// three — printed as an absent line, never as an empty one.
///
/// Prints each recorded value exactly as the container states it, with no
/// added label. `Base-Linear.aff4`'s own `caseNumber` literal is the string
/// `"Case ID: 1SR Canonical"` — a label baked into the recorded text itself —
/// so a label prepended here would double it (`"Case ID: Case ID: ..."`).
/// The full report's `Case` block does not label these fields either
/// (`case_field_label` names the block's own lines, not the values); brief
/// follows the same rule.
fn brief_case_line(summary: &ContainerSummary) -> Option<String> {
    let field = |predicate: &str| -> Option<String> {
        summary.objects.iter().find_map(|object| {
            object
                .properties
                .iter()
                .find(|p| p.name.eq_ignore_ascii_case(predicate))
                .map(|p| p.value.lexical().to_owned())
        })
    };

    let values: Vec<String> = ["caseNumber", "evidenceNumber", "examiner"]
        .into_iter()
        .filter_map(field)
        .collect();

    if values.is_empty() {
        None
    } else {
        Some(values.join(" / "))
    }
}

/// How many image-bearing objects [`write_brief_bitstream`] prints in full
/// before collapsing the rest to a count. Keeps brief output brief on an
/// AFF4-L container with many `FileImage` objects (`unicode.aff4` has 7);
/// `Base-Linear.aff4`-shaped containers have one image and one image stream,
/// well under the cap, so the cap never engages there.
const BRIEF_BITSTREAM_LIMIT: usize = 3;

/// Write each image-bearing object's size and hash together, so the two
/// numbers the user asked for cannot be misread as describing each other.
///
/// This is the substantive risk in showing both figures on one screen: on
/// `Base-Linear.aff4`, the image stream's linear SHA1 covers 3,964,928 stored
/// bytes, while the disk image's 268,435,456-byte size is the *described*
/// extent the map assembles from it (98.5% never stored). A flat list of
/// hashes above a flat list of sizes would invite
/// reading the SHA1 as covering the full 268 MB image, which it does not.
/// Grouping each hash under the object whose size sits right above it keeps
/// the association explicit instead of relying on the reader to infer it.
///
/// Also where "linear bitstream hash" vs. "block-map tree root" gets decided:
/// an ordinary `aff4:hash` (MD5/SHA-1/SHA-256/SHA-512/BLAKE2b) is
/// linear; `blockMapHash`, and `aff4:hash` typed `^^aff4:blockMapHashSHA512`
/// or `^^aff4:blockMapHashSHA256`, are the Merkle tree's root and must never
/// be labeled linear.
///
/// Only the `hash`/`blockMapHash` predicates are shown — never
/// `imageStreamHash` or `imageStreamIndexHash`. Those two are structural
/// hashes over the stream's own `.index`/internal bytes, not digests of
/// image content (`imageStreamHash` is flatly **unidentified**), so
/// labeling either "linear" would be worse than the
/// mislabeling this function exists to prevent. The user asked for "linear
/// bitstream hash values"; that is `hash` and nothing else.
fn write_brief_bitstream(out: &mut impl Write, summary: &ContainerSummary) -> std::io::Result<()> {
    // Requires a qualifying hash, not just a size: this section exists to
    // show linear bitstream hashes and tree roots alongside the extent each
    // covers, so an object with a size but no hash (a `FolderImage`, which
    // AFF4-L never hashes) has nothing to contribute here and would only
    // spend one of the limited slots for no benefit.
    let candidates: Vec<&Aff4Object> = order_objects(summary)
        .into_iter()
        .filter(|o| o.role.is_image() || matches!(o.role, ObjectRole::ImageStream))
        .filter(|o| {
            o.hashes
                .iter()
                .any(|h| h.predicate == "hash" || h.predicate == "blockMapHash")
        })
        .collect();

    if candidates.is_empty() {
        return Ok(());
    }

    writeln!(out)?;
    writeln!(out, "Bitstream")?;

    let shown = candidates.len().min(BRIEF_BITSTREAM_LIMIT);
    // Only the objects actually printed need an identity, and only when the
    // role label on the size line does not already disambiguate them (the
    // `Base-Linear.aff4` shape: one disk image, one image stream — `[disk
    // image]` / `[image stream]` already says which is which, and adding an
    // ARN line there would make the common case noisier for no reason).
    let needs_identity = {
        let mut roles: Vec<&ObjectRole> = candidates[..shown].iter().map(|o| &o.role).collect();
        roles.sort_by_key(|r| r.json_token().into_owned());
        roles.windows(2).any(|w| w[0] == w[1])
    };

    for object in &candidates[..shown] {
        if needs_identity {
            writeln!(out, "  {}", brief_identity(object, &candidates[..shown]))?;
        }
        if let Some(size) = object.size {
            writeln!(
                out,
                "  {:<17} {size} bytes ({})  [{}]",
                size_label(object),
                human_bytes(size),
                object.role
            )?;
        }
        for hash in object
            .hashes
            .iter()
            .filter(|h| h.predicate == "hash" || h.predicate == "blockMapHash")
        {
            write_brief_hash(out, hash)?;
        }
    }

    // From `counts`, not `candidates`: `summarize_brief` retains a capped
    // sample, so subtracting from the retained list would report "61 more" on a
    // container holding a million.
    let remaining = summary.counts.bitstream_candidates.saturating_sub(shown);
    if remaining > 0 {
        writeln!(
            out,
            "  ... and {remaining} more image object(s) with their own size/hash (see full report)"
        )?;
    }

    Ok(())
}

/// The identity line for one `Bitstream` entry, printed only when more than
/// one shown object shares a role label (so `[disk image]`/`[image stream]`
/// alone would not say which is which — the AFF4-L many-`FileImage` shape).
///
/// The full report identifies an object by its bare ARN
/// (`write_object`: `writeln!(out, "  {}", object.arn)`); this reuses that
/// same identity rather than inventing a third naming style. The trailing
/// path component (an AFF4-L `FileImage` ARN's final segment is the
/// filename) is shown when it disambiguates every object in `shown` on its
/// own; the full ARN is used instead the moment two candidates would
/// otherwise print the same trailing component, so two different objects can
/// never look identical here.
fn brief_identity(object: &Aff4Object, shown: &[&Aff4Object]) -> String {
    fn trailing(arn: &str) -> &str {
        arn.rsplit('/').next().unwrap_or(arn)
    }
    let this_trailing = trailing(object.arn.as_str());

    let collides = shown.iter().any(|other| {
        other.arn.as_str() != object.arn.as_str() && trailing(other.arn.as_str()) == this_trailing
    });

    if collides {
        object.arn.to_string()
    } else {
        this_trailing.to_owned()
    }
}

/// One digest line in the `Bitstream` section: full length, never truncated,
/// carrying [`StoredHash::PROVENANCE`] exactly as the full report's
/// `write_hash` does, and explicitly kinded as `linear` or `tree root` so it
/// cannot be misread as covering the same extent as the other kind.
fn write_brief_hash(out: &mut impl Write, hash: &StoredHash) -> std::io::Result<()> {
    let kind = if matches!(
        hash.algorithm,
        HashAlgorithm::BlockMapSha512 | HashAlgorithm::BlockMapSha256
    ) || hash.predicate == "blockMapHash"
    {
        "tree root"
    } else {
        "linear"
    };
    writeln!(
        out,
        "    {} ({}, {kind})  {}",
        hash.predicate,
        hash.algorithm,
        StoredHash::PROVENANCE
    )?;
    writeln!(out, "      {}", hash.hex)
}

/// The brief `Objects:` line: a one-line role-count summary in place of the
/// full per-object listing. Image-bearing roles (disk image, contiguous
/// image, discontiguous image, plain image, file image, folder) collapse to
/// a single "images" count, matching how `--objects images` already groups
/// them; image streams and maps are broken out since they are the two other
/// roles that filter admits. Every other described object is folded into a
/// trailing "described" total so the line never implies a role was dropped.
fn brief_object_counts(summary: &ContainerSummary) -> String {
    // From `counts`, not from `objects`: `summarize_brief` retains only the
    // objects it renders, so counting the list would undercount everything.
    let c = &summary.counts;
    let total = c.total;

    let mut breakdown = Vec::new();
    if c.images > 0 {
        breakdown.push(format!(
            "{} {}",
            c.images,
            plural(c.images, "image", "images")
        ));
    }
    if c.maps > 0 {
        breakdown.push(format!("{} {}", c.maps, plural(c.maps, "map", "maps")));
    }
    if c.image_streams > 0 {
        breakdown.push(format!(
            "{} {}",
            c.image_streams,
            plural(c.image_streams, "image stream", "image streams")
        ));
    }

    if breakdown.is_empty() {
        format!("{total} described")
    } else {
        format!("{total} described; {}", breakdown.join(", "))
    }
}

// --- object ordering -------------------------------------------------------

/// Predicate kinds that form the data path: image → map → stream, and a
/// stream's own children (its `BlockHashes` segments).
///
/// Deliberately excludes [`EdgeKind::Describes`] and [`EdgeKind::StoredIn`]:
/// those are metadata attribution and storage location, not the chain of
/// custody from image to bytes. `Other` edges (`mapGapDefaultStream` and
/// anything this build does not name) are excluded too — they describe a
/// spine node rather than extending the chain to another object.
fn is_spine_edge(kind: &EdgeKind) -> bool {
    matches!(
        kind,
        EdgeKind::DataStream | EdgeKind::DependentStream | EdgeKind::TargetStream
    )
}

/// Order objects for display: the data path first, then the volume's
/// `aff4:contains` manifest, then everything else.
///
/// Three tiers, with a fallback when no manifest exists: the middle tier is
/// empty and the order collapses to the data path followed by turtle
/// first-appearance order.
///
/// # Tier 1 — the data path
///
/// A "spine" is walked from each root, in three passes: every image-like
/// object first, then every remaining [`ObjectRole::Map`], then every
/// remaining [`ObjectRole::ImageStream`] — see [`is_spine_root`] for why
/// `Map`/`ImageStream` only qualify when no image-like object exists at all,
/// and the pass ordering between them. Traversal follows [`is_spine_edge`]
/// kinds **in either direction** — a Standard map asserts `dependentStream`
/// toward its stream, but a pre-standard map is reached only by the stream's
/// own `target` edge pointing back at the map, since pre-standard's
/// map→stream edge is `aff4:contains` (modelled as the volume manifest, not
/// a [`GraphEdge`] — see `container.rs`). Reading the graph as undirected for
/// this purpose is what lets one algorithm serve both spellings without a
/// generation-specific branch. A stream's `BlockHashes` children (ARNs of the
/// form `<stream>/...`) are attached immediately after it, since they
/// describe that stream and nowhere else.
///
/// Multiple independent roots are normal and are walked in turtle
/// first-appearance order within each pass: an AFF4-L container with several
/// `FileImage` objects has one root per file, each a spine of one.
///
/// # Tier 2 — the manifest
///
/// Every object not already placed, in the volume's own `aff4:contains`
/// order — the container's own declaration, and the most defensible
/// ordering authority available short of the data path itself.
///
/// # Tier 3 — everything else
///
/// Objects the manifest does not declare (or, with no manifest, everything
/// tier 1 did not reach), in turtle first-appearance order. When a manifest
/// exists, this tier additionally groups by role, so that a container with
/// many objects of one type (pre-standard's `Query`/`QueryAction`/`QueryItem`
/// triad) does not interleave them; the no-manifest fallback stays flat,
/// matching the tool's prior behavior exactly.
fn order_objects(summary: &ContainerSummary) -> Vec<&Aff4Object> {
    let objects = &summary.objects;

    // ARN → object, built once. A linear `objects.iter().find(...)` per spine
    // edge would make ordering O(n²): a logical acquisition where every file is
    // its own spine root scans the whole list per root. Measured on synthetic
    // AFF4-L containers, `info` alone —
    // `conformance` parses the same turtle in 0.5 s:
    //
    // | objects | before  | after  |
    // |---------|---------|--------|
    // | 10,000  | 13.0 s  | 0.06 s |
    // | 40,000  | 247.4 s | 0.20 s |
    //
    // The corpus could not have caught this: its largest container describes
    // ten objects, and the curve only becomes visible in the thousands.
    let index: std::collections::HashMap<&str, &Aff4Object> =
        objects.iter().map(|o| (o.arn.as_str(), o)).collect();
    let by_arn = |arn: &str| index.get(arn).copied();

    // Block-hash objects grouped by the ARN they hang off. A child is named
    // `<parent>/<suffix>`, so the parent is the text before the final `/` —
    // derived once here rather than rediscovered by scanning every object for
    // every node walked.
    let mut block_hash_children: std::collections::HashMap<&str, Vec<&Aff4Object>> =
        std::collections::HashMap::new();
    for object in objects {
        if object.role != ObjectRole::BlockHashes {
            continue;
        }
        let arn = object.arn.as_str();
        if let Some((parent, _)) = arn.rsplit_once('/')
            && index.contains_key(parent)
        {
            block_hash_children.entry(parent).or_default().push(object);
        }
    }

    // Reverse spine edges: for each target ARN, who points at it. The walk is
    // undirected (a pre-standard stream's `target` must reach a map that
    // asserts no edge back), and finding those by scanning every object's
    // edges per node was the third quadratic term here.
    let mut incoming: std::collections::HashMap<&str, Vec<&str>> = std::collections::HashMap::new();
    for object in objects {
        for edge in &object.edges {
            if is_spine_edge(&edge.kind) {
                incoming
                    .entry(edge.to.as_str())
                    .or_default()
                    .push(object.arn.as_str());
            }
        }
    }

    let mut visited: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    let mut ordered: Vec<&Aff4Object> = Vec::new();

    // Tier 1: walk a spine from every root, in turtle order. A Standard-
    // generation image and its map assert spine edges pointing at *each
    // other* (`dataStream` one way, `target` the other), so "not reached by
    // another spine edge" cannot pick out a root — every node on the chain
    // would fail that test. The role hierarchy breaks the tie instead: an
    // image-like role is always a root; `Map` and `ImageStream` only start a
    // walk when no image-like object exists anywhere in the container, which
    // is exactly the pre-standard shape (`is_spine_root`'s doc comment).
    //
    // Three passes, image-like roles first, then `Map`, then `ImageStream`: a
    // pre-standard map carries the disk's own attributes and is the closest
    // analogue to the image role Standard has a name for, so it should open
    // its own spine even when it happens to appear later in the turtle than
    // the stream that reaches it — walking from the stream first would still
    // visit the map, but as the second node of the stream's chain rather than
    // the first node of its own, which reads backwards for the one role that
    // stands in for "image" here.
    let has_image_role = objects.iter().any(|o| o.role.is_image());
    let root_passes: [fn(&ObjectRole) -> bool; 3] = [
        ObjectRole::is_image,
        |role| *role == ObjectRole::Map,
        |role| *role == ObjectRole::ImageStream,
    ];
    for admits_root in root_passes {
        for object in objects {
            if visited.contains(object.arn.as_str()) {
                continue;
            }
            if !admits_root(&object.role) || !is_spine_root(&object.role, has_image_role) {
                continue;
            }
            walk_spine(
                object,
                &block_hash_children,
                &incoming,
                by_arn,
                &mut visited,
                &mut ordered,
            );
        }
    }

    // Tier 2: the volume's own manifest, in declared order.
    for arn in &summary.manifest {
        if visited.contains(arn.as_str()) {
            continue;
        }
        if let Some(object) = by_arn(arn) {
            visited.insert(object.arn.as_str());
            ordered.push(object);
        }
    }

    // Tier 3: everything else. Grouped by role only when a manifest exists —
    // the no-manifest fallback is plain turtle order, the documented
    // pre-existing behavior (A8.4 rule 4).
    let remaining: Vec<&Aff4Object> = objects
        .iter()
        .filter(|o| !visited.contains(o.arn.as_str()))
        .collect();

    if summary.manifest.is_empty() {
        ordered.extend(remaining);
    } else {
        ordered.extend(group_by_role(remaining));
    }

    ordered
}

/// Whether a role is eligible to start a tier-1 spine walk.
///
/// An image-like role is always a root — it is the top of the data path by
/// definition, whatever edges happen to point at or from it. `Map` and
/// `ImageStream` are roots only when `has_image_role` is `false`: the
/// pre-standard shape, where the map itself carries the disk attributes and
/// no separate `DiskImage`/`Image` object exists (`AFF4PreStd/Base-Linear.af4`
/// describes `aff4:QueryMap, aff4:map, aff4:Image` on one subject with no
/// sibling image object). When an image-like object *does* exist, `Map` and
/// `ImageStream` must wait to be reached by the walk from it — a Standard map
/// and its image assert spine edges pointing at each other, so treating a map
/// as an independent root would start a second, redundant walk from the
/// middle of the same chain.
fn is_spine_root(role: &ObjectRole, has_image_role: bool) -> bool {
    role.is_image()
        || (!has_image_role && matches!(role, ObjectRole::Map | ObjectRole::ImageStream))
}

/// Breadth-first walk of one spine, appending every node reached (and each
/// stream's `BlockHashes` children) to `ordered`.
fn walk_spine<'a>(
    root: &'a Aff4Object,
    block_hash_children: &std::collections::HashMap<&'a str, Vec<&'a Aff4Object>>,
    incoming: &std::collections::HashMap<&'a str, Vec<&'a str>>,
    by_arn: impl Fn(&str) -> Option<&'a Aff4Object>,
    visited: &mut std::collections::BTreeSet<&'a str>,
    ordered: &mut Vec<&'a Aff4Object>,
) {
    let mut queue = std::collections::VecDeque::new();
    queue.push_back(root);
    visited.insert(root.arn.as_str());

    while let Some(node) = queue.pop_front() {
        ordered.push(node);

        // Block-hash children belong right after the stream they describe,
        // ahead of the rest of the spine walk — they are not a further step
        // down the data path, but detail on this node.
        //
        // Looked up by parent rather than by scanning every object per node:
        // that scan was the second half of this function's O(n²), and unlike
        // `by_arn` it ran even on containers with no block hashes at all,
        // which is every AFF4-L acquisition.
        for child in block_hash_children
            .get(node.arn.as_str())
            .map_or(&[][..], Vec::as_slice)
        {
            if visited.contains(child.arn.as_str()) {
                continue;
            }
            visited.insert(child.arn.as_str());
            ordered.push(child);
        }

        // Outgoing spine edges from this node.
        let mut neighbors: Vec<&str> = node
            .edges
            .iter()
            .filter(|e| is_spine_edge(&e.kind))
            .map(|e| e.to.as_str())
            .collect();

        // Incoming spine edges: another object's edge pointing at this node.
        // Undirected traversal is what lets a pre-standard stream's own
        // `target` (stream → map) reach the map even though the map asserts
        // no edge back — see the containing function's doc comment.
        for source in incoming
            .get(node.arn.as_str())
            .map_or(&[][..], Vec::as_slice)
        {
            if *source != node.arn.as_str() {
                neighbors.push(source);
            }
        }

        for arn in neighbors {
            if visited.contains(arn) {
                continue;
            }
            let Some(next) = by_arn(arn) else { continue };
            visited.insert(next.arn.as_str());
            queue.push_back(next);
        }
    }
}

/// Stable-sort tier 3 by role, preserving each role group's turtle order.
///
/// A `BTreeMap` keyed by the role's label would resort alphabetically, which
/// is exactly the kind of ordering authority this task set out to remove
/// — so this sorts on first-appearance-of-the-role instead, which
/// keeps the leading objects (usually the volume itself, then whatever the
/// manifest omitted) in a position close to where turtle order already put
/// them.
fn group_by_role(remaining: Vec<&Aff4Object>) -> Vec<&Aff4Object> {
    let mut role_order: Vec<&ObjectRole> = Vec::new();
    for object in &remaining {
        if !role_order.contains(&&object.role) {
            role_order.push(&object.role);
        }
    }

    let mut grouped = Vec::with_capacity(remaining.len());
    for role in role_order {
        grouped.extend(remaining.iter().filter(|o| &o.role == role).copied());
    }
    grouped
}

// --- the volume manifest ----------------------------

/// Write the `Described objects` block: the manifest's status, and the
/// declared/described reconciliation when one exists.
///
/// Three cases, matching the three rows of A8.4 rule 9's table — distinguished
/// by whether the volume is the subject of an `aff4:contains` triple at all,
/// not by whether [`ContainerSummary::manifest`] is non-empty, since a real
/// declaration can validly list zero ARNs (the middle row) and that is a
/// different fact from no declaration at all (the third row). Both produce an
/// empty `manifest` vector, so this cannot be told apart by `manifest` alone.
///
/// `container.rs`'s `build_manifest` does not surface that boolean directly,
/// but its behavior makes it recoverable: with no `aff4:contains` triple at
/// all, `build_manifest` returns immediately and `manifest_disagreements`
/// stays empty (rule 9's third row). With a real-but-empty declaration
/// (second row), every locally-described object other than the volume itself
/// is `PresentButUndeclared` — the declaration exists, and names nothing —
/// so `manifest_disagreements` is non-empty whenever the container has any
/// other local object. The one case this cannot resolve — an empty
/// declaration in a volume describing nothing but itself — is not observed
/// anywhere in the reference corpus; a real container in that state would
/// read as row three, a fallback that only understates a rare, otherwise
/// harmless case.
///
/// A disagreement is also recorded as a deviation (`container.rs`'s
/// `build_manifest`) and listed by `aff4tools conformance`; this block states
/// it inline as well, since a reader following the reconciliation should not
/// have to run a second command to see what disagreed.
fn write_manifest_block(out: &mut impl Write, summary: &ContainerSummary) -> std::io::Result<()> {
    writeln!(out)?;

    let has_declaration =
        !summary.manifest.is_empty() || !summary.manifest_disagreements.is_empty();

    if !has_declaration {
        writeln!(
            out,
            "Described objects: {} in this volume's information.turtle",
            summary.objects.len()
        )?;
        writeln!(
            out,
            "This volume declares no aff4:contains manifest. Object order below \
             follows the data path, then turtle first-appearance order."
        )?;
        return Ok(());
    }

    writeln!(
        out,
        "Described objects: {} in this volume's information.turtle",
        summary.objects.len()
    )?;

    if summary.manifest.is_empty() {
        writeln!(
            out,
            "The volume's aff4:contains manifest declares 0 objects."
        )?;
        return Ok(());
    }

    let declared_but_absent = summary
        .manifest_disagreements
        .iter()
        .filter(|d| d.kind == ManifestIssue::DeclaredButAbsent)
        .count();
    let present_but_undeclared = summary
        .manifest_disagreements
        .iter()
        .filter(|d| d.kind == ManifestIssue::PresentButUndeclared)
        .count();

    writeln!(
        out,
        "  The volume's aff4:contains manifest declares {} of them.",
        summary.manifest.len()
    )?;

    if present_but_undeclared > 0 {
        writeln!(
            out,
            "  {present_but_undeclared} are described but not declared:"
        )?;
        for disagreement in summary
            .manifest_disagreements
            .iter()
            .filter(|d| d.kind == ManifestIssue::PresentButUndeclared)
        {
            writeln!(out, "    {}", disagreement.arn)?;
        }
    } else {
        writeln!(out, "  0 are described but not declared.")?;
    }

    if declared_but_absent > 0 {
        writeln!(
            out,
            "  {declared_but_absent} are declared but not described \
             (see `aff4tools conformance`):"
        )?;
        for disagreement in summary
            .manifest_disagreements
            .iter()
            .filter(|d| d.kind == ManifestIssue::DeclaredButAbsent)
        {
            writeln!(out, "    {}", disagreement.arn)?;
        }
    } else {
        writeln!(out, "  0 are declared but not described.")?;
    }

    Ok(())
}

// --- case metadata header block --------------------------------------------

/// Case-bearing predicate local names, matched case-insensitively wherever
/// they occur.
///
/// Deliberately **not** a type filter. Pre-standard containers put
/// `caseName` and `caseDescription` directly on the map object, which no
/// case-oriented type (`CaseNotes`, `CaseDetails`) would ever admit — see
/// `AFF4PreStd/Base-Linear.af4` lines 92-93. Matching by predicate name
/// finds them wherever the writer placed them, standard or pre-standard,
/// with no extra branch for either generation.
const CASE_PREDICATES: [&str; 6] = [
    "caseNumber",
    "caseName",
    "caseDescription",
    "evidenceNumber",
    "examiner",
    "notes",
];

/// One case-bearing value, with the object it came from.
struct CaseField<'a> {
    arn: &'a str,
    value: String,
}

/// Write a `Case` header block, or nothing at all.
fn write_case_block(
    out: &mut impl Write,
    summary: &ContainerSummary,
    filter: ObjectFilter,
) -> std::io::Result<()> {
    let mut by_predicate: std::collections::BTreeMap<&str, Vec<CaseField>> =
        std::collections::BTreeMap::new();

    for object in &summary.objects {
        for property in &object.properties {
            let Some(canonical) = CASE_PREDICATES
                .iter()
                .find(|p| p.eq_ignore_ascii_case(&property.name))
            else {
                continue;
            };
            by_predicate.entry(canonical).or_default().push(CaseField {
                arn: object.arn.as_str(),
                value: property.value.lexical().to_owned(),
            });
        }
    }

    let has_case_data = CASE_PREDICATES.iter().any(|p| by_predicate.contains_key(p));

    if has_case_data {
        writeln!(out)?;
        writeln!(out, "Case")?;

        for &predicate in &CASE_PREDICATES {
            let Some(fields) = by_predicate.get(predicate) else {
                continue;
            };
            if predicate == "notes" {
                write_case_notes(out, summary, fields)?;
                continue;
            }
            write_case_scalar(out, predicate, fields)?;
        }

        write_case_recorded_by(out, summary, filter, &by_predicate)?;
    }

    if let Some(note) = writer_profile_note(&summary.prefixes) {
        writeln!(out)?;
        writeln!(out, "{note}")?;
    }

    Ok(())
}

/// Write the `Case` block's closing `Recorded by` line: a count of
/// contributing objects grouped by type, rather than every ARN spelled out.
///
/// B5's handover flagged the previous rendering — three full ARNs joined on
/// one line — as worth a second look. Every one of those ARNs is printed in
/// full a few lines below **when `--objects all` is in effect**; under the
/// default `--objects images` filter, `CaseNotes`/`CaseDetails`/`TimeStamps`
/// objects are exactly the roles that filter excludes (`ObjectFilter::admits`
/// in `main.rs`), so pointing at "below" would be false in the default view.
/// This checks `filter` against the actual contributing objects' roles rather
/// than assuming, so the pointer is accurate either way.
///
/// Grouped by declared type (`CaseNotes`, `CaseDetails`, ...) rather than by
/// [`ObjectRole`], since two distinct case-bearing types share one role
/// (`case info`) and collapsing them here would hide which object
/// contributed which field — exactly what the mockup
/// shows.
fn write_case_recorded_by(
    out: &mut impl Write,
    summary: &ContainerSummary,
    filter: ObjectFilter,
    by_predicate: &std::collections::BTreeMap<&str, Vec<CaseField>>,
) -> std::io::Result<()> {
    let contributors: std::collections::BTreeSet<&str> =
        by_predicate.values().flatten().map(|f| f.arn).collect();

    let mut by_type: Vec<(String, usize)> = Vec::new();
    let mut all_listed = true;
    for arn in &contributors {
        let object = summary.objects.iter().find(|o| o.arn.as_str() == *arn);
        if !object.is_some_and(|o| filter.admits(o)) {
            all_listed = false;
        }
        let type_name = object
            .and_then(|o| o.types.first())
            .map_or_else(|| "object".to_owned(), |t| local_name(t).to_owned());
        match by_type.iter_mut().find(|(name, _)| name == &type_name) {
            Some((_, count)) => *count += 1,
            None => by_type.push((type_name, 1)),
        }
    }

    let summary_text = by_type
        .into_iter()
        .map(|(type_name, count)| {
            let plural = if count == 1 { "" } else { "s" };
            format!("{count} {type_name} object{plural}")
        })
        .collect::<Vec<_>>()
        .join(", ");

    let pointer = if all_listed {
        "listed below"
    } else {
        "see --objects all"
    };

    writeln!(out, "  {:<17} {summary_text} ({pointer})", "Recorded by")
}

/// A field with one value per source is printed once; a genuine disagreement
/// between sources prints every distinct value with its ARN, since a
/// disagreement is a fact about the container and never something to pick a
/// side on.
fn write_case_scalar(
    out: &mut impl Write,
    predicate: &str,
    fields: &[CaseField],
) -> std::io::Result<()> {
    let label = case_field_label(predicate);
    let mut distinct: Vec<&str> = Vec::new();
    for field in fields {
        if !distinct.contains(&field.value.as_str()) {
            distinct.push(&field.value);
        }
    }

    if distinct.len() == 1 {
        writeln!(out, "  {label:<17} {}", distinct[0])?;
    } else {
        writeln!(out, "  {label} (objects disagree):")?;
        for field in fields {
            writeln!(out, "    {} — {}", field.value, field.arn)?;
        }
    }
    Ok(())
}

/// `notes` is a sequence, not a scalar: appended case notes are ordered by
/// when they were recorded, and flattening to one line would lose that order.
/// Ordered by each contributing object's own `aff4:timestamp` property, where
/// present; objects without one keep their relative position at the end.
fn write_case_notes(
    out: &mut impl Write,
    summary: &ContainerSummary,
    fields: &[CaseField],
) -> std::io::Result<()> {
    let timestamp_of = |arn: &str| -> Option<String> {
        summary
            .objects
            .iter()
            .find(|o| o.arn.as_str() == arn)
            .and_then(|o| o.property("timestamp"))
            .map(|p| p.value.lexical().to_owned())
    };

    let mut ordered: Vec<(Option<String>, &CaseField)> =
        fields.iter().map(|f| (timestamp_of(f.arn), f)).collect();
    ordered.sort_by(|a, b| match (&a.0, &b.0) {
        (Some(x), Some(y)) => x.cmp(y),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    });

    writeln!(out, "  Notes             {} entries", ordered.len())?;
    for (timestamp, field) in ordered {
        match timestamp {
            Some(ts) => writeln!(out, "    {ts}  {}", field.value)?,
            None => writeln!(out, "    {}", field.value)?,
        }
    }
    Ok(())
}

/// The display label for a case-bearing predicate.
fn case_field_label(predicate: &str) -> &'static str {
    match predicate {
        "caseNumber" => "Case number",
        "caseName" => "Case name",
        "caseDescription" => "Description",
        "evidenceNumber" => "Evidence number",
        "examiner" => "Examiner",
        other => unreachable!("unhandled case predicate {other:?}"),
    }
}

/// The BlackBag Technologies vendor namespace. BlackBag was purchased by
/// Cellebrite, so its presence is a hint that a Cellebrite tool wrote this
/// container.
const BLACKBAG_NAMESPACE: &str = "https://blackbagtech.com/aff4/Schema#";

/// The Cellebrite writer-profile note, if this container's prefixes declare
/// the BlackBag/Cellebrite vendor namespace.
fn writer_profile_note(prefixes: &[(String, String)]) -> Option<&'static str> {
    prefixes
        .iter()
        .any(|(_, namespace)| namespace == BLACKBAG_NAMESPACE)
        .then_some(
            "This file contains references to suggest it was created with Cellebrite \
             tooling. Cellebrite Digital Collector records case information and \
             acquisition log info in other, adjacent files. Please seek Acquisition \
             Log.txt and Device.log for more info.",
        )
}

// --- one object ------------------------------------------------------------

/// The label for an object's `size` line, qualifying its scope.
///
/// A `Map` (and any image-like object whose data path runs through one, e.g.
/// a `DiskImage`) declares the *described* logical extent — the full address
/// space the map covers, gaps included. An `ImageStream` declares the
/// *stored* extent — bytes actually present in this volume's bevies. The two
/// commonly disagree (a map gap reads as zeros without being stored
/// anywhere), and sharing the bare label `size` invites a reader to compare
/// them as the same quantity. Neither word implies damage: a stored extent
/// smaller than a described extent is the normal shape of a
/// symbolic-stream-backed image, not a defect.
///
/// Read from `types` rather than the coarser [`ObjectRole`], because AFF4-L's
/// `FileImage` covers three different shapes that a role alone cannot
/// distinguish (confirmed against the corpus):
///
/// - `FileImage, Image, Map` (`broken-dedupe.aff4`): genuinely map-backed,
///   with a separate `ImageStream` behind it — the same stored/described gap
///   a `DiskImage` has, measured: 13.6 MiB described vs. 13.7 MiB stored.
/// - `FileImage, Image, ImageStream` (`unicode.aff4`): the object *is* its
///   own chunked stream — `chunkSize`/`chunksInSegment` sit directly on it —
///   so its `size` is the stored byte count already; no separate map exists
///   to diverge from.
/// - `FileImage, Image, zip_segment` (`dream.aff4`): stored as one plain ZIP
///   member, no chunking and no map. Same reasoning as the `ImageStream`
///   case: one number, not two scopes.
///
/// Labelling the second and third shapes "described extent" would overclaim
/// a stored/described distinction that does not exist for them — the
/// opposite failure from an earlier one-size-fits-all `size`, and just
/// as misleading, since a reader who has learned the distinction from a
/// `DiskImage` would wrongly read "described" as "not necessarily stored".
/// Plain `size` says no such distinction applies here.
fn size_label(object: &Aff4Object) -> &'static str {
    // Case-insensitive: pre-standard spells this type `map`, Standard `Map`
    // (`ObjectRole::from_types` matches both the same way for `role`, but a
    // `FileImage` that is *also* a `Map` — `broken-dedupe.aff4`'s shape —
    // resolves to role `FileImage`, since `from_types` gives `FileImage`
    // priority; checking `types` directly is what recovers the distinction).
    let has_map_type = object
        .types
        .iter()
        .any(|t| local_name(t).eq_ignore_ascii_case("map"));

    if object.role == ObjectRole::Map || has_map_type {
        "described extent"
    } else if object.role == ObjectRole::ImageStream {
        "stored extent"
    } else if matches!(
        object.role,
        ObjectRole::DiskImage
            | ObjectRole::ContiguousImage
            | ObjectRole::DiscontiguousImage
            | ObjectRole::Image
    ) {
        // An image-like object that is not itself typed `Map` still sits
        // atop one via `dataStream` (Standard) — its own `size` is the
        // logical/described extent the map covers, same as the map's.
        "described extent"
    } else {
        "size"
    }
}

fn write_object(
    out: &mut impl Write,
    object: &Aff4Object,
    prefixes: &[(String, String)],
    manifest: &[String],
) -> std::io::Result<()> {
    writeln!(out)?;
    writeln!(out, "  {}", object.arn)?;

    // Rule 7: property columns size to the widest label present in
    // *this* block, not a fixed width — so a long name (`acquisitionCompletionState`)
    // never collapses the column every short name (`role`, `size`) still uses.
    // Computed as a dry run over every label this function is about to print,
    // in the same order, so the two passes cannot drift apart.
    let mut widest = "role".len();
    widest = widest.max(size_label(object).len());
    if !object.types.is_empty() {
        widest = widest.max("types".len());
    }
    if object.locality != Locality::Undeclared {
        widest = widest.max("stored in".len());
    }
    for edge in object.edges.iter().filter(|e| e.kind != EdgeKind::StoredIn) {
        widest = widest.max(edge.kind.label().len());
    }
    if object.role == ObjectRole::Volume && !manifest.is_empty() {
        widest = widest.max(format!("declares {} objects", manifest.len()).len());
    }
    for hash in &object.hashes {
        widest = widest.max(format!("{} ({})", hash.predicate, hash.algorithm).len());
    }
    for property in object
        .properties
        .iter()
        .filter(|p| !p.is_vendor() && !is_edge_property(p))
    {
        widest = widest.max(property.name.len());
    }

    writeln!(out, "    {:<widest$} {}", "role", object.role)?;

    if !object.types.is_empty() {
        // v1.0a §2.1 requires multiple types; showing all of them lets a reader
        // spot a container that declares an incomplete set.
        // A vendor type renders prefixed — `bbt:APFSContainerImage` — because
        // stripping the namespace would make an extension indistinguishable
        // from a standard AFF4 type.
        let names: Vec<String> = object
            .types
            .iter()
            .map(|t| qualified_name(t, prefixes))
            .collect();
        writeln!(out, "    {:<widest$} {}", "types", names.join(", "))?;
    }

    if let Some(size) = object.size {
        writeln!(
            out,
            "    {:<widest$} {} ({})",
            size_label(object),
            size,
            human_bytes(size)
        )?;
    }

    match object.locality {
        Locality::External => writeln!(
            out,
            "    {:<widest$} {} (another volume)",
            "stored in",
            object.stored_in.as_deref().unwrap_or("?")
        )?,
        Locality::Local => writeln!(out, "    {:<widest$} this volume", "stored in")?,
        Locality::Undeclared => {}
    }

    for edge in object.edges.iter().filter(|e| e.kind != EdgeKind::StoredIn) {
        write_edge(out, object, edge, prefixes, widest)?;
    }

    if object.role == ObjectRole::Volume && !manifest.is_empty() {
        writeln!(
            out,
            "    {:<widest$} (aff4:contains)",
            format!("declares {} objects", manifest.len())
        )?;
    }

    if object.role == ObjectRole::BlockHashes {
        write_block_hashes_header(out, object, widest)?;
    }
    for hash in &object.hashes {
        write_hash(out, object, hash, widest)?;
    }

    // Vendor properties are grouped under their namespace, separately from the
    // unmodelled AFF4 properties below, so it is clear they are an extension
    // rather than an AFF4 term. Cellebrite's `bbt:` block, e.g.
    let vendor: Vec<&aff4tools::Property> = object
        .properties
        .iter()
        .filter(|p| p.is_vendor() && !is_edge_property(p))
        .collect();

    if !vendor.is_empty() {
        let mut namespaces: Vec<(&str, &str)> = Vec::new();
        for property in &vendor {
            if let (Some(prefix), Some(namespace)) =
                (property.prefix.as_deref(), property.namespace.as_deref())
                && !namespaces.iter().any(|(p, _)| *p == prefix)
            {
                namespaces.push((prefix, namespace));
            }
        }

        let label = namespaces
            .iter()
            .map(|(prefix, namespace)| format!("{prefix}: {namespace}"))
            .collect::<Vec<_>>()
            .join(", ");

        let vendor_widest = vendor
            .iter()
            .map(|p| p.name.len())
            .max()
            .unwrap_or(0)
            .max(20);

        writeln!(out, "    vendor properties ({label})")?;
        for property in &vendor {
            let value = render_value(&property.value, prefixes);
            writeln!(
                out,
                "      {:<vendor_widest$} {}",
                property.name,
                truncate(&value, 100)
            )?;
        }
    }

    // Every remaining property not already shown as an edge above — an edge
    // covers exactly the IRI-valued properties (see `is_edge_property`), so
    // this is the literal-valued remainder plus any `Other`-kind edge whose
    // value did not parse as an IRI (there are none in the corpus, but the
    // filter is by content, not by assumption).
    for property in object
        .properties
        .iter()
        .filter(|p| !p.is_vendor() && !is_edge_property(p))
    {
        let value = render_value(&property.value, prefixes);
        writeln!(
            out,
            "    {:<widest$} {}",
            property.name,
            truncate(&value, 100)
        )?;
    }

    Ok(())
}

/// `BlockHashes` objects hold two distinct algorithms that must never
/// share a label. `hash (SHA512)` (below, from [`write_hash`]) is the
/// recorded digest **of the segment as a whole**, computed with whatever
/// algorithm the acquiring tool chose for `blockHashesHash` — SHA-512 in
/// every corpus fixture. It is *not* the algorithm the per-chunk block hashes
/// *inside* that segment use, which is named only by the segment's own ARN
/// suffix (`blockhash.md5`, `.sha1`, `.sha256`, `.blake2b`, `.sha512`) and
/// appears in no `aff4:hash` triple on the object.
///
/// This prints that content algorithm — the `holds` line — ahead of the
/// digest, so a reader sees both scopes named before either digest. When the
/// suffix is absent or unrecognized, `holds` says so explicitly rather than
/// guessing a format detail.
fn write_block_hashes_header(
    out: &mut impl Write,
    object: &Aff4Object,
    widest: usize,
) -> std::io::Result<()> {
    // Shared with JSON's `BlockHashesInfo` (`model.rs`) via
    // `Aff4Object::block_hashes_info`, so the two surfaces cannot drift on
    // which ARN suffixes are recognized.
    let info = object.block_hashes_info();
    let parent = info.as_ref().and_then(|i| i.of_stream.as_deref());

    match info.as_ref().and_then(|i| i.content_algorithm.as_deref()) {
        Some(algorithm) => {
            writeln!(
                out,
                "    {:<widest$} per-block {algorithm} digests",
                "holds"
            )?;
        }
        None => writeln!(out, "    {:<widest$} not stated by this container", "holds")?,
    }

    if let Some(parent) = parent {
        writeln!(out, "    {:<widest$} {} (ARN parent)", "of stream", parent)?;
    }

    Ok(())
}

/// Write one recorded digest line, plus its full hex value on the following
/// line, plus whatever cross-reference note applies.
///
/// Two notes are possible, both label-scope findings:
///
/// - On a `BlockHashes` object: this digest is of the segment as a
///   whole, not of the per-block hashes the segment holds (see
///   [`write_block_hashes_header`], printed just above this line).
/// - On the `blockMapHashSHA512`/`blockMapHash` pair v1.0a §6.2
///   requires on a `DiskImage`/`Map`: both lines carry the identical value,
///   spec-mandated at two locations, not a coincidence or a contradiction.
fn write_hash(
    out: &mut impl Write,
    object: &Aff4Object,
    hash: &StoredHash,
    widest: usize,
) -> std::io::Result<()> {
    writeln!(
        out,
        "    {:<widest$} {}",
        format!("{} ({})", hash.predicate, hash.algorithm),
        StoredHash::PROVENANCE
    )?;
    writeln!(out, "      {}", hash.hex)?;

    if object.role == ObjectRole::BlockHashes && hash.predicate == "hash" {
        writeln!(
            out,
            "      This is the recorded digest of the segment as a whole. It does not \
             describe the algorithm of the block hashes the segment holds — see \"holds\" \
             above."
        )?;
    }

    if hash.predicate == "hash"
        && matches!(
            hash.algorithm,
            HashAlgorithm::BlockMapSha512 | HashAlgorithm::BlockMapSha256
        )
    {
        writeln!(
            out,
            "      Spec §6.2 records this value twice: also as blockMapHash on the map \
             below. Both readings are shown as recorded; this command recomputes neither."
        )?;
    }
    if hash.predicate == "blockMapHash" {
        writeln!(
            out,
            "      Same value as hash ({}) on the disk image above (spec §6.2).",
            block_map_hash_variant(&hash.algorithm)
        )?;
    }

    Ok(())
}

/// The `blockMapHashSHA512`/`blockMapHashSHA256`-style datatype name a
/// `Map`'s plain `blockMapHash` (typed `^^aff4:SHA512`/`^^aff4:SHA256`)
/// corresponds to on its `DiskImage` counterpart,
/// cross-reference note.
fn block_map_hash_variant(algorithm: &HashAlgorithm) -> String {
    match algorithm {
        HashAlgorithm::Sha512 => "blockMapHashSHA512".to_owned(),
        HashAlgorithm::Sha256 => "blockMapHashSHA256".to_owned(),
        other => other.to_string(),
    }
}

/// Whether `property` is already represented in [`Aff4Object::edges`].
///
/// `container.rs`'s `build_object` calls `edge_for` on every statement before
/// deciding whether it also becomes a `Property` — every property whose value
/// is an IRI (other than `aff4:contains`, which becomes neither) has exactly
/// one corresponding edge. Filtering on that, rather than matching predicate
/// names, stays correct even for an edge kind this build does not recognize:
/// an unrecognized IRI-valued predicate is still `EdgeKind::Other` and still
/// printed as an edge, so listing it again as a bare property would duplicate
/// the line rather than add information.
fn is_edge_property(property: &aff4tools::Property) -> bool {
    property.value.as_iri().is_some()
}

/// Write one graph edge: the relationship phrase, the object it points to
/// (with its role, where known), and the raw predicate in parentheses.
///
/// `edge.to` is qualified the same way a type or vendor value would be
/// (`qualified_name`) before printing. Most edges point at another object's
/// `aff4://` ARN, which already reads fine unqualified, but a symbolic-stream
/// reference such as `aff4:mapGapDefaultStream`'s target
/// (`http://aff4.org/Schema#Zero`) is a bare AFF4-namespace IRI, and printing
/// it raw — while every neighboring edge prints a phrase — is B5's handover
/// item 2. Qualifying it renders `aff4:Zero`, consistent with how the rest of
/// the report already treats AFF4-namespace IRIs.
fn write_edge(
    out: &mut impl Write,
    object: &Aff4Object,
    edge: &aff4tools::GraphEdge,
    prefixes: &[(String, String)],
    widest: usize,
) -> std::io::Result<()> {
    let target = qualify_edge_target(&edge.to, prefixes);
    writeln!(
        out,
        "    {:<widest$} {} ({})",
        edge.kind.label(),
        target,
        edge_predicate(&edge.kind)
    )?;
    let _ = object; // reserved for a future role-of-target lookup; see B6.
    Ok(())
}

/// Render an edge target for display: an AFF4-namespace IRI (a symbolic
/// stream such as `aff4:Zero`, `aff4:UnknownData`, `aff4:UnreadableData`)
/// renders prefixed; anything else — chiefly another object's `aff4://` ARN —
/// prints unchanged.
fn qualify_edge_target(to: &str, prefixes: &[(String, String)]) -> String {
    if let Some(name) = to
        .strip_prefix(aff4tools::lexicon::STANDARD_NAMESPACE)
        .or_else(|| to.strip_prefix(aff4tools::lexicon::LEGACY_NAMESPACE))
    {
        return format!("aff4:{name}");
    }
    if to.starts_with("http://") || to.starts_with("https://") {
        return prefixed(to, prefixes).unwrap_or_else(|| to.to_owned());
    }
    to.to_owned()
}

/// The predicate local name an [`EdgeKind`] was built from.
///
/// [`GraphEdge`] does not carry the source predicate for its named variants —
/// each is built from exactly one predicate (see `container.rs`'s
/// `classify_edge`), so the mapping back is total and static. Only
/// [`EdgeKind::Other`] carries its own name, since it exists precisely for
/// predicates this build does not otherwise recognize.
fn edge_predicate(kind: &EdgeKind) -> String {
    match kind {
        EdgeKind::Describes | EdgeKind::TargetStream => "aff4:target".to_owned(),
        EdgeKind::DataStream => "aff4:dataStream".to_owned(),
        EdgeKind::DependentStream => "aff4:dependentStream".to_owned(),
        EdgeKind::StoredIn => "aff4:stored".to_owned(),
        EdgeKind::Other(name) => format!("aff4:{name}"),
    }
}

/// An IRI in prefixed form where a binding covers it, else its local name.
///
/// AFF4's own namespace is left bare — qualifying every standard type would be
/// noise — so a prefix in the output means "this is an extension".
fn qualified_name(iri: &str, prefixes: &[(String, String)]) -> String {
    if iri.starts_with(aff4tools::lexicon::STANDARD_NAMESPACE)
        || iri.starts_with(aff4tools::lexicon::LEGACY_NAMESPACE)
    {
        return local_name(iri).to_owned();
    }

    prefixed(iri, prefixes).unwrap_or_else(|| local_name(iri).to_owned())
}

/// Render an RDF value, qualifying an IRI object where a prefix is bound.
///
/// `bbt:APFST2ContainerType` rather than the full IRI, which is unreadable in a
/// report and pushes real content off the line.
fn render_value(value: &aff4tools::Value, prefixes: &[(String, String)]) -> String {
    match value.as_iri() {
        Some(iri) => prefixed(iri, prefixes).unwrap_or_else(|| format!("<{iri}>")),
        None => value.lexical().to_owned(),
    }
}

/// The prefixed form of an IRI, longest matching namespace winning.
fn prefixed(iri: &str, prefixes: &[(String, String)]) -> Option<String> {
    prefixes
        .iter()
        .filter(|(_, namespace)| iri.starts_with(namespace.as_str()))
        .max_by_key(|(_, namespace)| namespace.len())
        .map(|(name, namespace)| format!("{name}:{}", &iri[namespace.len()..]))
}

/// Describe where the volume ARN came from (v1.0a §5.4 allows two locations).
pub(crate) fn describe_arn_source(source: &aff4tools::ArnSource) -> String {
    match source {
        aff4tools::ArnSource::ZipComment => "from the ZIP comment".into(),
        aff4tools::ArnSource::ContainerDescription => "from container.description".into(),
        aff4tools::ArnSource::Both { consistent: true } => {
            "from both ZIP comment and container.description".into()
        }
        aff4tools::ArnSource::Both { consistent: false } => {
            "***> ZIP comment and container.description DISAGREE — see deviations".into()
        }
        aff4tools::ArnSource::Metadata => "recovered from information.turtle".into(),
    }
}

/// The local name of an IRI: the part after the last `#` or `/`.
fn local_name(iri: &str) -> &str {
    iri.rsplit_once(['#', '/']).map_or(iri, |(_, name)| name)
}

/// Shorten a long property value for display.
///
/// Only ever applied to free-text properties — never to a digest, an ARN, or a
/// size, all of which must be reported in full.
fn truncate(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_string();
    }
    let kept: String = text.chars().take(limit).collect();
    format!("{kept}… ({} characters)", text.chars().count())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Build an object carrying exactly `types`, for the content-type cases.
    ///
    /// The role is derived by `ObjectRole::from_types`, the same call the
    /// container builder makes, so these fixtures cannot claim a role their
    /// types would not produce.
    fn typed(arn: &str, types: &[&str]) -> Aff4Object {
        let iris: Vec<std::sync::Arc<str>> = types
            .iter()
            .map(|t| std::sync::Arc::from(format!("http://aff4.org/Schema#{t}").as_str()))
            .collect();
        let locus = aff4tools::Locus::new(std::path::PathBuf::from("test.aff4"));
        Aff4Object {
            arn: aff4tools::Arn::parse(arn, &locus).expect("test ARN must parse"),
            role: ObjectRole::from_types(&iris),
            types: iris,
            size: None,
            hashes: Vec::new(),
            stored_in: None,
            locality: Locality::Undeclared,
            properties: Vec::new(),
            edges: Vec::new(),
            block_hashes: None,
        }
    }

    /// The counts a real parse would have accumulated for these objects.
    ///
    /// `ContainerSummary::counts` is filled during the parse, not derived from
    /// `objects`, precisely so it stays right when `objects` is a subset. A
    /// test building a summary by hand has no parse, so it derives them here —
    /// which is sound only because these fixtures retain every object.
    fn counts_of(objects: &[Aff4Object]) -> aff4tools::ObjectCounts {
        let mut counts = aff4tools::ObjectCounts::default();
        for object in objects {
            let bitstream = object
                .hashes
                .iter()
                .any(|h| h.predicate == "hash" || h.predicate == "blockMapHash");
            counts.observe(&object.role, bitstream);
        }
        counts
    }

    /// Wrap objects in the minimum summary the report functions read.
    ///
    /// No manifest and no deviations: this exists to exercise ordering, and a
    /// manifest would route objects through tier 2 instead of the spine walk.
    fn summary_of(objects: Vec<Aff4Object>) -> ContainerSummary {
        let locus = aff4tools::Locus::new(std::path::PathBuf::from("test.aff4"));
        let counts = counts_of(&objects);
        ContainerSummary {
            source_path: std::path::PathBuf::from("test.aff4"),
            volume: aff4tools::VolumeInfo {
                arn: aff4tools::Arn::parse("aff4://11111111-1111-1111-1111-111111111111", &locus)
                    .expect("volume ARN must parse"),
                arn_source: aff4tools::ArnSource::ZipComment,
            },
            generation: aff4tools::Generation::PyAff4Logical,
            version: None,
            objects,
            segments: aff4tools::SegmentSummary {
                count: 0,
                kinds: Vec::new(),
            },
            counts,
            deviations: Vec::new(),
            prefixes: Vec::new(),
            manifest: Vec::new(),
            manifest_disagreements: Vec::new(),
        }
    }

    /// Ordering must stay linear in the object count.
    ///
    /// `order_objects` was O(n²) three times over: `by_arn` scanned every
    /// object per spine edge, block-hash children were found by scanning every
    /// object per node, and incoming spine edges by scanning every object's
    /// edges per node. An AFF4-L acquisition makes every file its own spine
    /// root, so all three compounded — `info` on a synthetic 40,000-object
    /// container took **251 seconds**, of which the parse was under one.
    /// `conformance`, which parses the same turtle and does not order, took
    /// 0.5 s. That gap is what identified this as report-side.
    ///
    /// The corpus cannot catch this: its largest container describes ten
    /// objects. Measured by **growth ratio** rather than wall-clock, following
    /// `turtle::subject_lookup_and_rendering_stay_linear` — a structural check
    /// that an index exists would still pass if the walk ignored it.
    #[test]
    fn ordering_objects_stays_linear() {
        // Each file is a spine root pointing at its own stream, and each
        // stream carries a block-hash child. That shape drives all three of
        // the quadratic sites: `by_arn` resolves the edge, the child lookup
        // finds the block hashes, and the reverse index finds the file from
        // the stream. A fixture of bare objects with no edges exercises only
        // the third, and would pass with the other two reverted.
        fn order(files: usize) -> std::time::Duration {
            const VOL: &str = "aff4://11111111-1111-1111-1111-111111111111";
            let mut objects = Vec::with_capacity(files * 3);
            for i in 0..files {
                let file = format!("{VOL}//f/{i:07}.txt");
                let stream = format!("{VOL}/stream{i:07}");
                let mut image = typed(&file, &["FileImage", "Image"]);
                image.edges.push(aff4tools::GraphEdge {
                    kind: EdgeKind::DataStream,
                    to: stream.clone(),
                });
                objects.push(image);
                objects.push(typed(&stream, &["ImageStream"]));
                objects.push(typed(&format!("{stream}/blockhash.sha1"), &["BlockHashes"]));
            }

            let expected = objects.len();
            let summary = summary_of(objects);
            let start = std::time::Instant::now();
            let ordered = order_objects(&summary);
            let elapsed = start.elapsed();
            assert_eq!(
                ordered.len(),
                expected,
                "every object must be ordered exactly once"
            );
            elapsed
        }

        // Warm up so the first allocation does not land inside a measurement.
        let _ = order(500);

        let small = order(1_000);
        let large = order(8_000);

        // The quadratic form cost ~64x here; the linear form costs ~8x.
        assert!(
            large.as_secs_f64() < small.as_secs_f64() * 24.0,
            "ordering 8x the objects took {large:?} against {small:?} for the \
             smaller set — that growth is superlinear, so the walk is scanning \
             every object per node again"
        );
    }

    /// A discontiguous disk image names its shape.
    ///
    /// **No corpus container is discontiguous** — the type comes from
    /// aff4-cpp-lite.
    #[test]
    fn a_discontiguous_disk_image_says_so() {
        let objects = vec![typed(
            "aff4://11111111-1111-1111-1111-111111111111",
            &["DiscontiguousImage", "DiskImage", "Image"],
        )];
        assert_eq!(
            describe_content(&objects, &counts_of(&objects)),
            "DiskImage (discontiguous)"
        );
    }

    /// A disk image declaring no shape is named without an invented qualifier.
    #[test]
    fn a_disk_image_without_a_shape_gets_no_qualifier() {
        let objects = vec![typed(
            "aff4://22222222-2222-2222-2222-222222222222",
            &["DiskImage", "Image"],
        )];
        assert_eq!(
            describe_content(&objects, &counts_of(&objects)),
            "DiskImage"
        );
    }

    /// A disk image wins over logical objects in the same container.
    ///
    /// Nothing in the corpus mixes them, but the order the cases are tried is a
    /// decision rather than an accident, so it is pinned.
    #[test]
    fn a_disk_image_outranks_logical_objects() {
        let objects = vec![
            typed(
                "aff4://33333333-3333-3333-3333-333333333333/f",
                &["FileImage", "Image"],
            ),
            typed(
                "aff4://33333333-3333-3333-3333-333333333333",
                &["ContiguousImage", "DiskImage", "Image"],
            ),
        ];
        assert_eq!(
            describe_content(&objects, &counts_of(&objects)),
            "DiskImage (contiguous)"
        );
    }

    /// An empty container states the absence rather than printing nothing.
    #[test]
    fn no_content_types_are_stated_as_an_absence() {
        assert_eq!(
            describe_content(&[], &aff4tools::ObjectCounts::default()),
            "not stated by this container"
        );
    }

    /// Digests and ARNs must never be shortened; only free text may be.
    #[test]
    fn truncation_reports_what_it_removed() {
        let short = "abc";
        assert_eq!(truncate(short, 10), "abc");

        let long = "x".repeat(50);
        let out = truncate(&long, 10);
        assert!(out.starts_with("xxxxxxxxxx"), "{out}");
        assert!(out.contains("50 characters"), "{out}");
    }

    #[test]
    fn local_names_drop_the_namespace() {
        assert_eq!(local_name("http://aff4.org/Schema#DiskImage"), "DiskImage");
        assert_eq!(local_name("http://afflib.org/2009/aff4#map"), "map");
        assert_eq!(local_name("bare"), "bare");
    }

    #[test]
    fn writer_profile_matches_the_exact_blackbag_namespace() {
        let prefixes = vec![("bbt".to_owned(), BLACKBAG_NAMESPACE.to_owned())];
        assert!(writer_profile_note(&prefixes).is_some());
    }

    /// Detection must key on the namespace URI, never the prefix label — a
    /// writer is free to bind that namespace to any prefix name.
    #[test]
    fn writer_profile_matches_a_renamed_prefix_with_the_same_namespace() {
        let prefixes = vec![("vendor_xyz".to_owned(), BLACKBAG_NAMESPACE.to_owned())];
        assert!(writer_profile_note(&prefixes).is_some());
    }

    #[test]
    fn writer_profile_does_not_match_a_different_namespace() {
        let prefixes = vec![("bbt".to_owned(), "https://example.com/Schema#".to_owned())];
        assert!(writer_profile_note(&prefixes).is_none());
    }

    #[test]
    fn writer_profile_does_not_match_an_empty_prefix_list() {
        assert!(writer_profile_note(&[]).is_none());
    }

    /// The note's wording is fixed by user ruling R2 and must not drift: it
    /// hedges ("references to suggest") rather than asserting which tool
    /// wrote the container, and it names the two files without the tool
    /// stating or checking that they exist.
    #[test]
    fn writer_profile_note_text_is_hedged_and_names_the_adjacent_files() {
        let prefixes = vec![("bbt".to_owned(), BLACKBAG_NAMESPACE.to_owned())];
        let note = writer_profile_note(&prefixes).expect("note");
        assert!(note.contains("references to suggest"), "{note}");
        assert!(note.contains("Acquisition Log.txt"), "{note}");
        assert!(note.contains("Device.log"), "{note}");
    }

    #[test]
    fn arn_source_disagreement_is_stated_loudly() {
        let text = describe_arn_source(&aff4tools::ArnSource::Both { consistent: false });
        assert!(text.contains("DISAGREE"), "{text}");
    }
}
