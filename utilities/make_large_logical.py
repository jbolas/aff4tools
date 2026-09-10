#!/usr/bin/env python3
"""Generate a large AFF4-L container with realistic per-file metadata, for testing.

Per file, matching `AFF4-L/unicode.aff4` and this project's own writer:

    a               aff4:FileImage, aff4:Image, aff4:ImageStream
    aff4:birthTime, lastAccessed, lastWritten, recordChanged   (4 timestamps)
    aff4:hash                                    MD5 + SHA1    (2 digests)
    aff4:originalFileName                        full path
    aff4:size, chunkSize, chunksInSegment, compressionMethod
    aff4:stored                                  volume ARN

Folders four timestamps, a path, and a size.

**This writes a container that is structurally valid but whose bevies are
stubs.** It is a metadata-scale fixture, for measuring how `info` behaves when
`information.turtle` is enormous.

Usage:
    python3 make_large_logical.py OUT.aff4 --files 400000 [--dirs 4000]
    python3 make_large_logical.py OUT.aff4 --files 1000000 --minimal

`--minimal` writes the three-property shape the original fixture used, so the
two can be compared directly on the same file count.
"""

import argparse
import hashlib
import zipfile

VOLUME = "aff4://7f3d1e88-4b21-4c9a-9e55-2a6b0c1d4e77"
SNAPPY = "http://code.google.com/p/snappy/"
# The one image stream every map-form file addresses, which is the point of
# AFF4-L v1.0-ALPHA section 6.3: "implementations may choose to store the
# datastreams of multiple source files in a single Image Stream."
SHARED_STREAM = "aff4://0947bfd0-1265-42d3-95b6-8d7bed108e9b"

HEADER = """@prefix aff4: <http://aff4.org/Schema#> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
@prefix aff4l: <http://aff4.org/Schema/2022/#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .

"""


def timestamps(i: int) -> tuple[str, str, str, str]:
    """Four distinct timestamps, varying per file."""
    day = 1 + (i % 28)
    hour = i % 24
    minute = (i * 7) % 60
    second = (i * 13) % 60
    base = f"2026-03-{day:02d}T{hour:02d}:{minute:02d}:{second:02d}Z"
    later = f"2026-03-{day:02d}T{hour:02d}:{minute:02d}:{(second + 1) % 60:02d}Z"
    return base, later, base, base


def digests(i: int) -> tuple[str, str]:
    """MD5 and SHA1 of the file's notional content: unique per file."""
    payload = f"file-{i:09d}-content".encode()
    return hashlib.md5(payload).hexdigest(), hashlib.sha1(payload).hexdigest()


def file_block(i: int, dirs: int, minimal: bool) -> str:
    """One file's triples."""
    folder = i % dirs if dirs else 0
    path = f"/acquired/dir{folder:05d}/file{i:09d}.dat"
    arn = f"<{VOLUME}/{path}>"
    size = 4096 + (i % 1_000_000)

    if minimal:
        return (
            f"{arn} a aff4:FileImage, aff4:Image ;\n"
            f'    aff4:originalFileName ".{path}"^^xsd:string ;\n'
            f"    aff4:size {size} .\n\n"
        )

    birth, accessed, written, changed = timestamps(i)
    md5, sha1 = digests(i)
    return (
        f"{arn} a aff4:FileImage,\n"
        f"        aff4:Image,\n"
        f"        aff4:ImageStream ;\n"
        f'    aff4:birthTime "{birth}"^^xsd:dateTime ;\n'
        f"    aff4:chunkSize 32768 ;\n"
        f"    aff4:chunksInSegment 1024 ;\n"
        f"    aff4:compressionMethod <{SNAPPY}> ;\n"
        f'    aff4:hash "{md5}"^^aff4:MD5,\n'
        f'        "{sha1}"^^aff4:SHA1 ;\n'
        f'    aff4:lastAccessed "{accessed}"^^xsd:dateTime ;\n'
        f'    aff4:lastWritten "{written}"^^xsd:dateTime ;\n'
        f'    aff4:originalFileName ".{path}"^^xsd:string ;\n'
        f'    aff4:recordChanged "{changed}"^^xsd:dateTime ;\n'
        f"    aff4:size {size} ;\n"
        f"    aff4:stored <{VOLUME}> .\n\n"
    )


def folder_block(n: int, minimal: bool) -> str:
    """One folder's triples."""
    path = f"/acquired/dir{n:05d}"
    arn = f"<{VOLUME}/{path}>"
    if minimal:
        return f"{arn} a aff4:FolderImage, aff4:Image ;\n    aff4:size 0 .\n\n"

    birth, accessed, written, changed = timestamps(n)
    return (
        f"{arn} a aff4:Folder,\n"
        f"        aff4:FolderImage ;\n"
        f'    aff4:birthTime "{birth}"^^xsd:dateTime ;\n'
        f'    aff4:lastAccessed "{accessed}"^^xsd:dateTime ;\n'
        f'    aff4:lastWritten "{written}"^^xsd:dateTime ;\n'
        f'    aff4:originalFileName ".{path}/"^^xsd:string ;\n'
        f'    aff4:recordChanged "{changed}"^^xsd:dateTime ;\n'
        f"    aff4:size 4096 .\n\n"
    )


# --- AFF4-L v1.0-ALPHA section 6 storage forms -------------------------------
#
# Each form is emitted at scale so the study can measure what it costs the
# metadata: turtle bytes, triple count, and the subjects a reader must build.
# Bevies stay stubs, as elsewhere in this generator, because what is being
# measured is the metadata and not the content.

import base64
import uuid


def _guid_arn(i: int) -> str:
    """A stable per-file GUID ARN, as AFF4-L v1.0-ALPHA section 2 requires.

    Derived from the index so a run is reproducible: the study must be able to
    rebuild the same container and get the same measurements.
    """
    return "aff4://" + str(uuid.UUID(int=(0x9E2C5B71 << 96) + i, version=4))


def v21_file_block(i: int, dirs: int, form: str, content_bytes: int) -> str:
    """One v2.1 file subject, stored in the named AFF4-L section 6 form."""
    folder = i % dirs if dirs else 0
    path = f"/acquired/dir{folder:05d}/file{i:09d}.dat"
    arn = _guid_arn(i)
    birth, accessed, written, changed = timestamps(i)
    md5, sha1 = digests(i)

    common = (
        f'    aff4:birthTime "{birth}"^^xsd:dateTime ;\n'
        f'    aff4:lastAccessed "{accessed}"^^xsd:dateTime ;\n'
        f'    aff4:lastWritten "{written}"^^xsd:dateTime ;\n'
        f'    aff4:recordChanged "{changed}"^^xsd:dateTime ;\n'
        f'    aff4:fileName "file{i:09d}.dat" ;\n'
        f'    aff4:originalPathName "{path}" ;\n'
        f"    aff4:size {content_bytes} ;\n"
        f"    aff4:stored <{VOLUME}> ;\n"
    )
    hashes = (
        f'    aff4:hash "{md5}"^^aff4:MD5,\n'
        f'        "{sha1}"^^aff4:SHA1 ;\n'
    )

    if form == "in-metadata":
        # The bytes themselves, base64 in the turtle. This is the form that
        # grows the metadata segment, which docs/RDF-scalability.md identifies
        # as the one cost that scales with file size rather than with what is
        # retained.
        payload = base64.b64encode(bytes((i + j) % 251 for j in range(content_bytes)))
        return (
            f"<{arn}> a aff4:FileImage,\n        aff4:Image ;\n"
            + common + hashes
            + f'    aff4l:dataStream "{payload.decode()}"^^xsd:base64Binary .\n\n'
        )

    if form == "zipsegment":
        return (
            f"<{arn}> a aff4:FileImage,\n        aff4:Image,\n"
            f"        aff4:ZipSegment ;\n" + common + hashes.rstrip(" ;\n") + " .\n\n"
        )

    if form == "imagestream":
        return (
            f"<{arn}> a aff4:FileImage,\n        aff4:Image,\n"
            f"        aff4:ImageStream ;\n"
            f"    aff4:chunkSize 32768 ;\n"
            f"    aff4:chunksInSegment 1024 ;\n"
            f"    aff4:compressionMethod <{SNAPPY}> ;\n"
            + common + hashes.rstrip(" ;\n") + " .\n\n"
        )

    if form == "map":
        # AFF4-L v1.0-ALPHA section 6.3, first form: the Map type added to the
        # file image instance, sharing one image stream across every file.
        return (
            f"<{arn}> a aff4:FileImage,\n        aff4:Image,\n"
            f"        aff4:Map ;\n"
            f"    aff4:dependentStream <{SHARED_STREAM}> ;\n"
            + common + hashes.rstrip(" ;\n") + " .\n\n"
        )

    raise ValueError(f"unknown form {form!r}")


def v21_substream_block(i: int, parent: str, attrs: int, attr_bytes: int) -> str:
    """A file's extended attributes, each its own subject.

    One subject per attribute, which is what the writer emits. The study uses
    this to measure what substream support costs the metadata per file.
    """
    out = []
    for a in range(attrs):
        child = _guid_arn(0x40000000 + i * 8 + a)
        payload = base64.b64encode(bytes((i + a) % 251 for _ in range(attr_bytes)))
        out.append(
            f"<{child}> a aff4:FileExtendedAttribute ;\n"
            f'    aff4:name "com.example.attr{a}" ;\n'
            f"    aff4:target <{parent}> ;\n"
            f"    aff4:size {attr_bytes} ;\n"
            f'    aff4l:dataStream "{payload.decode()}"^^xsd:base64Binary .\n\n'
        )
    return "".join(out)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("output")
    ap.add_argument("--files", type=int, required=True)
    ap.add_argument("--dirs", type=int, default=0, help="default: files/100")
    ap.add_argument(
        "--minimal",
        action="store_true",
        help="three properties per file, for comparison with the old fixture",
    )
    ap.add_argument(
        "--no-segments",
        action="store_true",
        help="skip per-file ZIP members; metadata only, far faster to build",
    )
    ap.add_argument(
        "--form",
        choices=["in-metadata", "zipsegment", "imagestream", "map"],
        help="write a v2.1 container in this AFF4-L v1.0-ALPHA section 6 "
             "storage form, instead of the legacy v1.1 shape",
    )
    ap.add_argument(
        "--content-bytes",
        type=int,
        default=256,
        help="per-file content size the metadata claims (default 256). Sets "
             "the base64 payload for --form in-metadata.",
    )
    ap.add_argument(
        "--xattrs",
        type=int,
        default=0,
        help="extended attributes per file, each its own subject",
    )
    ap.add_argument(
        "--xattr-bytes",
        type=int,
        default=32,
        help="bytes per extended attribute (default 32)",
    )
    args = ap.parse_args()

    dirs = args.dirs or max(1, args.files // 100)

    # Built as one string then written once: streaming into the ZIP member
    # would need an open handle across the whole loop for no benefit at these
    # sizes, and the turtle is the artifact being measured.
    parts = [HEADER, f"<{VOLUME}> a aff4:ZipVolume .\n\n"]
    for n in range(dirs):
        parts.append(folder_block(n, args.minimal))
    if args.form:
        # Every map-form file addresses one shared image stream, so it is
        # declared once rather than per file.
        if args.form == "map":
            parts.append(
                f"<{SHARED_STREAM}> a aff4:ImageStream ;\n"
                f"    aff4:chunkSize 32768 ;\n"
                f"    aff4:chunksInSegment 1024 ;\n"
                f"    aff4:compressionMethod <{SNAPPY}> ;\n"
                f"    aff4:size {args.files * args.content_bytes} ;\n"
                f"    aff4:stored <{VOLUME}> .\n\n"
            )
        for i in range(args.files):
            parts.append(
                v21_file_block(i, dirs, args.form, args.content_bytes)
            )
            if args.xattrs:
                parts.append(
                    v21_substream_block(
                        i, _guid_arn(i), args.xattrs, args.xattr_bytes
                    )
                )
    else:
        for i in range(args.files):
            parts.append(file_block(i, dirs, args.minimal))
    turtle = "".join(parts)

    z = zipfile.ZipFile(args.output, "w", zipfile.ZIP_DEFLATED, allowZip64=True)
    z.writestr("container.description", VOLUME)
    version = "major=2\nminor=1\n" if args.form else "major=1\nminor=1\n"
    z.writestr("version.txt", version + "tool=aff4tools-fixture\n")
    z.writestr("information.turtle", turtle)
    if not args.no_segments:
        # One stored member per file. Content is a single byte: this fixture
        # measures metadata scale, not data volume.
        #
        # The in-metadata form stores nothing here by definition — its bytes
        # are in the turtle — which is the whole point of measuring it.
        if args.form in ("in-metadata", "map"):
            # Neither stores a member named by the file's own ARN. The
            # in-metadata form carries its bytes in the turtle; the map form
            # addresses one shared image stream, and writing a per-file member
            # would make each file look segment-stored and report as an
            # AFF4-L 2019 section 3.8 departure that the fixture does not mean.
            pass
        elif args.form:
            for i in range(args.files):
                z.writestr(_guid_arn(i), b"x", zipfile.ZIP_STORED)
        else:
            for i in range(args.files):
                folder = i % dirs
                z.writestr(
                    f"/acquired/dir{folder:05d}/file{i:09d}.dat",
                    b"x",
                    zipfile.ZIP_STORED,
                )
    z.comment = VOLUME.encode()
    z.close()

    info = zipfile.ZipFile(args.output).getinfo("information.turtle")
    objects = args.files + dirs + args.files * args.xattrs
    print(f"{args.output}")
    print(f"  objects   : {objects:,} ({args.files:,} files, {dirs:,} folders)")
    print(
        f"  turtle    : {info.file_size / 1048576:.1f} MB uncompressed, "
        f"{info.compress_size / 1048576:.2f} MB stored"
    )
    print(f"  per object: {info.file_size / objects:.0f} bytes of turtle")


if __name__ == "__main__":
    main()
