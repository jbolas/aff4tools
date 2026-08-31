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

HEADER = """@prefix aff4: <http://aff4.org/Schema#> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
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
    args = ap.parse_args()

    dirs = args.dirs or max(1, args.files // 100)

    # Built as one string then written once: streaming into the ZIP member
    # would need an open handle across the whole loop for no benefit at these
    # sizes, and the turtle is the artifact being measured.
    parts = [HEADER, f"<{VOLUME}> a aff4:ZipVolume .\n\n"]
    for n in range(dirs):
        parts.append(folder_block(n, args.minimal))
    for i in range(args.files):
        parts.append(file_block(i, dirs, args.minimal))
    turtle = "".join(parts)

    z = zipfile.ZipFile(args.output, "w", zipfile.ZIP_DEFLATED, allowZip64=True)
    z.writestr("container.description", VOLUME)
    z.writestr("version.txt", "major=1\nminor=1\ntool=aff4tools-fixture\n")
    z.writestr("information.turtle", turtle)
    if not args.no_segments:
        # One stored member per file. Content is a single byte: this fixture
        # measures metadata scale, not data volume.
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
    objects = args.files + dirs
    print(f"{args.output}")
    print(f"  objects   : {objects:,} ({args.files:,} files, {dirs:,} folders)")
    print(
        f"  turtle    : {info.file_size / 1048576:.1f} MB uncompressed, "
        f"{info.compress_size / 1048576:.2f} MB stored"
    )
    print(f"  per object: {info.file_size / objects:.0f} bytes of turtle")


if __name__ == "__main__":
    main()
