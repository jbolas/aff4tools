#!/usr/bin/env python3
"""Create test AFF4 containers.

Purpose: a fixture for the parallel read path. The reference corpus tops out
at one bevy per stream, so the reorder window never fills and two deadlocks in
`src/parallel.rs` reached a real container without a test catching them.

Contents are lorem ipsum. No real-world data. This is obviously not a test
of how real-world data may behave during compression and hashing.

Everything the verifier checks is written for real, so the container verifies
clean rather than merely parsing:
  - per-chunk MD5 and SHA-1 block hashes, one segment per bevy
  - SHA-512 over each block-hash segment (blockHashesHash)
  - map, idx segments and their SHA-512 digests
  - mapHash   = SHA512(map || idx)          [no mapPath here]
  - blockMapHash = SHA512(the digests above, concatenated raw)
  - MD5 and SHA-256 linear hashes over the whole stream
"""

import argparse
import hashlib
import struct
import zipfile
from pathlib import Path

VOLUME = "aff4://11111111-2222-3333-4444-555555555555"
IMAGE = "aff4://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
STREAM = "aff4://99999999-8888-7777-6666-555555555555"
MAP = "aff4://12121212-3434-5656-7878-909090909090"

LOREM = (
    b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod "
    b"tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim "
    b"veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea "
    b"commodo consequat. Duis aute irure dolor in reprehenderit in voluptate "
    b"velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint "
    b"occaecat cupidatat non proident, sunt in culpa qui officia deserunt "
    b"mollit anim id est laborum. Bibendum!"
)


# Compression codecs, by the IRI the standard assigns each one.
#
# These are identifiers, not live links: spec 3.3 keeps the historical Google
# Code URLs deliberately, for compatibility with containers already written.
# Do not "modernise" them — a reader matches on the exact string.
CODEC_IRIS = {
    "stored": "http://aff4.org/Schema#compression/stored",
    "snappy": "http://code.google.com/p/snappy/",
    "zlib": "https://www.ietf.org/rfc/rfc1950.txt",
    "deflate": "https://tools.ietf.org/html/rfc1951",
    "lz4": "https://code.google.com/p/lz4/",
}


def compress_chunk(codec: str, data: bytes) -> bytes:
    """Compress one chunk, or return it verbatim when that is no smaller.

    Spec 3.2 makes chunk length the signal: a reader treats
    `len(chunk) == chunkSize` as *stored*, and decompresses otherwise. So a
    compressed form that happens to reach chunkSize would be misread as
    verbatim. Writer guidance in the same section keeps a margin —
    `compressedLen < chunkSize - 16` — and this follows it.

    Incompressible data therefore lands in the container uncompressed even in a
    "snappy" stream. That is correct, and worth knowing when reading a
    generated fixture: not every chunk is an exercise of the codec.
    """
    if codec == "stored":
        return data

    if codec == "snappy":
        import snappy

        out = snappy.compress(data)
    elif codec == "zlib":
        import zlib

        out = zlib.compress(data, 9)
    elif codec == "deflate":
        import zlib

        # Raw DEFLATE (RFC 1951): no zlib header, no Adler-32 trailer. The
        # negative window size is what selects it. AFF4 gives deflate and zlib
        # separate IRIs precisely because they are different byte streams.
        c = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
        out = c.compress(data) + c.flush()
    elif codec == "lz4":
        import lz4.block

        # Raw block format, no size prefix: the chunk size comes from metadata,
        # so a stored length would be redundant and would not match what
        # readers expect.
        out = lz4.block.compress(data, store_size=False)
    else:
        raise ValueError(f"unknown codec {codec}")

    return out if len(out) < len(data) - 16 else data


def escaped(arn: str) -> str:
    """The ARN as a ZIP member path prefix, per spec 5 URI->path mapping."""
    return arn.replace(":", "%3A").replace("/", "%2F")


def chunk_bytes(index: int, chunk: int) -> bytes:
    """Deterministic synthetic content for one chunk, exactly `chunk` bytes."""
    seed = f"[chunk {index:08d}] ".encode()
    body = seed + LOREM * ((chunk // len(LOREM)) + 2)
    return body[:chunk]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate a synthetic AFF4 container for testing.",
        epilog="Contents are lorem ipsum only. Never contains real-world data.",
    )
    parser.add_argument(
        "output", type=Path, help="where to write the container"
    )
    parser.add_argument(
        "--bevies", type=int, default=10_000,
        help="how many bevies the stream spans (default: 10000)",
    )
    parser.add_argument(
        "--chunk-size", type=int, default=512,
        help="bytes per chunk; smaller makes a smaller file (default: 512)",
    )
    parser.add_argument(
        "--chunks-in-segment", type=int, default=1,
        help="chunks per bevy (default: 1, the smallest that hits the count)",
    )
    parser.add_argument(
        "--no-block-hashes", action="store_true",
        help="omit per-chunk block-hash segments, as Cellebrite images do",
    )
    parser.add_argument(
        "--codec", default="stored",
        choices=["stored", "snappy", "zlib", "deflate", "lz4"],
        help="compression applied to each chunk (default: stored). "
             "Needs python-snappy for snappy and lz4 for lz4; zlib and "
             "deflate use the standard library. Note aff4tools declines raw "
             "deflate by design, so such a container reports Unsupported "
             "rather than verifying",
    )
    parser.add_argument(
        "--discontiguous", action="store_true",
        help="leave the second half of the address space uncovered by the "
             "map, and type the image aff4:DiscontiguousImage. Spec 4 fills "
             "such holes from aff4:mapGapDefaultStream, defaulting to "
             "aff4:Zero. No reference container is discontiguous, so this is "
             "the only way to exercise that path",
    )
    parser.add_argument(
        "--gap-stream", default=None,
        help="declare aff4:mapGapDefaultStream explicitly, e.g. aff4:FF. "
             "Only meaningful with --discontiguous; omitted by default, "
             "which is the Cellebrite shape where the spec 4 default applies",
    )
    parser.add_argument(
        "--stripes", type=int, default=1,
        help="split the image across N volumes, written as NAME_1.aff4 … "
             "NAME_N.aff4 (default: 1, a single container)",
    )
    parser.add_argument(
        "--stripe-defect", default="none",
        choices=["none", "missing-metadata", "conflicting-chunk-size"],
        help="write a deliberately broken striped set, to exercise the "
             "decline paths. 'missing-metadata' omits the foreign-stream "
             "stubs, so nothing names the sibling volume and discovery "
             "cannot find it; 'conflicting-chunk-size' has two volumes "
             "declare different chunk sizes for one stream (default: none)",
    )
    parser.add_argument(
        "--arn-order", default="matching",
        choices=["matching", "reversed", "shuffled"],
        help="how the generated ARNs sort relative to the filenames. "
             "'reversed' makes ARN order disagree with filename order, so a "
             "tool inferring stripe order from an ARN sort gets it wrong "
             "(default: matching)",
    )
    args = parser.parse_args()

    out: Path = args.output
    chunk: int = args.chunk_size
    chunks_in_segment: int = args.chunks_in_segment
    bevies: int = args.bevies
    size = chunk * chunks_in_segment * bevies
    write_block_hashes = not args.no_block_hashes

    if args.stripes < 1:
        parser.error("--stripes must be at least 1")
    if args.gap_stream and not args.discontiguous:
        parser.error("--gap-stream needs --discontiguous")
    if args.discontiguous and args.stripes != 1:
        parser.error("--discontiguous is not implemented for striped sets")
    if args.stripes == 1:
        if args.stripe_defect != "none":
            parser.error("--stripe-defect needs --stripes 2 or more")
        build(out, chunk, chunks_in_segment, bevies, size, write_block_hashes,
              args.codec, args.discontiguous, args.gap_stream)
    else:
        build_striped(
            out, chunk, chunks_in_segment, bevies, size,
            write_block_hashes, args.stripes, args.stripe_defect,
            args.arn_order, args.codec,
        )


def build(
    out: Path,
    chunk: int,
    chunks_in_segment: int,
    bevies: int,
    size: int,
    write_block_hashes: bool,
    codec: str = "stored",
    discontiguous: bool = False,
    gap_stream=None,
) -> None:
    stream_dir = escaped(STREAM)
    map_dir = escaped(MAP)

    # Accumulators for the linear hashes and the block-hash tree.
    md5_linear = hashlib.md5()
    sha256_linear = hashlib.sha256()
    blockhash_md5_digests = []
    blockhash_sha1_digests = []

    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        out.unlink()

    # ZIP_STORED throughout: the AFF4 codec is `stored`, and the members are
    # the compressed representation, so no ZIP-level compression either.
    with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED, allowZip64=True) as z:
        # Spec 5.4: container.description MUST be the first member.
        z.writestr("container.description", VOLUME)
        z.writestr("version.txt", "major=1\nminor=0\ntool=aff4tools-synthetic\n")

        for bevy in range(bevies):
            payload = bytearray()
            index = bytearray()
            offset = 0
            for c in range(chunks_in_segment):
                data = chunk_bytes(bevy * chunks_in_segment + c, chunk)

                # The bevy holds the *compressed* form; every digest covers the
                # plaintext. Getting this backwards produces a container that
                # parses and then fails every hash — the failure mode this
                # generator exists to rule out.
                stored = compress_chunk(codec, data)
                payload += stored
                # Bevy index entry: <QI> offset, length — of the stored bytes.
                index += struct.pack("<QI", offset, len(stored))
                offset += len(stored)

                md5_linear.update(data)
                sha256_linear.update(data)
                blockhash_md5_digests.append(hashlib.md5(data).digest())
                blockhash_sha1_digests.append(hashlib.sha1(data).digest())

            base = f"{stream_dir}/{bevy:08d}"
            z.writestr(base, bytes(payload))
            z.writestr(f"{base}.index", bytes(index))
            # Per-chunk block hashes sit beside the bevy, raw bytes not hex.
            if write_block_hashes:
                start = bevy * chunks_in_segment
                end = start + chunks_in_segment
                z.writestr(
                    f"{base}.blockHash.md5",
                    b"".join(blockhash_md5_digests[start:end]),
                )
                z.writestr(
                    f"{base}.blockHash.sha1",
                    b"".join(blockhash_sha1_digests[start:end]),
                )

        # BlockHashes: SHA-512 over the concatenation of every block-hash
        # segment of one algorithm, in bevy order.
        bh_md5_all = b"".join(blockhash_md5_digests)
        bh_sha1_all = b"".join(blockhash_sha1_digests)
        blockhashes_md5 = hashlib.sha512(bh_md5_all).digest()
        blockhashes_sha1 = hashlib.sha512(bh_sha1_all).digest()

        # The map: one entry covering the whole image, pointing at the stream.
        # <QQQI>: offset, length, target offset, target id.
        #
        # --discontiguous instead covers only the stored bytes and declares an
        # address space twice that size, so the upper half is a hole. That is
        # the shape a sparse acquisition produces: the imager wrote what it
        # read and left the rest uncovered.
        declared_size = size * 2 if discontiguous else size
        image_shape = (
            "aff4:DiscontiguousImage" if discontiguous else "aff4:ContiguousImage"
        )
        # Omitted entirely when discontiguous and no stream was named: that is
        # the Cellebrite shape, where spec 4's aff4:Zero default applies and
        # the container states nothing. A contiguous image keeps the property
        # every reference container carries.
        if discontiguous:
            gap_default_line = (
                f"\n    aff4:mapGapDefaultStream  {gap_stream} ;"
                if gap_stream
                else ""
            )
        else:
            gap_default_line = "\n    aff4:mapGapDefaultStream  aff4:Zero ;"

        # The map covers only the stored half; the image declares twice that.
        map_size = declared_size
        map_bytes = struct.pack("<QQQI", 0, size, 0, 0)
        idx_bytes = (STREAM + "\n").encode()
        z.writestr(f"{map_dir}/map", map_bytes)
        z.writestr(f"{map_dir}/idx", idx_bytes)

        map_point = hashlib.sha512(map_bytes).digest()
        map_idx = hashlib.sha512(idx_bytes).digest()
        # mapHash covers the segment bytes, concatenated (no mapPath here).
        map_hash = hashlib.sha512(map_bytes + idx_bytes).hexdigest()

        # blockMapHash: BlockHashes ordered by digest length ascending
        # (MD5 then SHA-1), then the three map-segment digests. With no block
        # hashes written there are no BlockHashes terms to include.
        #
        # `mapPath` is absent here, and an absent segment still contributes —
        # as the SHA-512 of no bytes at all. Dropping the term instead is the
        # obvious mistake, and it yields a clean-looking wrong answer.
        leaves = (
            blockhashes_md5 + blockhashes_sha1 if write_block_hashes else b""
        )
        map_path = hashlib.sha512(b"").digest()
        block_map = hashlib.sha512(
            leaves + map_point + map_idx + map_path
        ).hexdigest()

        # Only claim BlockHashes subjects when the segments they describe were
        # actually written: recording a digest for an absent segment would make
        # the container internally inconsistent.
        block_hash_subjects = (
            f"""
<{STREAM}/blockhash.md5>
    a          aff4:BlockHashes ;
    aff4:hash  "{blockhashes_md5.hex()}"^^aff4:SHA512 .

<{STREAM}/blockhash.sha1>
    a          aff4:BlockHashes ;
    aff4:hash  "{blockhashes_sha1.hex()}"^^aff4:SHA512 .
"""
            if write_block_hashes
            else ""
        )

        turtle = f"""@prefix aff4: <http://aff4.org/Schema#> .
@prefix rdf:  <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
@prefix xsd:  <http://www.w3.org/2001/XMLSchema#> .

<{STREAM}>
    a                          aff4:ImageStream ;
    aff4:chunkSize             "{chunk}"^^xsd:int ;
    aff4:chunksInSegment       "{chunks_in_segment}"^^xsd:int ;
    aff4:compressionMethod     <{CODEC_IRIS[codec]}> ;
    aff4:size                  "{size}"^^xsd:long ;
    aff4:hash                  "{md5_linear.hexdigest()}"^^aff4:MD5 , "{sha256_linear.hexdigest()}"^^aff4:SHA256 ;
    aff4:stored                <{VOLUME}> ;
    aff4:target                <{MAP}> .

{block_hash_subjects}
<{MAP}>
    a                         aff4:Map ;
    aff4:dependentStream      <{STREAM}> ;{gap_default_line}
    aff4:mapHash              "{map_hash}"^^aff4:SHA512 ;
    aff4:mapIdxHash           "{map_idx.hex()}"^^aff4:SHA512 ;
    aff4:mapPointHash         "{map_point.hex()}"^^aff4:SHA512 ;
    aff4:blockMapHash         "{block_map}"^^aff4:SHA512 ;
    aff4:size                 "{map_size}"^^xsd:long ;
    aff4:stored               <{VOLUME}> ;
    aff4:target               <{IMAGE}> .

<{IMAGE}>
    a                aff4:Image , {image_shape} , aff4:DiskImage ;
    aff4:dataStream  <{MAP}> ;
    aff4:size        "{declared_size}"^^xsd:long ;
    aff4:hash        "{block_map}"^^aff4:blockMapHashSHA512 ;
    aff4:stored      <{VOLUME}> .

<{VOLUME}>
    a                  aff4:ZipVolume ;
    aff4:contains      <{IMAGE}> , <{STREAM}> , <{MAP}> ;
    aff4:interface     aff4:Volume ;
    aff4:stored        "synthetic-test.aff4" .
"""
        z.writestr("information.turtle", turtle)
        z.comment = VOLUME.encode()

    on_disk = out.stat().st_size
    print(f"wrote {out}")
    print(f"  {bevies} bevies, {chunks_in_segment} chunk/bevy, {chunk} B/chunk")
    print(f"  stream size {size} bytes ({size / 1048576:.1f} MiB)")
    print(f"  file size   {on_disk} bytes ({on_disk / 1048576:.1f} MiB)")
    print(f"  md5    {md5_linear.hexdigest()}")
    print(f"  sha256 {sha256_linear.hexdigest()}")


def stripe_arns(count: int, order: str) -> dict:
    """ARNs for a striped set, with a controllable sort order.

    The leading hex digit decides how each family sorts. With `matching`, ARN
    order agrees with filename order (`_1` before `_2`); with `reversed` it
    disagrees, so a tool that infers stripe order by sorting ARNs gets the
    wrong answer while filename order stays right. `shuffled` makes the volume,
    map, and stream families disagree with *each other*, so no single ARN sort
    is consistent.

    This matters because the striped image's root digest is order-sensitive:
    SHA-512(blockMapHash1 || blockMapHash2 || ...). An ordering rule that
    happens to work on the two-volume reference fixture — where several
    candidate keys agree by chance — must be tested against a set where they
    disagree.
    """
    if count > 15:
        raise ValueError("at most 15 stripes, to keep one hex digit per stripe")

    forward = [f"{i + 1:x}" for i in range(count)]
    backward = list(reversed(forward))

    if order == "matching":
        volume_keys = map_keys = stream_keys = forward
    elif order == "reversed":
        volume_keys = map_keys = stream_keys = backward
    else:  # shuffled: each family sorts differently from the others
        volume_keys = backward
        map_keys = forward
        stream_keys = backward

    return {
        "volumes": [f"aff4://{k}0000000-0000-4000-8000-00000000000{k}"
                    for k in volume_keys],
        "maps": [f"aff4://{k}1111111-1111-4111-8111-11111111111{k}"
                 for k in map_keys],
        "streams": [f"aff4://{k}2222222-2222-4222-8222-22222222222{k}"
                    for k in stream_keys],
        # One image ARN shared by every volume: the join key (v1.0a 7.1).
        "image": "aff4://99999999-9999-4999-8999-999999999999",
    }


def build_striped(
    out: Path,
    chunk: int,
    chunks_in_segment: int,
    bevies: int,
    size: int,
    write_block_hashes: bool,
    stripes: int,
    defect: str,
    arn_order: str,
    codec: str = "stored",
) -> None:
    """Write one image across `stripes` volumes, per Standard v1.0a 7.1.

    Structure reproduced from the reference fixture, including the parts that
    are awkward:

      - one shared `aff4:DiskImage` ARN in every volume (the join key)
      - each volume declares *every* stream, but the foreign ones as stubs
        carrying only `aff4:stored` and `aff4:target` — no size, no chunkSize
      - every volume stores *all* streams' block-hash segments, while holding
        only its own bevies
      - each volume's `blockMapHash` covers only its own local stream
      - the image root is SHA-512 over the stripes' blockMapHash digests,
        in stripe order
    """
    arns = stripe_arns(stripes, arn_order)
    image_arn = arns["image"]

    # Bevies round-robin, so each volume holds a genuine subset and the maps
    # must interleave targets.
    owner = [b % stripes for b in range(bevies)]

    # Per-stripe accumulators.
    md5 = [hashlib.md5() for _ in range(stripes)]
    sha256 = [hashlib.sha256() for _ in range(stripes)]
    bh_md5 = [[] for _ in range(stripes)]
    bh_sha1 = [[] for _ in range(stripes)]
    payloads = [[] for _ in range(stripes)]
    local_index = [0] * stripes

    # Map entries over the whole address space, each naming the stripe that
    # holds the bytes. Built once and shared: every volume's map covers the
    # entire image (v1.0a 7.1), which is why either map alone suffices.
    bevy_bytes = chunk * chunks_in_segment
    entries = []

    for bevy in range(bevies):
        s = owner[bevy]
        payload = bytearray()
        index = bytearray()
        offset = 0
        for c in range(chunks_in_segment):
            data = chunk_bytes(bevy * chunks_in_segment + c, chunk)
            # Bevy holds compressed bytes; digests cover the plaintext.
            stored_bytes = compress_chunk(codec, data)
            payload += stored_bytes
            index += struct.pack("<QI", offset, len(stored_bytes))
            offset += len(stored_bytes)
            md5[s].update(data)
            sha256[s].update(data)
            bh_md5[s].append(hashlib.md5(data).digest())
            bh_sha1[s].append(hashlib.sha1(data).digest())

        # The stream-local bevy number, which is what the segment is named.
        n = local_index[s]
        local_index[s] += 1
        payloads[s].append((n, bytes(payload), bytes(index)))

        # <QQQI>: mapped offset, length, target offset, target id.
        entries.append(
            struct.pack(
                "<QQQI", bevy * bevy_bytes, bevy_bytes, n * bevy_bytes, s
            )
        )

    map_bytes = b"".join(entries)
    idx_bytes = ("\n".join(arns["streams"]) + "\n").encode()

    map_point = hashlib.sha512(map_bytes).digest()
    map_idx_digest = hashlib.sha512(idx_bytes).digest()
    map_hash = hashlib.sha512(map_bytes + idx_bytes).hexdigest()
    map_path = hashlib.sha512(b"").digest()

    # Per-stripe blockMapHash, over that stripe's OWN stream only. Including a
    # foreign stripe's block hashes matches nothing — verified against the
    # reference fixture, and the trap this generator exists to reproduce.
    block_map = []
    blockhashes = []
    for s in range(stripes):
        md5_all = b"".join(bh_md5[s])
        sha1_all = b"".join(bh_sha1[s])
        digests = (hashlib.sha512(md5_all).digest(),
                   hashlib.sha512(sha1_all).digest())
        blockhashes.append(digests)
        leaves = digests[0] + digests[1] if write_block_hashes else b""
        block_map.append(
            hashlib.sha512(
                leaves + map_point + map_idx_digest + map_path
            ).digest()
        )

    # The striped image root: SHA-512 over the stripes' blockMapHash digests,
    # in stripe order. Order-sensitive by construction.
    image_root = hashlib.sha512(b"".join(block_map)).hexdigest()

    stem = out.stem
    written = []

    for s in range(stripes):
        path = out.with_name(f"{stem}_{s + 1}{out.suffix}")
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            path.unlink()

        volume = arns["volumes"][s]
        stream_dir = escaped(arns["streams"][s])
        map_dir = escaped(arns["maps"][s])

        with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED, allowZip64=True) as z:
            z.writestr("container.description", volume)
            z.writestr(
                "version.txt", "major=1\nminor=0\ntool=aff4tools-synthetic\n"
            )

            # This stripe's own bevies.
            for n, payload, index in payloads[s]:
                base = f"{stream_dir}/{n:08d}"
                z.writestr(base, payload)
                z.writestr(f"{base}.index", index)

            # Block-hash segments for EVERY stream, including foreign ones —
            # as the reference fixture does. This is what makes bevy presence,
            # not segment presence, the test for which streams a stripe's
            # blockMapHash covers.
            if write_block_hashes:
                for other in range(stripes):
                    other_dir = escaped(arns["streams"][other])
                    z.writestr(
                        f"{other_dir}/00000000.blockHash.md5",
                        b"".join(bh_md5[other]),
                    )
                    z.writestr(
                        f"{other_dir}/00000000.blockHash.sha1",
                        b"".join(bh_sha1[other]),
                    )

            z.writestr(f"{map_dir}/map", map_bytes)
            z.writestr(f"{map_dir}/idx", idx_bytes)

            local_chunk = chunk
            stream_size = len(payloads[s]) * bevy_bytes
            local = f"""<{arns["streams"][s]}>
    a                          aff4:ImageStream ;
    aff4:chunkSize             "{local_chunk}"^^xsd:int ;
    aff4:chunksInSegment       "{chunks_in_segment}"^^xsd:int ;
    aff4:compressionMethod     <{CODEC_IRIS[codec]}> ;
    aff4:size                  "{stream_size}"^^xsd:long ;
    aff4:hash                  "{md5[s].hexdigest()}"^^aff4:MD5 , "{sha256[s].hexdigest()}"^^aff4:SHA256 ;
    aff4:stored                <{volume}> ;
    aff4:target                <{arns["maps"][s]}> .
"""

            # Foreign streams as stubs: `stored` names the sibling volume, and
            # nothing else is declared. The absent size is the point — it is
            # what makes a lone stripe unreadable and drives discovery.
            stubs = ""
            for other in range(stripes):
                if other == s:
                    continue
                if defect == "missing-metadata":
                    # Not even a stub: nothing names the volume that holds the
                    # foreign stream, so the set cannot be joined at all.
                    continue

                if defect == "conflicting-chunk-size" and s == 0:
                    # Stripe 1's stub declares a chunkSize for the *same*
                    # stream that stripe 2 describes, and declares it wrongly.
                    # Two volumes disagreeing about one stream cannot both be
                    # right; picking a side would make the digest
                    # unattributable, so this must be declined.
                    stubs += f"""
<{arns["streams"][other]}>
    a               aff4:ImageStream ;
    aff4:chunkSize  "{chunk * 2}"^^xsd:int ;
    aff4:stored     <{arns["volumes"][other]}> ;
    aff4:target     <{arns["maps"][s]}> .
"""
                    continue

                stubs += f"""
<{arns["streams"][other]}>
    a            aff4:ImageStream ;
    aff4:stored  <{arns["volumes"][other]}> ;
    aff4:target  <{arns["maps"][s]}> .
"""

            bh_subjects = ""
            if write_block_hashes:
                for other in range(stripes):
                    bh_subjects += f"""
<{arns["streams"][other]}/blockhash.md5>
    a          aff4:BlockHashes ;
    aff4:hash  "{blockhashes[other][0].hex()}"^^aff4:SHA512 .

<{arns["streams"][other]}/blockhash.sha1>
    a          aff4:BlockHashes ;
    aff4:hash  "{blockhashes[other][1].hex()}"^^aff4:SHA512 .
"""

            dependents = " , ".join(f"<{a}>" for a in arns["streams"])

            turtle = f"""@prefix aff4: <http://aff4.org/Schema#> .
@prefix rdf:  <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
@prefix xsd:  <http://www.w3.org/2001/XMLSchema#> .

{local}{stubs}{bh_subjects}
<{arns["maps"][s]}>
    a                         aff4:Map ;
    aff4:dependentStream      {dependents} ;
    aff4:mapGapDefaultStream  aff4:Zero ;
    aff4:mapHash              "{map_hash}"^^aff4:SHA512 ;
    aff4:mapIdxHash           "{map_idx_digest.hex()}"^^aff4:SHA512 ;
    aff4:mapPointHash         "{map_point.hex()}"^^aff4:SHA512 ;
    aff4:blockMapHash         "{block_map[s].hex()}"^^aff4:SHA512 ;
    aff4:size                 "{size}"^^xsd:long ;
    aff4:stored               <{volume}> ;
    aff4:target               <{image_arn}> .

<{image_arn}>
    a                aff4:Image , aff4:ContiguousImage , aff4:DiskImage ;
    aff4:dataStream  <{arns["maps"][s]}> ;
    aff4:size        "{size}"^^xsd:long ;
    aff4:hash        "{image_root}"^^aff4:blockMapHashSHA512 ;
    aff4:stored      <{volume}> .

<{volume}>
    a                  aff4:ZipVolume ;
    aff4:contains      <{image_arn}> , <{arns["streams"][s]}> , <{arns["maps"][s]}> ;
    aff4:interface     aff4:Volume ;
    aff4:stored        "{path.name}" .
"""
            z.writestr("information.turtle", turtle)
            z.comment = volume.encode()

        written.append((path, volume, len(payloads[s])))

    print(f"wrote a {stripes}-stripe set ({arn_order} ARN order)")
    for path, volume, count in written:
        print(f"  {path.name}  {count} bevies  {volume}")
    print(f"  shared DiskImage {image_arn}")
    print(f"  image root       {image_root}")
    print("  stripe order for the root digest is filename order "
          f"({', '.join(p.name for p, _, _ in written)})")
    if defect != "none":
        print(f"  DEFECT: {defect} — this set is expected to be declined")


if __name__ == "__main__":
    main()
