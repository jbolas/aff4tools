# Testing

**This is a machine-generated file, primarily intended for coding agent context.**

How the suite is organized, what it does and does not prove, and the
conventions that keep it honest.

## Running

```sh
./utilities/fetch-corpus.sh         # get the corpus, once
cargo test                          # the library and CLI
cargo test --features corpus        # plus the gated corpus tests
cargo test -p aff4tools-ffi         # the C library (add --features corpus)
```

The fetch script needs `git` and `python3`. It downloads the reference
containers at pinned commits and generates the v2.1 containers (see
[Fixtures](#fixtures)), all into `~/.cache/aff4tools/corpus`, where the tests
look by default. Re-running it leaves containers already at the pinned commit
alone.

To use another directory, pass it to the script and point the tests at it:

```sh
./utilities/fetch-corpus.sh /data/aff4-corpus
export AFF4_TEST_IMAGES=/data/aff4-corpus
```

A plain `cargo test` runs only the main crate. The workspace sets no
`default-members`, so the C library's tests in `aff4tools-ffi/tests/abi.rs`
run only under `-p aff4tools-ffi` or `--workspace`.

### What needs the corpus

**Most corpus tests are gated, not skipped.** `tests/corpus.rs`,
`tests/coverage.rs`, `tests/independent_digest_agreement.rs`, the corpus tests
in `tests/cli.rs`, and those in `abi.rs` compile only under `--features corpus`.
A runtime skip would let CI report success having checked nothing; a
compile-time feature cannot.

Two groups break that rule:

- **Ungated, and fail without the corpus.** `tests/storage_forms.rs`,
  `tests/storage_malformed.rs`, and `tests/zip_segment_conformance.rs` read the
  generated v2.1 containers. Without them, a plain `cargo test` fails 20 tests.
- **Ungated, and pass without the corpus.** Six tests in `tests/malformed.rs`
  and one in `tests/storage_malformed.rs` return early when their container is
  absent. They report success having checked nothing.

### Tests that need pyaff4

Two files compare against pyaff4, the only other implementation that
recomputes AFF4 digests. Each checks for its environment variables at run time
and, if any is missing, prints a skip notice and passes:

| File | Checks | Variables |
|---|---|---|
| `tests/cross_tool.rs` | pyaff4 accepts what aff4tools writes | `AFF4_PYAFF4_PYTHON`, `AFF4_PYAFF4_ROOT` |
| `tests/independent_digest_agreement.rs` | both compute the same digests on the corpus | `AFF4_PYAFF4_PYTHON`, `AFF4_PYAFF4_PATCHED` |

`AFF4_PYAFF4_PYTHON` names an interpreter that can import pyaff4. Each file's
header explains how to set pyaff4 up; the second needs a one-line patch to
pyaff4.

```sh
AFF4_PYAFF4_ROOT=/path/to/pyaff4 AFF4_PYAFF4_PYTHON=/path/to/venv/bin/python \
    cargo test --test cross_tool
```

### The `nonconforming` suite

`tests/nonconforming.rs` builds only under its feature:

```sh
cargo test --features nonconforming
```

It covers capabilities that exist to build proposed Canonical Reference Images.
The feature gates the **command-line interface**: no shipped binary offers
these flags, so nothing a user can type makes one write such a container. The
corresponding `LogicalOptions` fields stay public in every build, so a program
linking the library can still ask for them deliberately. A green `cargo test`
says nothing about any of it, in exactly the way it says nothing about the
corpus.

## ⚠ Codec coverage — read this before trusting a decompressed chunk

**Only snappy has been verified against real-world evidence.** Every reference
container declares snappy and nothing else. 
Searching the corpus for `compression/stored`, `NullCompressor`,
`rfc1950`, `rfc1951`, `p/lz4`, or `github.com/google/snappy` returns nothing.

| Codec | Real evidence | Generated container | Status |
|---|---|---|---|
| Snappy | 121 chunks from `Base-Linear.aff4` | yes | Verified |
| Stored | — (returns its input) | yes | Implemented |
| Zlib | **none** | yes | Container-tested |
| LZ4 | **none** | yes | Container-tested |
| Deflate | none obtainable | yes, and declines | Declined → `Unsupported` |
| Snappy (Rekall) | none obtainable | no writer exists | Declined → `Unsupported` |

Generated containers compress with **Python's** `zlib`, `python-snappy`, and
`lz4` — independent implementations, so a bug shared between a Rust compressor
and the Rust decompressor cannot cancel out. They also prove the surrounding
path: that the IRI resolves to the right codec, that the bevy index locates
chunks whose lengths differ from `chunkSize`, and that digests still match.
Confirmed non-vacuous — pointing `Codec::Lz4` at the zlib decoder fails
`each_codec_verifies_a_real_container`.

What they do not establish: the payload is lorem ipsum, compressing about 60:1,
and real disk images do not behave that way. Nor does a generated container
show how a *commercial* writer frames its chunks. **A container using zlib,
LZ4, deflate, or Rekall snappy from a real acquisition tool remains more
valuable to this project than any test we can write.**

Deflate is declined rather than guessed: AFF4 assigns it and zlib separate IRIs
for genuinely different byte streams, and decoding one as the other would
produce a confident mismatch.

## Layout

Unit tests live beside the code, because they exercise crate-private functions
invisible from `tests/`. Integration tests see only the public API, as a
downstream consumer would; `tests/cli.rs` launches the real binary through
`assert_cmd`, which is what proves the library/binary seam.

Unit tests are in `#[cfg(test)] mod tests` blocks under `src/`. The
integration tests in `tests/`:

| File | Covers |
|---|---|
| `acquire_verify.rs` | Acquisition, then verification of the result |
| `aff4l_v1_alpha_acquire.rs` | Writing AFF4-L v1.0-ALPHA containers |
| `citation_style.rs` | Every specification citation names its document |
| `cli.rs` | The built binary, end to end |
| `codecs.rs` | Codec coverage |
| `corpus.rs` | Values read from the reference containers |
| `coverage.rs` | Rules `conformance` cannot evaluate, and `--strict` |
| `cross_tool.rs` | Gate 4: pyaff4 accepts what aff4tools writes |
| `dedupe_acquire.rs` | AFF4-L 2019 §4 deduplication |
| `discontiguous.rs` | Maps with holes |
| `disk_image.rs` | Finding a set's parts, choosing its image, reading it |
| `hash_algorithms.rs` | AFF4-L v1.0-ALPHA §4.4 digests, plus BLAKE3 |
| `hdt_backend.rs` | The HDT backend answers as `Graph` does (`hdt-experiment`) |
| `independent_digest_agreement.rs` | Gate 5: aff4tools and pyaff4 compute the same digests |
| `logical_acquire.rs` | AFF4-L writing |
| `logical_scan.rs` | The metadata scanner's queue, cost model, and degradation |
| `malformed.rs` | Damaged input |
| `metadata_integrity.rs` | AFF4-L v1.0-ALPHA §10.1 metadata integrity hash |
| `multi_part_acquire.rs` | Writing one image across several parts |
| `nonconforming.rs` | The `nonconforming` feature |
| `parallel_pipeline.rs` | Ordering and deadlock in the parallel reader |
| `progress.rs` | Progress rendering |
| `read_only_guard.rs` | Write-blocking, by scanning `src/` as text |
| `rule_registry.rs` | `docs/conformance-rules.md` matches the registry |
| `shared_map_storage.rs` | AFF4-L v1.0-ALPHA §6.3 shared map storage |
| `storage_forms.rs` | Reading every AFF4-L v1.0-ALPHA §6 storage form |
| `storage_malformed.rs` | Strict AFF4-L v1.0-ALPHA §6 dispatch |
| `striped_generated.rs` | Striped volumes |
| `write_roundtrip.rs` | Write gates 1–3 |
| `xattr_acquire.rs` | Extended attributes (Unix only) |
| `zip_segment_conformance.rs` | AFF4-L v1.0-ALPHA §6.1 and §8 |

The C library's tests are in `aff4tools-ffi/tests/abi.rs`.

Test names are the index. `cargo test <name>` runs one; the doc comment above
it says what it asserts and what makes it fail. That is deliberately not
duplicated here, because a hand-maintained list of every test drifts out of
date faster than anyone notices.

## Fixtures

Reference containers come from two upstreams under different licenses, and
this project redistributes neither:

| Source | License | Containers |
|---|---|---|
| [`aff4/pyaff4`](https://github.com/aff4/pyaff4) | Apache-2.0 | 12 |
| [`aff4/aff4-cpp-lite`](https://github.com/aff4/aff4-cpp-lite) | LGPL-3.0 | 8 |

`utilities/fetch-corpus.sh` downloads them at pinned commits.

No AFF4-L v1.0-ALPHA reference images exist yet, so the script also runs
`utilities/make_v21_container.py`, which writes 34 small v2.1 containers into
`aff4tools-v2.1/`. The generator is independent of the aff4tools writer. Its
output is test input, not canonical reference images. Without `python3` the
script skips this step and warns, and the tests that read these containers
fail.

All of these are treated as read-only evidence: a test needing mutated bytes copies the original into a
`tempfile::TempDir` and mutates the copy, and `tests/malformed.rs` asserts the
source's length and mtime are unchanged afterwards.

Two synthetic fixtures are committed under `tests/fixtures/`. This project
made them, so they ship with the source and need no download — the tests that
read them run on a bare clone:

| Fixture | Size | Purpose |
|---|---|---|
| `deflate-test.aff4` | 8.6 KB | An intact container in a codec this build declines. `verify` exits 0 and names the limit — a tool limit is not damaged evidence. |
| `bitrot-test.aff4` | 15 KB | A bevy segment failing its recorded ZIP checksum. `verify` exits 9. |

The codec tests generate their own containers rather than reading fixtures, so
nothing can drift out of sync with the generator:

```sh
python3 utilities/create_test_aff4.py /tmp/x.aff4 --codec snappy \
    --bevies 4 --chunk-size 512 --chunks-in-segment 1
```

`bitrot-test.aff4` is the one fixture that cannot be regenerated from a flag —
the generator has no corruption mode. It is made in two steps: generate a valid
container, then flip one bit at two offsets inside the **stored bytes** of a
bevy. Corrupting the payload rather than the ZIP structure is the point: the
archive still parses and only the CRC disagrees, which is the state real bit
rot produces. Flipping a header byte gives a different failure, and not the one
under test.

## Expected values come from outside this crate

This is the most important convention here, and it was learned the hard way.
Six bugs passed tests written against this crate's own assumptions.

**Three caught by corpus validation:**

1. **ARN member-name mapping.** Expectations hand-derived from spec text got
   the doubled slash wrong — `//test_images/…` where containers store
   `/test_images/…`. Every unit test passed. Run against real ARNs,
   `unicode.aff4` mapped **0 of 9** member names. After the fix: 9 of 9.
2. **Unreported timestamp deviations.** `dream.aff4` reported 1 deviation where
   5 were expected: the builder inspected datatypes only on `size` and
   `stored`, so four lowercase `xsd:datetime` literals were swallowed
   unexamined.
3. **Deviation flooding.** `broken-dedupe.aff4` produced 445 deviations, 437 of
   them one per dedupe-index subject, burying every other finding. Now
   aggregated to 9.

**Three caught by hostile input** — each a decoder returning success where it
had to fail, the direction that does real damage because the caller cannot
tell:

4. **Snappy accepted a zero-length chunk.** A bare `0x00` is a valid varint
   meaning "decompresses to nothing", so the decoder returned `Ok([])` and a
   caller would have hashed an empty buffer as evidence.
5. **Truncated zlib returned partial data.** `read_to_end` treats a short
   stream as clean EOF, never reaching the Adler-32 trailer — half a stream
   yielded `Ok(12664)` of an expected 32768 bytes. Silent short data produces a
   plausible digest that fails the acquisition hash, sending an examiner after
   tampering that never happened. Now uses `flate2::Decompress`, which reports
   `StreamEnd` only when the trailer validates.
6. **A hostile `chunkSize` aborted the process, and the first fix broke valid
   chunks.** A declared size near `usize::MAX` panicked in `Vec::with_capacity`
   before a byte was read. Reserving a modest 64 KiB instead was wrong the
   other way: `decompress_vec` does not grow past capacity, so every legitimate
   chunk above 64 KiB failed as "truncated", and no test caught it because none
   used a chunk that large. Now bounded by `MAX_CHUNK_SIZE` at the entry point,
   with a regression test at 1 MiB.

So `tests/corpus.rs` asserts values read out of the containers — the exact
volume ARN, `Evimetry 2.2.0`, size 268435456, the full 40-character SHA1 — not
golden-file snapshots, which rot and hide what is being checked.

### One container is not the corpus

A related failure, caught at review before any code was written. The map entry
width (28 bytes) and the rule "entries are sorted and contiguous" were both
derived from `Base-Linear.aff4` alone. Checking all 16 maps across 10
containers showed:

- **28 bytes held everywhere** — but five maps are also divisible by 32, so
  segment length alone never proved it.
- **"Sorted" was false.** `broken-dedupe.aff4` stores its 437 entries out of
  address order; sorted, they are gapless and sum exactly to the declared size.
  The proposed rule would have rejected a structurally sound container.

Structural claims get checked against **every** container that has the
structure, not the first one opened.

## What the guards actually guarantee

Each was verified by planting a violation and watching it fail, not by assuming
the mechanism works.

**Read-only** (`tests/read_only_guard.rs`). Scans `src/*.rs` for write APIs
outside test modules and asserts a single `File::open` chokepoint in
`src/zip.rs`. Verified by planting `File::create` in `version.rs`: it failed
with the exact file and line, then went green on restore. Since writing landed,
the scan excludes `src/write/`, which has its own chokepoint test requiring all
creation to route through `sink.rs`, and a second guard refuses any write
handle targeting a registered acquisition source.

The rule protects *evidence*, not files in general. Sources and containers
being read may never change; the output `.aff4` and its log are new files the
tool exists to create, both via `create_new` so neither can overwrite anything.
`the_allow_exemption_covers_only_the_line_it_annotates` asserts a documented
`#[allow]` cannot spread past its own line.

**Never panics on malformed input** (`tests/malformed.rs`). Empty files, random
bytes, truncation at eleven fractions, a wiped EOCD signature, a corrupted
central-directory offset, non-Turtle metadata, 5000 nested brackets, `u64::MAX`
sizes. Every case returns a specific error; none may panic.

The EOCD tests locate `PK\x05\x06` by searching rather than assuming an offset.
In `Base-Linear.aff4` it sits 66 bytes from the end because of a 44-byte volume
comment — a fixed tail length silently stops testing anything the moment a
fixture's comment changes. An earlier version made exactly that mistake and
passed while testing nothing.

**No codec panics, and none silently succeeds** (`src/codec.rs`). Every codec
runs against every hostile input — empty, single bytes, all-`0xff`, a varint
claiming a huge length — across chunk sizes from `0` to `usize::MAX`. Every
failure must be `Malformed` or `Unsupported` and must carry the container path,
since an error with no locus is useless in a report. Corruption is checked by
flipping one bit at a time through a whole zlib chunk: each flip must fail or
produce different bytes, because a corrupted chunk decoding correctly would
mean the checksum was never consulted.

**Digests are never truncated** (`tests/cli.rs`). The full SHA1, MD5, and
128-character SHA512 appear in output, and no `…` appears anywhere.

## The corpus cannot reach every state

Reference containers hold **one bevy per stream**, so the parallel read path's
reorder window never fills on any of them. Three deadlocks in `src/parallel.rs`
reached a real 237 GB container with the whole suite green. None was a subtle
race: each parked every thread at 0% CPU. The tests simply could not construct
the state.

`tests/parallel_pipeline.rs` builds its own fixture in-process — ten thousand
bevies of 512 bytes. A bevy that reads instantly lets readers outrun the
consumer, so the window saturates. Measured: **80 window-full events in 0.4
seconds** there against **none in 60 seconds** of the real container, whose
32 MiB bevies keep the pipeline I/O-starved. The cheap fixture reaches the
dangerous state the expensive one cannot.

It covers ordering and liveness only. Throughput and the reader governor need
sustained reading at realistic bevy sizes, which does not belong in a suite
that has to stay fast.

**The general lesson:** a fixture that is merely *representative* is not
enough. What matters is whether it can reach the states the code has to
survive.

## Generated striped fixtures

The corpus holds exactly **one** striped container: two volumes, one bevy per
stream. Enough to prove cross-volume reading works; not enough to prove the
rules are right. `--stripes N` writes sets that close the gap, reproducing the
reference fixture's awkward properties deliberately:

- one shared `aff4:DiskImage` ARN across every volume (the join key)
- foreign streams declared as **stubs** — `aff4:stored` and `aff4:target` only
- **every** volume stores **all** streams' block-hash segments while holding
  only its own bevies
- each stripe's `blockMapHash` covers only its own local stream
- the image root as `SHA-512(bmh₁ ‖ … ‖ bmhₙ)`, in stripe order

### Adversarial stripe orderings

The image root is order-sensitive, but on a two-volume fixture, sorting by
filename and by map ARN happen to agree — so either rule looks correct on a
sample of two. `--arn-order` breaks the coincidence:

| `--arn-order` | filename | volume ARN | map ARN | stream ARN |
|---|---|---|---|---|
| `matching` | 1,2,3 | 1,2,3 | 1,2,3 | 1,2,3 |
| `reversed` | 1,2,3 | 3,2,1 | 3,2,1 | 3,2,1 |
| `shuffled` | 1,2,3 | 3,2,1 | **1,2,3** | 3,2,1 |

`shuffled` is the discriminating case: map ARN agrees with filename while the
others disagree, so candidate rules give different answers on one container.
Against generated roots, all written in filename order:

| set | filename | map ARN | stream ARN |
|---|---|---|---|
| `matching` | match | match | match |
| `reversed` | match | **no** | **no** |
| `shuffled` | match | match | **no** |

Filename order is the rule that survives.

## Coverage gaps worth knowing

- **Scudette pre-Standard dialect**: zero fixtures. The detect-and-refuse path is tested
  only with a synthetic archive.
- **Encrypted containers**: no fixture; detection is unimplemented.
- **Directory-backed volumes** (v1.0a §5): not implemented.
- **Zlib and LZ4 against real containers**: see the codec warning above.
- **Raw deflate and Rekall snappy codecs**: declined by decision, not implemented.

