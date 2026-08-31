# Testing

**This is a machine-generated file, primarily intended for coding agent context.**

How the suite is organized, what it does and does not prove, and the
conventions that keep it honest.

## Running

```sh
cargo test                          # 534 tests, nothing to download
./utilities/fetch-corpus.sh         # get the reference containers, once
cargo test --features corpus        # 687 tests, against real evidence
```

That is the whole setup. The fetch script downloads the reference containers
into `~/.cache/aff4tools/corpus`, which is where the tests look by default —
no environment variable needed. It is safe to re-run: already-fetched
containers at the pinned commit are left alone.

Pass a different directory to put them elsewhere, then point the tests at it:

```sh
./utilities/fetch-corpus.sh /data/aff4-corpus
export AFF4_TEST_IMAGES=/data/aff4-corpus
```

`tests/cross_tool.rs` additionally runs pyaff4 as an independent implementation
and needs its source tree plus a Python that can import it:

```sh
AFF4_PYAFF4_ROOT=/path/to/pyaff4 AFF4_PYAFF4_PYTHON=python3 \
    cargo test --test cross_tool
```

**Corpus tests are gated, not skipped.** A green `cargo test` without fixtures
means 534 tests passed — not that any real container was verified. A runtime
skip would let CI report success having checked nothing, so the gate is a
compile-time feature instead.

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

| Location | Sees | Purpose |
|---|---|---|
| `src/**/*.rs` in `#[cfg(test)] mod tests` | private items | Unit |
| `tests/cli.rs` | the built binary | End-to-end CLI |
| `tests/corpus.rs` | public API | Real containers |
| `tests/malformed.rs` | public API | Damaged input |
| `tests/split_acquire.rs` | public API | Split-set writing |
| `tests/logical_acquire.rs` | public API | AFF4-L writing |
| `tests/dedupe_acquire.rs` | public API | AFF4-L §4 dedupe |
| `tests/striped_generated.rs` | public API | Striped volumes |
| `tests/acquire_verify.rs` | public API | Acquisition + proof |
| `tests/write_roundtrip.rs` | public API | Write gates 1–3 |
| `tests/discontiguous.rs` | the built binary | Maps with holes |
| `tests/read_only_guard.rs` | `src/*.rs` as text | Write-blocking |
| `tests/codecs.rs` | public API | Codec coverage |
| `tests/independent_digest_agreement.rs` | public API + pyaff4 | Digest agreement |
| `tests/parallel_pipeline.rs` | public API | Ordering, deadlock |
| `tests/cross_tool.rs` | public API + pyaff4 | Gate 4, env-gated |

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

`utilities/fetch-corpus.sh` downloads them at pinned commits. They are treated
as read-only evidence: a test needing mutated bytes copies the original into a
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
reached a real 236 GB container with the whole suite green. None was a subtle
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
- **Directory-backed volumes** (spec §5): not implemented.
- **Zlib and LZ4 against real containers**: see the codec warning above.
- **Raw deflate and Rekall snappy codecs**: declined by decision, not implemented.

