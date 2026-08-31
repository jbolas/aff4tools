# RDF scalability: reading 10M objects without needing 66 GB of RAM

These are agent-generated notes, lightly edited by a person, regarding an informal review of the AFF4-L's ability to scale up to 
contain millions of objects. Such a scale is realistic for the logical acquisition of a user volume. `aff4tools` implements some commonsense approaches to memory management, as explained here.

The choice to use RDF for metadata in the AFF4-L specification does create scalability issues that will need to be addressed through the evolution of the Standard.

## The problem RDF creates

AFF4 stores its metadata as RDF in Turtle syntax, in a single
`information.turtle` member. RDF's unit is the **triple** — subject, predicate,
object. Using ARN prefixing reduces the length of subject strings but not the number 
of triples in the turtle file. An AFF4-L object with 15 properties will result in 15 separate RDF statements that share a
subject string. 

Pre-optimization, running `aff4tools conformance` on a container with 1,010,001 objects required **6.6 GB** of RDF data to be held in memory.
An earlier projection, extrapolated from a 404,000-object fixture, put 10M objects at **~76 GB**. Either way, that's a big turtle.

Three properties of the RDF format make it expensive:

1. **A triple is small and numerous.** At ~438 bytes per parsed statement,
   150M triples is ~66 GB — **8.6× the text they came from**. The overhead is
   per-allocation: string headers, capacity rounding, and pointer indirection on
   objects that average ~51 bytes of actual text.
2. **Turtle is not random-access.** There is no index and no way to seek to a
   subject. Answering "what does this ARN say" traditionally means parsing the entire turtle first.
3. **Nothing bounds the file.** The reference corpus contains nothing larger than 439 objects and 99 KB.
   The format permits, and real acquisitions produce, containers four orders of magnitude larger.

A logical (AFF4-L) acquisition of ten million files with 15 properties each has these projections:
| | count |
|---|---|
| described objects | 10,000,000 |
| triples | ~150,000,000 |
| `information.turtle` | ~7.5 GB |
| held in memory | ~66 GB |

## What was tried and rejected: HDT

Schatz's AFF4-L paper (§4–§6) proposes **HDT** — Header, Dictionary, Triples — a
binary RDF format that stores each distinct string once in a dictionary and
encodes triples as integer IDs into it. It is the obvious answer, so it was
built and measured behind `--features hdt-experiment` (`src/metadata/hdt_store.rs`).

**As a store it worked**: 115.6 MiB against ~2.5 GB, a 22× reduction, with both
backends agreeing on every triple across 60 corpus invocations.

**End to end it saved nothing.** Two reasons:

- **The store was not the cost.** The objects built *from* the store dominated,
  and both backends paid for those identically.
- **It made the rest worse.** Serving HDT required a trait returning *owned*
  strings, because HDT decodes from a compressed dictionary rather than holding
  text to borrow. That forced ~15 million clone-and-drop cycles on the ordinary
  path, for a backend that was never adopted.

It also built 1.45× slower and needed a side index to preserve source order,
which gave back much of the saving.

**It is now further from being worth revisiting than when it was rejected.**
Neither `info` nor `conformance` retains a triple store at all — HDT would be a
compact representation of something that no longer exists in memory. The
experiment is kept behind its feature flag as a record.

The real lesson was one of sequencing: **compressing a structure is worth less
than not building it.**

## Strategy 1: string interning

A container's *predicates* and *type IRIs* are drawn from a tiny vocabulary
while its *subjects* repeat once per triple about them. Measured on a
million-object container:

| term | occurrences | distinct |
|---|---|---|
| predicate IRIs | ~12,100,000 | **13** |
| datatype IRIs | ~7,100,000 | **4** |
| type IRIs | ~1,000,000 | **3** |
| subject IRIs | ~15,100,000 | 1,010,001 |

(Counted on that fixture. A 404,000-object container measured 11 distinct
predicates and 6 distinct type IRIs — the vocabulary is small whatever the
container, which is the point.)

Storing each occurrence as its own `String` costs 24 bytes inline plus a heap
allocation *every time*. **Interning** keeps a pool of distinct values and hands
out `Arc<str>` — a shared, reference-counted pointer — so a repeated term costs
8 bytes and shares one allocation.

Applied to predicates, types, datatypes, and subjects, this took the parsed
graph from 4.215 GB to 2.257 GB.

**Deliberately not applied to literal values.** Timestamps, digests, and paths
are genuinely distinct in real containers — the corpus measures 20–44% repeats —
so a pool would add a hash lookup per term and return little. A generated
fixture showing 87% repeats is an artifact of the generator, not evidence.

## Strategy 2: streaming instead of retaining

This is the change that mattered most.

**Retaining** means parsing the whole file into a queryable structure, then
walking it. Every triple stays live because any part of the code might ask for
any subject at any time. Peak memory is *everything at once*.

**Streaming** means processing each subject as it is read and then dropping it.
The parser holds one subject's statements — a dozen triples — instead of 150
million.

This is possible because of one fact, verified across all four generations in
the corpus: **every subject's statements are contiguous in the turtle.** A
reader can therefore complete an object when the subject changes and never hold
two.

**That is an observation about writers, not a guarantee of the format.** Turtle
permits a subject to reappear later. So `Graph::stream_by_subject` detects a
repeat, **records it as a deviation**, and emits a second partial subject —
splitting an object visibly rather than silently merging or dropping half of it.

What each command retains now:

| command | retains |
|---|---|
| `conformance` | deviations, plus a `HashSet` of subject ARNs |
| `info --brief` | counts, ~64 sampled objects, case-metadata carriers |
| `info` (large) | the same as `--brief` |

`conformance` needs the ARN set because a reference may point *forward* to a
subject not yet parsed; unresolved references are deferred and settled once the
pass completes.

The retained graph still exists for striped containers, where each volume's
metadata must be resolved against the others, and for `verify`.

**Measured:** `conformance` 6.618 → 1.074 GB; `info` 4.675 → 1.050 GB.

## Strategy 3: capping the terminal listing

`info` prints one block per object. Nobody wants to read 10 million object descriptions.

**Above 2,000 objects the listing degrades to the `--brief` summary**, followed
by a notice giving the true object count and naming
`--full-listing <PATH>`, which writes the complete report to a file.

2,000 sits well above the largest reference container (439 objects), so no
canonical container's output changed.

## Other measures

- **Borrow rather than copy the source.** `escape_byte_ranges` percent-encodes
  pyaff4's byte-range IRIs so a conformant parser accepts them. It returns
  `Cow<str>` and borrows when the source contains no `[`, avoiding a second full
  copy of the segment. This saved nothing when written — the peak was elsewhere
  — and became worth 0.75 GB once streaming removed everything above it.
- **Never parse a graph nobody reads.** `Container::open` parsed and retained
  `information.turtle` while `summarize` parsed its own copy.
  `open_without_graph` skips the first. Freeing it afterwards would not have
  helped: peak is a high-water mark, and both were live at once.
- **`shrink_to_fit` on per-object vectors.** Grown by pushing, so a two-element
  `edges` or `hashes` list sat on four slots. Harmless at ten objects; 0.23 GB at
  a million.
- **Counting during the parse.** `ContainerSummary::counts` accumulates totals as
  each object is built, so a command that retains a *subset* still reports honest
  totals.
- **Found and removed quadratic scans.** Three linear searches inside per-object loops
  were invisible on corpus containers and fatal at scale: dangling-reference
  checks (10¹⁴ comparisons at 10M), manifest reconciliation (10¹²), and striped
  volume merging (10¹⁴). All are hash lookups now.

## Measuring this at all

Peak RSS varied by **1.12 GB across four identical runs** — larger than most
effects being measured. It depends on when the allocator returns pages to the
kernel and when the kernel samples.

`src/main.rs` installs a counting global allocator behind
`AFF4TOOLS_ALLOC_STATS=1`, reporting the high-water mark of live bytes. It is
byte-identical across runs, and every figure in this document comes from it.

**The distinction that made the difference: churn is not peak.** Removing 15
million clone-and-drop cycles saved ~11% of runtime and *no memory*, because
each clone was freed before the next was made. A change only moves the peak if
what it removes was live *at the moment of the peak*.

## Post-optimization

Memory consumption measured using a container with 1,010,001 objects (and a 771 MB turtle):

| | before | after |
|---|---|---|
| `info` | 4.675 GB | **1.050 GB** |
| `info --brief` | 4.675 GB | **1.050 GB** |
| `conformance` | 6.618 GB | **1.074 GB** |

**Projection to 10M objects: ~10.7 GB**, against an original projection of ~66 GB.

Of the ~1.05 GB, **0.753 GB is the metadata segment read into memory before
parsing begins** — the one remaining structural cost, and the only item that
scales with file size rather than with what is retained. Streaming that read
would take all three commands to roughly 3.2 GB at 10M. It is not implemented.

**These projections are linear extrapolations from a 1M-object fixture.**
Nothing here has been run against a 7.5 GB turtle. If memory is exhausted the
tool currently aborts with no error and no exit code from this project's
taxonomy.

## Last comments

There may be better ways to parse voluminous RDF, better approaches for `aff4tools` to use the data in the turtle file, and better fundamental ways to represent object metadata that would circumvent the verbosity and scalability issues of RDF triples. All deserve more research.
