# Conformance rules

This is a catalog of every AFF4 and AFF4-L specification rule that `aff4tools conformance` knows about, generated from the rule
registry in `src/rules/catalog.rs`.

**This file is generated.** Edit the rule registry, not this document.

## Rule states

| State | Meaning |
|---|---|
| detected | A checker exists and runs. |
| not implemented | Declared, but no checker exists yet. Reported as a coverage gap. |
| not checkable | No checker can exist yet, because the requirement itself is unsettled. |

## AFF4 Specification 1.0a

| Rule | Level | State | Requirement |
|---|---|---|---|
| `AFF4_V1_0A/2.2/1` (§2.2) | SHOULD | not implemented | Numeric literals carry an explicit datatype, as the standard's own containers write them. |
| `AFF4_V1_0A/2.2/2` (§2.2) | SHOULD | not implemented | Datatype IRIs are spelled as the standard defines them, not in a variant case. |
| `AFF4_V1_0A/2.2/3` (§2.2) | MUST | detected | A literal's datatype is the one its property expects. |
| `AFF4_V1_0A/6.1/1` (§6.1) | MUST | detected | A digest's length matches the algorithm its datatype declares. |
| `AFF4_V1_0A/5.4/1` (§5.4) | MUST | detected | The ZIP comment carries the volume ARN starting at offset 0, with nothing appended. |
| `AFF4_V1_0A/5.4/2` (§5.4) | MUST | detected | The ZIP comment and container.description agree on the volume ARN. |
| `AFF4_V1_0A/5.4/3` (§5.4) | MUST | detected | Every object the volume holds appears in its own aff4:contains manifest. |
| `AFF4_V1_0A/5.1/1` (§5.1) | MUST | detected | An ARN maps to a storage path by the URI-to-path rules, which admit no byte-range suffix. |
| `AFF4_V1_0A/4/1` (§4) | MAY | detected | A discontiguous map's holes are filled from its declared gap stream. |
| `AFF4_V1_0A/5/1` (§5) | MUST | detected | Each storage path holds one segment, so a repeated member name leaves the earlier one unreachable. |
| `AFF4_V1_0A/7.1/1` (§7.1) | MAY | detected | A stripe may reference streams held in a sibling volume of the same set. |
| `AFF4_V1_0A/7.1/2` (§7.1) | MUST | detected | Volumes of one striped set agree on every property of a commonly-named stream. |
| `AFF4_V1_0A/none/1` (not legislated) | MAY | detected | Content-addressed dedupe subjects are an extension no clause prohibits. |
| `AFF4_V1_0A/none/2` (not legislated) | MAY | detected | A reference to an undescribed ARN with no aff4:stored pointer cannot be resolved or attributed. |

## AFF4-L (Schatz, DFRWS USA 2019, Digital Investigation 29, S143-S149)

| Rule | Level | State | Requirement |
|---|---|---|---|
| `AFF4L_PAPER_2019/3.8/1` (§3.8) | MUST | detected | A file stored directly as a ZIP segment declares aff4:zip_segment in its type list. |

## AFF4-L Standard v1.0-ALPHA

| Rule | Level | State | Requirement |
|---|---|---|---|
| `AFF4L_V1_ALPHA/1.1/1` (§1.1) | MUST | not implemented | AFF4 objects are named by ARN, with the suspect's path and file name carried in properties rather than encoded into the name. |
| `AFF4L_V1_ALPHA/4.1/1` (§4.1) | MUST | not implemented | A writer emits new lexicon terms under the namespace its governing standard assigns them. |
| `AFF4L_V1_ALPHA/4.1/2` (§4.1) | MAY | not implemented | A reader may accept either namespace prefix for a lexicon term, so that containers written against the earlier schema still read. |
| `AFF4L_V1_ALPHA/6/1` (§6) | MUST | not implemented | A reader handles every storage stream form this section describes, not a chosen subset. |
| `AFF4L_V1_ALPHA/6/2` (§6) | MUST | not implemented | A writer implements at least one of the storage stream forms this section describes. |
| `AFF4L_V1_ALPHA/6.1/1` (§6.1) | MUST | not implemented | A stream held as a ZIP segment is compressed with Stored or Deflate and no other method. |
| `AFF4L_V1_ALPHA/6.1/2` (§6.1) | SHOULD NOT | not implemented | A ZIP segment storage stream holds no stream of one gibibyte or more. |
| `AFF4L_V1_ALPHA/6.1/3` (§6.1) | MUST | not implemented | A writer records a linear digest of each ZIP segment storage stream in that stream's hash property. |
| `AFF4L_V1_ALPHA/6.2/1` (§6.2) | MUST NOT | not implemented | An in-metadata storage stream holds no stream larger than one kilobyte. |
| `AFF4L_V1_ALPHA/6.2/2` (§6.2) | MAY | not implemented | A stream carried inside the metadata need not record its own digests, since the metadata integrity hash covers it. |
| `AFF4L_V1_ALPHA/6.3.1/1` (§6.3.1) | MUST | not implemented | A writer computes and records a block map digest for every map, under either of the two property spellings the standard allows. |
| `AFF4L_V1_ALPHA/6.3.1/2` (§6.3.1) | MUST | not implemented | A reader accepts either block map digest spelling and can verify the block map digests of every map and dependent image stream. |
| `AFF4L_V1_ALPHA/9/1` (§9) | MUST | not checkable | Triples from the primary metadata segment and from every store it imports are read as one graph. |
| `AFF4L_V1_ALPHA/9a/1` (§9a) | MAY | not checkable | A container may carry an accelerated metadata store beside the primary one, holding everything the primary and any secondary stores hold. |
| `AFF4L_V1_ALPHA/9a/2` (§9a) | MAY | not checkable | A reader may take its metadata from the accelerated store in place of the primary and secondary stores. |
| `AFF4L_V1_ALPHA/9a.1/1` (§9a.1) | MUST | not checkable | An implementation of the accelerated serialization confines itself to the triple, dictionary, and dictionary-section encodings the standard names. |
| `AFF4L_V1_ALPHA/10.1/1` (§10.1) | MUST | not implemented | The digest of the primary metadata segment is recorded in a companion segment beside it, written in the turtle datatype syntax. |
| `AFF4L_V1_ALPHA/10.1/2` (§10.1) | MUST | not implemented | That digest uses SHA-256, SHA-512, or a stronger algorithm the standard supports. |
| `AFF4L_V1_ALPHA/10.2/1` (§10.2) | MAY | not checkable | A container may carry an X509 signature of the primary metadata segment in a companion segment beside it. |
| `AFF4L_V1_ALPHA/10.2/2` (§10.2) | MUST | not checkable | A signature is PEM encoded, and the certificate chain stored with it is complete down to the root and likewise PEM encoded. |
| `AFF4L_V1_ALPHA/10.2/3` (§10.2) | MUST | not checkable | Where several keys sign the metadata, each signature and certificate segment is named by the pattern the standard fixes. |
| `AFF4L_V1_ALPHA/10.2/4` (§10.2) | MUST | not checkable | A signature and its certificate chain share one extensible name part, itself valid UTF-8. |
| `AFF4L_V1_ALPHA/10.3/1` (§10.3) | MUST | not checkable | The digest of each secondary metadata store is recorded in the primary store, against that secondary store's own resource name. |
| `AFF4L_V1_ALPHA/10.3/2` (§10.3) | MUST | not checkable | A digest recorded for a secondary metadata store uses SHA-256, SHA-512, or a stronger algorithm the standard supports. |

## Coverage

13 of 39 declared rules are checked.
