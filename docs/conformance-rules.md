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

## Coverage

13 of 15 declared rules are checked.
