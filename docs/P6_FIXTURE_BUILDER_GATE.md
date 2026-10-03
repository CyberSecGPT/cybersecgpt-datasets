# P6 Deterministic Fixture Generator and Offline Builder Gate

## Status

**Proposed — exact-head owner architecture/security/licence acceptance is
required before implementation.**

This gate authorizes only the next bounded implementation increment: reviewed
deterministic first-party fixture generators and a network-disabled corpus
builder/replay verifier. It does not authorize external acquisition, a real or
admitted corpus snapshot, tokenizer training, tokenizer-artifact promotion,
final Tokenizer v1 selection, or later P6/P7 work.

## Architecture boundary

The dataset repository may own generator definitions, deterministic offline
construction, validation, filtering, deduplication, manifest production, and
replay evidence. It must not own tokenizer algorithms or artifacts, training,
model weights, inference, authorization, or execution.

The increment must preserve this one-way trust flow:

```text
reviewed generator source + pinned configuration
    -> deterministic fixture bytes
    -> untrusted-input validation and filtering
    -> deterministic ordering and exact deduplication
    -> content-minimized manifest candidate
    -> offline replay verification
```

Generator or builder output remains untrusted data. Neither output nor a valid
manifest may grant authorization, approve a licence, admit a snapshot,
authorize training, weaken policy, or trigger execution.

## Authorized source and rights scope

Only deterministic first-party generated fixtures are in scope. Every literal,
template, vocabulary item, grammar fragment, and configuration input must be:

1. newly authored for CyberSecGPT without copying protected expression;
2. traceable to reviewed repository source and an exact commit;
3. covered by an explicit project-owner rights decision for acquisition,
   processing, tokenizer training, derived statistics, and tokenizer-artifact
   distribution; and
4. bound to a reviewed rights-evidence record and digest.

The generator may encode inert facts, public identifiers, protocol shapes,
syntax forms, and fictional examples. Standards facts or syntax may inform
newly authored fixtures, but external prose, code, datasets, feeds, telemetry,
repositories, vulnerability descriptions, malware, generated AI output, or
other third-party expression must not be copied or fetched.

Public availability is not permission. CC BY, software licences, copyleft,
custom terms, ambiguous public-domain claims, web scraping, remote APIs, hosted
AI systems, pretrained models, and third-party generators are outside this
increment and fail closed.

This gate does not itself make a legal dedication or approve any generated
snapshot. The exact generator revision, rights evidence, notices, and intended
uses require a separately recorded owner licence decision before any output can
be proposed for snapshot admission.

## Deterministic generator contract

Implementation must make every output a pure function of versioned local
inputs. It must bind at least:

- generator ID, schema version, and source commit;
- policy and configuration digests;
- input-provenance digest;
- explicit deterministic seed or an explicit no-seed declaration;
- domain profile and sample-count plan;
- canonical ordering rule;
- strict UTF-8 and LF-newline policy; and
- output sample IDs, byte counts, and SHA-256 digests.

The generator must not use clocks, locale, environment-dependent ordering,
platform randomness, host identity, mutable global state, network responses,
external commands, dynamic imports, callbacks, plugins, or provider services.
The same accepted inputs must produce byte-identical ordered outputs on Python
3.11, 3.12, and 3.13.

Fixtures must be inert and fictional. They must not contain live credentials,
private or routable operational targets, personal data, private telemetry,
weaponized payloads, executable binaries, exploit delivery, persistence,
evasion logic, or instructions that can authorize an action.

## Offline builder and replay contract

The builder may consume only locally supplied regular files and reviewed
generator output. Network access must be absent by construction and verified
under a network-disabled test. The initial implementation must reject archives,
links, devices, sockets, named pipes, traversal, absolute paths, alternate data
streams, external references, unsafe serialization, executable loading, and
unknown file types.

Construction must perform, in a fixed documented order:

1. path and file-type admission;
2. byte and UTF-8 validation;
3. canonical newline normalization;
4. content safety, secret, personal-data, and contamination checks;
5. exact SHA-256 duplicate removal;
6. deterministic sample-ID assignment and ASCII ordering;
7. domain and exclusion accounting; and
8. creation of an unsealed manifest candidate followed by canonical sealing.

Replay verification must rebuild from the same pinned local inputs in a fresh
temporary directory and compare ordered sample IDs, digests, byte counts,
exclusions, transformation identities, canonical manifest bytes, and final
manifest digest. Any difference is terminal and fail closed.

## Resource and content limits

The implementation must enforce limits below the existing manifest maxima. The
first increment is capped at:

- 16 generators;
- 4,096 included samples;
- 65,536 bytes per sample;
- 8,388,608 included bytes in total;
- 32 transformation stages;
- 64 exclusion reasons;
- 1,024 input files;
- 8,388,608 input bytes in total;
- path depth of 8 and path length of 512 UTF-8 bytes; and
- explicit deadline, cancellation, and memory-budget checks.

Limit exhaustion, cancellation, deadline expiry, malformed input, an unknown
domain, a rejected review, inconsistent provenance, filter uncertainty, or a
replay mismatch must produce a terminal non-admitted result. Partial output
must not be promoted, reused as supported evidence, or silently retried with
weaker controls.

## Safety and contamination controls

Tests must demonstrate fail-closed handling for representative secrets and
credentials, private keys, personal identifiers, private communications,
confidential markers, prompt-injection-shaped text, malformed Unicode,
non-canonical newlines, duplicate content, unsafe paths, unsupported file
types, executable signatures, weaponized payload markers, and generator-output
contamination.

Detection results are evidence, not authorization. A negative automated scan
does not prove licence suitability or safety. Uncertain or contradictory
results require exclusion and human review; they must never be promoted to
accepted.

Raw samples, quarantined bytes, detected values, and sensitive excerpts must
not appear in exceptions, logs, test names, reports, manifests, commits,
packages, CI output, or evidence. Diagnostics may contain only bounded record
identifiers, reason codes, counts, and digests.

## Domain scope

The generator may cover only inert representative shapes needed for Tokenizer
v1 evaluation: natural language, programming-language syntax, shell and
PowerShell syntax, assembly-like text, Windows/Linux log shapes, HTTP, DNS,
URLs, reserved IP addresses, hashes, CVE-shaped fictional identifiers, JSON,
YAML, XML, Sigma/YARA-shaped inert rules, SIEM-query shapes, firewall/IDS rule
shapes, infrastructure-as-code, telemetry shapes, threat-intelligence
summaries, and malware-analysis descriptions.

Coverage is not permission to include operational data, copied reports, live
targets, functional malware, or exploit content. Reserved documentation ranges
and explicitly fictional identifiers must be used wherever applicable.

## Repository and distribution boundary

Permitted Git content is limited to generator and builder source, policies,
schemas, minimal reviewed unit-test literals, content-minimized manifests,
notices, digests, and replay evidence. Generated corpus bytes, acquisition
caches, quarantine, temporary files, archives, build output, and snapshot
stores must remain outside Git and outside wheel and source distributions.

The package must retain zero runtime dependencies and no proprietary-provider
SDK or remote-AI dependency. CI retains read-only permissions, uses no secrets,
and must not require network access after dependency installation.

## Required implementation evidence

Before the implementation increment can be accepted, it must provide:

1. deterministic generator and builder contracts matching this gate;
2. exact source, policy, configuration, and provenance binding;
3. cross-version byte-equivalence evidence on Python 3.11–3.13;
4. offline/no-network construction and fresh-directory replay evidence;
5. bounds, cancellation, deadline, malformed-input, path, and fail-closed tests;
6. safety, secret, personal-data, contamination, and deduplication evidence;
7. proof that raw generated samples are absent from Git, logs, packages, and CI
   artifacts;
8. Ruff, Black, strict mypy, repository/security validation, dependency
   consistency, split-package imports, pytest with 100% source and branch
   coverage, package build, and exact distribution verification;
9. final architecture, security, licence, and complete-diff review; and
10. explicit project-owner `ACCEPT` bound to the exact reviewed head.

Passing this implementation gate authorizes only a later, separately reviewed
proposal for an exact corpus snapshot. It does not authorize external source
acquisition, snapshot admission, tokenizer training, artifact promotion, or
final Tokenizer v1 selection.
