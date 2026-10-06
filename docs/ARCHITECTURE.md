# Architecture

## Ownership

This repository owns acquisition governance, provenance, rights review,
filtering, deduplication, deterministic transformation, safety review, corpus
snapshot identity, offline replay, and reusable dataset publication.

It does not own tokenizer behavior or artifacts (`cybersecgpt-tokenizer`), model
training (`cybersecgpt-training`), model architecture, inference, authorization,
or execution.

## Trust boundary

All source bytes, metadata, archives, manifests, URLs, and generated fixtures
are untrusted data. They cannot grant authorization, execute code, load plugins,
make network requests, widen scope, or weaken policy. Acquisition is separate
from deterministic offline construction. Published evidence is content-
minimized; raw corpus bytes do not enter source distributions or CI logs.

## Current gate

The first proposed gate is
[`P6_TOKENIZER_CORPUS_GATE.md`](P6_TOKENIZER_CORPUS_GATE.md). No corpus work may
start until that exact revision receives owner architecture/security/licence
acceptance, passes CI, is merged, and post-merge `main` is verified.

The separately reviewed validation scaffold is documented in
[`P6_CI_VALIDATION_SCAFFOLD.md`](P6_CI_VALIDATION_SCAFFOLD.md). Its package is
an intentionally empty namespace-safe boundary; validation success cannot
authorize data acquisition, admission, training, or artifact promotion.

The first implementation increment is limited to the immutable manifest
contracts in [`P6_CORPUS_MANIFEST_CONTRACTS.md`](P6_CORPUS_MANIFEST_CONTRACTS.md).
It introduces no corpus bytes, acquisition, construction, admission, or
training authority.

The deterministic first-party fixture implementation is governed by
[`P6_FIXTURE_BUILDER_GATE.md`](P6_FIXTURE_BUILDER_GATE.md). Immutable generator
definitions bind source commit, policy, configuration, provenance and seed
state to approved first-party source records. Construction normalizes UTF-8/LF
bytes, applies content checks, exact-digest deduplication and stable ordering,
then seals the existing manifest contract. Replay regenerates from the same
pinned inputs and compares the complete immutable result.

The implementation performs no acquisition, network access, external command,
dynamic import, callback, plugin, unsafe deserialization or execution. Raw
generated fixtures exist only in memory and are absent from package and source
distribution boundaries. A successful build or replay is evidence, not
authorization, corpus admission, licence approval or training approval.

The accepted
[`P6_FIRST_PARTY_SNAPSHOT_GATE.md`](P6_FIRST_PARTY_SNAPSHOT_GATE.md) preserves
the dataset/tokenizer L0 boundary while defining the next review sequence. Exact
generator source must first receive owner rights, safety, and contamination
acceptance. A later snapshot proposal may then construct and replay 1,024
first-party samples, produce a canonical dataset manifest, and verify a
deterministic projection with the exact tokenizer admission verifier. Neither
stage adds a production cross-repository import or authorizes training.

Stage 1 is the exact source proposal in
[`P6_FIRST_PARTY_GENERATOR_SOURCE_EVIDENCE.md`](P6_FIRST_PARTY_GENERATOR_SOURCE_EVIDENCE.md).
Eight static generator families are bound to a caller-supplied accepted Git
revision and expose only content-minimized counts and digests for review. They
create no source approval record and do not invoke the snapshot builder.
