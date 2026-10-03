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
