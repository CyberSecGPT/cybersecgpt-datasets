# CyberSecGPT Datasets

Authoritative repository for CyberSecGPT dataset governance, provenance,
licensing, deterministic corpus construction, filtering, deduplication,
versioning, validation, and reproducible snapshot publication.

The repository is being initialized for the P6 Tokenizer v1 corpus snapshot.
No corpus, source, snapshot, training input, tokenizer artifact, or production
approval exists yet.

Repository validation is offline-capable and cannot grant authorization. The
Python 3.11–3.13 CI and exact distribution boundary are defined in
[`docs/P6_CI_VALIDATION_SCAFFOLD.md`](docs/P6_CI_VALIDATION_SCAFFOLD.md).
The first implementation increment defines only bounded canonical manifest
contracts; see
[`docs/P6_CORPUS_MANIFEST_CONTRACTS.md`](docs/P6_CORPUS_MANIFEST_CONTRACTS.md).
The deterministic first-party fixture generator and network-disabled
builder/replay implementation is governed by
[`docs/P6_FIXTURE_BUILDER_GATE.md`](docs/P6_FIXTURE_BUILDER_GATE.md). It binds
reviewed source approvals to generator configuration, produces only fictional
in-memory fixtures, filters and deduplicates in a fixed order, seals a
content-minimized manifest candidate, and verifies byte-identical replay without
network access. Generated corpus bytes remain outside Git and distributions.

This implementation produces evidence only. It does not admit a corpus
snapshot, authorize training, approve a licence, promote a tokenizer artifact,
or grant any execution authority.

The proposed first policy permits only deterministic first-party generated
fixtures and sources independently verified as public domain or CC0. Public
availability alone is never sufficient. See
[`docs/P6_TOKENIZER_CORPUS_GATE.md`](docs/P6_TOKENIZER_CORPUS_GATE.md).
