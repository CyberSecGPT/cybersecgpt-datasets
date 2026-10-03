# P6 Dataset CI and Validation Scaffold

## Scope

This scaffold makes validation observable before any corpus implementation. It
contains only packaging, repository-policy validation, tests, and CI wiring.
It does not define a corpus schema, acquire or generate samples, admit a
snapshot, authorize training, or promote a tokenizer artifact.

## Required gates

Every pull request and push to `main` runs unchanged checks on Python 3.11,
3.12, and 3.13:

- Ruff and Black;
- strict mypy;
- repository, secret-pattern, corpus-file, provider, and dependency-boundary
  validation;
- installed dependency consistency and namespace-package import;
- pytest with 100% source coverage; and
- package build with exact wheel and source-distribution verification.

The workflow has read-only repository permissions, uses no secrets, makes no
provider calls, and grants no authorization. The validation package exposes no
corpus implementation API.

## Acceptance boundary

This scaffold requires exact-head owner architecture/security acceptance and
post-merge `main` CI verification. Passing it permits only the next separately
reviewed corpus implementation increment described by
`P6_TOKENIZER_CORPUS_GATE.md`.
