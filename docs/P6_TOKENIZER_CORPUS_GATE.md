# P6 Tokenizer v1 Corpus Snapshot — Architecture, Security, and Licence Gate

## Status

**Proposed — exact-head owner acceptance required before implementation.**

This gate initializes only the dataset-governance boundary needed by P6.10. It
does not approve or acquire a corpus, authorize tokenizer training, promote an
artifact, select Tokenizer v1, or begin P7.

## Authorized source class

The proposed snapshot may contain only:

1. deterministic first-party fixtures produced by reviewed, versioned source
   generators without an AI service or external network dependency; and
2. material whose authoritative rights statement establishes public-domain or
   CC0 status for the exact acquired revision and all intended uses.

Public availability, repository visibility, API access, robots permission, a
missing copyright notice, or an unverified licence label is not permission.
CC BY, permissive software licences, copyleft, custom terms, and ambiguous
government material are outside this first snapshot and fail closed.

## Source approval record

Each source record must bind a stable source ID, canonical origin, acquisition
method and date, exact revision and byte digest, authoritative rights-evidence
URI and digest, SPDX expression or explicit public-domain determination,
jurisdiction/limitations, reviewer/date, obligations, restrictions, and
separate allow/deny decisions for acquisition, processing, tokenizer training,
derived statistics, and tokenizer-artifact distribution.

Synthetic records additionally bind generator source commit, generator policy,
configuration digest, input provenance, deterministic seed if any, and a
contamination decision. Generator output may encode inert representative facts
and syntax but must not reproduce unlicensed source expression.

## Snapshot construction

Construction is a two-stage process:

- an explicitly authorized acquisition stage produces immutable local inputs;
- a network-disabled builder validates and transforms those inputs into an
  ordered snapshot and content-minimized manifest.

The manifest binds schema version, corpus ID, every source decision, generator
and transformation identity, inclusion/exclusion rules, strict UTF-8 policy,
ordering, deterministic sampling, exact duplicate removal, domain counts,
exclusion counts, ordered sample IDs/digests/byte counts, total bounds, notices,
approved purpose, distribution limitations, and its own canonical digest.

Any byte, order, source, rights, rule, generator, configuration, or review
change creates a new snapshot identity. Offline replay must reproduce identical
ordered sample digests and manifest bytes.

## Domain profile

The bounded pilot must cover natural language and representative defensive
cybersecurity syntax: Python, JavaScript/TypeScript, C/C++, Rust, Java,
PowerShell, shell, assembly-like text, Windows/Linux logs, HTTP, DNS, URLs, IP
addresses, hashes, CVE-shaped identifiers, JSON, YAML, XML, Sigma/YARA-shaped
inert rules, SIEM query shapes, firewall/IDS rules, infrastructure-as-code,
telemetry, threat-intelligence summaries, and malware-analysis descriptions.

Coverage is evidence, not permission to include live credentials, operational
targets, weaponized payloads, malicious binaries, or private telemetry.

## Security controls

- strict byte, sample, source, archive, expansion, nesting, path, time, and
  memory ceilings;
- strict UTF-8 and canonical newline handling;
- traversal, link, device, executable, and unsafe serialization rejection;
- secret, credential, private-key, personal-data, confidential-data, malformed-
  input, contamination, and exact-duplicate checks;
- inert parsing only—no importing, compiling, rendering, interpreting, shelling
  out to content, dynamic loading, callbacks, or plugins;
- no raw sample content in logs, errors, evidence, commits, packages, or CI;
- cancellation and deadline propagation with terminal fail-closed outcomes;
- no implicit network access and no proprietary provider dependency; and
- admission evidence cannot grant authorization or weaken any external policy.

## Repository and publication boundary

Raw acquired material and quarantine stay outside Git and outside package
distributions. This repository may contain generator source, schemas, policy,
tests using minimal reviewed fixtures, content-minimized manifests, notices,
digests, and reproducibility evidence. A separately controlled snapshot store
holds admitted corpus bytes by exact digest.

`cybersecgpt-tokenizer` may consume only a separately accepted manifest digest
and locally supplied bytes whose identity and order pass its admission verifier.

## Required implementation evidence

Before the snapshot can be accepted:

1. implement canonical source, rights, transformation, sample, exclusion, and
   snapshot manifests with bounded deterministic encodings;
2. implement deterministic first-party generators and a network-disabled
   builder/replay verifier;
3. record authoritative rights evidence for every non-generated input;
4. demonstrate domain coverage, deduplication, safety/secret/PII/contamination
   filtering, malformed-input rejection, and resource limits;
5. produce an exact proposed snapshot manifest and digest without committing raw
   corpus bytes;
6. reproduce it offline from pinned authorized inputs;
7. cross-check admission using `cybersecgpt-tokenizer` at its exact version;
8. pass Ruff, Black, strict mypy, repository/security validation, dependency
   consistency, split-package imports, pytest with 100% source coverage, Python
   3.11–3.13, package build, and exact distribution-boundary verification; and
9. receive an explicit owner architecture/security/licence `ACCEPT` decision
   bound to the exact reviewed head and exact snapshot manifest digest.

Snapshot acceptance authorizes only a separately gated tokenizer-training run.
Training success does not authorize artifact promotion or final Tokenizer v1
selection.
