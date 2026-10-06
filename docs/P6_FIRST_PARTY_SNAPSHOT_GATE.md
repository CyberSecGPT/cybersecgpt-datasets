# P6 Tokenizer v1 First-Party Corpus Snapshot Gate

## Status

**Accepted — project-owner acceptance was recorded for PR #6 head
`c290cb24a11a5e4f4ce504917363b06e1744bcf5`; squash-merged as
`602907fd8ae45443f1c210c09a9b5b2c2d92373c`; pre-merge CI run #9 and
post-merge `main` CI run #10 passed.**

This gate authorizes only the reviewed preparation of one bounded, deterministic,
first-party-generated Tokenizer v1 pilot snapshot and its content-minimized
admission evidence. It does not approve generator source that has not yet been
reviewed, admit a snapshot, authorize tokenizer training, promote an artifact,
finally select Tokenizer v1, or begin later P6/P7 work.

## Accepted baselines

The proposed increment is based on these exact verified revisions:

- `cybersecgpt-datasets` main
  `8dfc03c7c69bd126a7bbd3f47d8a0f3b91061083`, including the canonical
  snapshot records and deterministic offline fixture builder; and
- `cybersecgpt-tokenizer` main
  `0d3b1bff2328392a5b385b0c5b2bd7d08177b792`, including the P6.10
  corpus-manifest admission verifier.

The eventual snapshot evidence must bind the exact implementation revisions it
actually uses. A baseline change requires renewed compatibility review and may
change the snapshot or admission-manifest identity.

## Architecture and ownership boundary

`cybersecgpt-datasets` owns generator-source review, source approval records,
deterministic construction, filtering, deduplication, snapshot identity, replay,
and reusable content-minimized evidence. `cybersecgpt-tokenizer` owns only the
tokenizer-specific admission projection and exact local-byte verification.

The implementation must preserve this flow:

```text
accepted generator source revision
    -> independently recorded owner rights/safety/contamination decision
    -> deterministic in-memory generation
    -> network-disabled validation, filtering, and deduplication
    -> canonical dataset snapshot manifest + replay identity
    -> deterministic tokenizer admission projection
    -> exact local-byte admission with the pinned tokenizer verifier
    -> content-minimized evidence proposal
```

No production package may import the peer repository or create a circular L0
dependency. Cross-repository verification must use exact local checkouts in an
isolated evidence environment and must not add a runtime dependency, provider
SDK, network service, or shared private storage.

Generator output, manifests, projection output, admission output, and CI results
are evidence only. They cannot grant authorization, approve rights, lower data
classification, widen target scope or provider/network policy, relax offline
requirements, extend deadlines or resource budgets, reduce verification, or
trigger training or execution.

## Authorized source class

Only newly authored CyberSecGPT first-party generator source is in scope. This
increment must not acquire, scrape, copy, translate, summarize, or derive
protected expression from websites, repositories, feeds, reports, standards,
telemetry, malware, vulnerability descriptions, commercial tools, hosted AI
systems, pretrained models, or other third-party material.

Public facts, syntax shapes, reserved documentation identifiers, and fictional
defensive examples may inform original fixtures. They do not authorize copying
third-party prose or code. No public-domain, CC0, open-source, proprietary, or
other external source is admitted by this gate.

The exact generator literals, templates, vocabularies, grammar fragments,
configuration, policy, and provenance digest must receive a recorded
project-owner decision covering, separately:

- acquisition or generation;
- processing;
- tokenizer training;
- derived statistics; and
- tokenizer-artifact distribution.

The first-party rights record is permission for the reviewed CyberSecGPT use; it
is not a public copyright dedication or a repository-wide licence. Unknown,
ambiguous, contradictory, expired, revoked, or differently scoped evidence fails
closed.

## Two-stage review sequence

Approval must not be asserted before it exists. Implementation therefore uses
two separately reviewed increments after this gate:

1. **Generator-source review.** Add only the exact deterministic generator
   definitions, policy/configuration identities, minimal tests, and
   content-minimized rights/safety/contamination evidence. Generate no admitted
   snapshot and record no owner decision that has not actually occurred. The
   owner must accept that exact head before it may become an approved source
   revision.
2. **Snapshot evidence.** From the accepted generator-source revision, create
   approved source records, construct and replay the exact snapshot, project it
   into the tokenizer admission contract, and record both manifest digests and
   admission evidence. The owner must accept the exact snapshot-evidence head and
   both exact manifest digests before the snapshot is admitted.

Any generator-source change after stage 1 invalidates its acceptance and returns
the process to stage 1. Any content, ordering, mapping, policy, transformation,
review, notice, or digest change after stage 2 creates a new candidate snapshot
requiring renewed acceptance.

## Fixed pilot profile

The candidate is capped at exactly eight accepted generators and eight matching
first-party source records. Each generator represents one tokenizer evaluation
domain and proposes exactly 128 safe, unique samples. A conforming candidate
therefore has exactly 1,024 included samples. Any filter exclusion, duplicate,
missing domain, count mismatch, or unsafe item makes the candidate ineligible
for snapshot acceptance rather than silently reducing or rebalancing it.

The included bytes must remain within the existing stricter builder ceilings:

- at most 65,536 bytes per sample;
- at most 8,388,608 bytes in total;
- at most 1,024 generated inputs;
- path depth at most 8 and UTF-8 path length at most 512 bytes; and
- existing cancellation, deadline, and memory-related count/byte checks.

The exact fine-domain plan and tokenizer projection are:

| Tokenizer evaluation domain | Dataset fine domains | Exact included count |
| --- | --- | ---: |
| `natural_language` | `natural-language` | 128 |
| `code` | `code`, `powershell`, `shell`, `assembly` | 32 each |
| `logs` | `windows-log`, `linux-log` | 64 each |
| `structured_data` | `json`, `yaml`, `xml`, `iac` | 32 each |
| `network` | `http`, `dns`, `url`, `telemetry` | 32 each |
| `security_identifiers` | `hash` | 128 |
| `detection_rules` | `sigma`, `yara`, `firewall`, `ids`, `siem-query` | 26, 26, 26, 25, 25 |
| `security_prose` | `threat-intelligence`, `malware-analysis` | 64 each |

Every sample must be fictional and inert. Reserved documentation networks and
domains must be used where identifiers are needed. Security prose may describe
defensive analysis shapes but must not provide functional exploitation,
credential theft, persistence, evasion, destructive action, or operational
targeting instructions.

## Exact dataset snapshot identity

The snapshot evidence must bind at least:

- exact dataset repository and accepted generator-source commits;
- corpus and manifest schema versions;
- generator IDs, schema versions, source commits, policy/configuration digests,
  provenance digests, and explicit seed/no-seed state;
- every reviewed source record and rights-evidence digest;
- strict UTF-8/LF, ordering, sampling, filtering, deduplication, and
  transformation identities;
- notices and distribution limitations;
- ordered sample IDs, fine domains, byte counts, and SHA-256 digests;
- exact exclusion counts, which must all be zero for this pilot candidate;
- canonical dataset manifest bytes and digest; and
- the deterministic replay digest.

Construction must occur with network access denied and no filesystem-dependent
ordering, clock input, locale, host identity, external command, dynamic import,
callback, plugin, unsafe deserialization, or provider service. Fresh-directory
replay on Python 3.11, 3.12, and 3.13 must reproduce the same ordered sample
records, canonical manifest bytes, manifest digest, and replay digest.

Raw generated samples must remain in memory for this pilot. Any persistent or
external snapshot store requires a separate architecture, security, licence,
retention, and access-control review before use. Raw samples must not enter Git,
wheel/source distributions, logs, exceptions, test reports, CI artifacts,
caches, or review evidence.

## Deterministic tokenizer admission projection

The projection into `csgpt-corpus-manifest-v1` must be a pure deterministic
operation over the accepted dataset manifest and ordered local bytes. It must
apply these rules exactly:

- retain `corpus_id`, `source_id`, acquisition metadata, source revision and
  digest, reviewer/date, permission flags, sample ID, byte count, content digest,
  exclusion reason/count, and ordered sample position;
- map dataset `approved_purpose` unchanged;
- map dataset `distribution_limitations` to tokenizer
  `artifact_distribution_terms`;
- use the exact first-party expression
  `LicenseRef-CyberSecGPT-First-Party-Tokenizer-v1`, with the underlying rights
  evidence and restrictions retained in the dataset manifest;
- map an approved dataset rights decision to tokenizer `approved`, and approved
  safety/contamination decisions to tokenizer `clean`; any other value is a
  terminal projection failure;
- map fine domains only through the fixed table above;
- map each dataset transformation to the same stage ID and configuration digest,
  with tokenizer tool ID `<tool-id>@<tool-revision>`; and
- append an `admission-projection` transformation whose configuration digest is
  the exact dataset manifest digest and whose tool identity binds the projection
  profile and exact dataset implementation revision.

The projection evidence must bind both the dataset manifest digest and the
distinct tokenizer admission-manifest digest. Digest equality is neither
expected nor accepted as a substitute for verified field mapping.

The pinned tokenizer verifier must then admit exactly 1,024 locally regenerated
sample byte strings in manifest order. Missing, extra, reordered, renamed,
changed, resized, unreadable, rights-ineligible, cancelled, deadline-expired, or
digest-mismatched content is terminal and must not be retried under weaker
controls.

## Security, contamination, and failure policy

The proposal must demonstrate fail-closed handling for representative:

- secrets, credentials, private keys, authentication material, personal or
  regulated data, private communications, and confidential markers;
- prompt/tool-injection-shaped text and instructions that claim authority;
- executable signatures, unsafe serialization, filesystem links, devices,
  archives, traversal, alternate streams, external references, callbacks, and
  plugins;
- non-documentation network targets, weaponized payload markers, persistence,
  evasion, destructive action, and functional malware or exploit content;
- malformed Unicode, non-canonical newlines, duplicate bytes, unknown domains,
  altered ordering, projection mismatch, and replay mismatch; and
- sample, byte, path, memory, cancellation, and deadline limits.

Automated negative scans are defence in depth, not proof that content is safe,
original, uncontaminated, or legally usable. Uncertain or contradictory results
exclude the source and block the candidate. Failures disclose only bounded IDs,
reason codes, counts, and digests, never raw or quarantined values.

## Required evidence before snapshot acceptance

The snapshot-evidence increment must provide:

1. the exact accepted generator-source revision and recorded owner
   rights/safety/contamination decision;
2. exact source, generator, configuration, policy, provenance, notice, and
   restriction bindings;
3. the fixed 1,024-sample domain/count report with no exclusions or duplicates;
4. exact dataset manifest and replay digests;
5. the deterministic projection profile, tokenizer verifier commit, tokenizer
   admission-manifest digest, and successful exact-byte admission result;
6. fresh-directory, network-disabled, Python 3.11–3.13 reproduction evidence;
7. negative security, malformed-input, resource, cancellation, deadline,
   projection, rights, and replay evidence;
8. proof that raw corpus bytes, secrets, credentials, quarantine, build output,
   provider dependencies, and network requirements are absent from Git,
   distributions, logs, and CI artifacts;
9. Ruff, Black, strict mypy, repository/security validation, dependency
   consistency, split-package imports, pytest with 100% source and branch
   coverage, package build, and exact distribution verification;
10. final architecture, security, licence, and complete-diff review; and
11. explicit project-owner `ACCEPT` bound to the exact reviewed head, exact
    dataset manifest digest, and exact tokenizer admission-manifest digest.

Snapshot acceptance authorizes only a separately proposed and reviewed
Tokenizer v1 training-run gate. It does not itself authorize training, artifact
promotion, signing, final Tokenizer v1 selection, model training, or P7 work.
