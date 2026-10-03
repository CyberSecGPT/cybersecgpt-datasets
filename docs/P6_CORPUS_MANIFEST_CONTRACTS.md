# P6 Corpus Manifest Contracts

## Scope

This increment implements only immutable, bounded, content-minimizing records
for source approval, deterministic transformations, ordered samples,
exclusions, and an exact snapshot identity. It does not acquire or generate
content, build or admit a snapshot, perform filtering, train a tokenizer or
model, or promote an artifact.

## Security and architecture boundary

Canonical length-prefixed bytes bind every provenance, rights, safety,
contamination, purpose, transformation, ordering, sample, exclusion, notice,
and distribution decision. Any change produces a different SHA-256 identity.
Unknown, rejected, or revoked reviews and any denied purpose permission fail
closed. Generated sources require pinned generator provenance; non-generated
sources cannot claim it.

The contracts retain no raw corpus bytes, perform no I/O, networking,
deserialization, imports, callbacks, plugins, subprocesses, or execution, and
emit one content-minimizing validation error. A valid manifest is integrity
evidence only and cannot grant authorization or weaken any external policy.

## Deferred work

Generators, acquisition, filtering, deterministic construction/replay,
Tokenizer admission projection, an exact proposed snapshot, licence evidence,
and cross-repository verification require separately reviewed increments.
