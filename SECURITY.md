# Security Policy

Report suspected vulnerabilities privately to the repository owner rather than
publishing secrets or sensitive corpus content in an issue.

Dataset inputs are untrusted. The project rejects secrets, credentials, private
keys, personal or regulated data, private communications, confidential data,
executable loaders, unsafe deserialization, archive traversal, external
references, callbacks, plugins, and implicit network access.

Unknown, ambiguous, contradictory, expired, revoked, or incompatible rights
fail closed. Raw samples and sensitive values must not appear in logs, test
reports, errors, commits, packages, or CI artifacts.

Dataset admission never grants authorization and never weakens classification,
target, provider/network, offline, deadline, resource, or verification policy.

CI uses read-only repository permissions and no project secrets. Repository
validation rejects corpus-like archives/data files, recognized secret formats,
runtime dependencies, and proprietary provider SDK markers. These checks are
defence in depth and do not replace source, licence, or human security review.

Manifest validation is content-minimizing and in-memory only. A structurally
valid or sealed manifest is integrity evidence, never authorization, licence
approval, snapshot admission, training approval, or artifact approval.

The proposed fixture/builder gate permits no external acquisition or copied
third-party expression. Generator and builder output remains untrusted;
uncertain rights, provenance, safety, contamination, filtering, or replay
results fail closed and cannot be converted into snapshot admission.

The fixture builder accepts only immutable reviewed first-party generator
definitions. It binds every generator to an independently approved source
record, has no network or execution primitive, enforces explicit cancellation,
deadline, input-count and byte ceilings, and reports only a fixed generic error.
Secret-, personal-data-, executable-, prompt-injection- and contamination-shaped
fixtures are excluded without echoing raw values. Exact duplicates are removed
before stable sample identities and a sealed manifest candidate are produced.
Replay mismatch remains terminal and cannot be reinterpreted as acceptance.
