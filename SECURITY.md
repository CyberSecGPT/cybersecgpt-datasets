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
