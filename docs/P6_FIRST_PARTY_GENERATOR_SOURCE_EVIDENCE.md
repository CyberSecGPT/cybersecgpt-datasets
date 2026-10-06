# P6 First-Party Generator-Source Proposal Evidence

## Status

**Pending exact-head project-owner architecture, security, licence, safety, and
contamination acceptance.**

This record proposes exact generator source for review. It is technical evidence
only: it records no approved `SourceApprovalRecord`, admits no corpus snapshot,
authorizes no training, and grants no execution authority.

## Accepted parent gate

The proposal is based on the accepted first-party snapshot gate:

- reviewed PR #6 head:
  `c290cb24a11a5e4f4ce504917363b06e1744bcf5`;
- squash-merge commit:
  `602907fd8ae45443f1c210c09a9b5b2c2d92373c`;
- successful pre-merge CI run #9: `37423862388`;
- successful post-merge `main` CI run #10: `37424112336`; and
- pinned tokenizer admission-verifier baseline:
  `0d3b1bff2328392a5b385b0c5b2bd7d08177b792`.

The exact source revision for this proposal is the eventual reviewed PR head,
supplied explicitly to `first_party_generators`. It is not guessed, read from an
environment variable, or embedded through a self-referential commit hash.

## Exact source boundary

The sole generator source is
`src/cybersecgpt/datasets/first_party_generators.py`. It defines eight static,
newly authored first-party generator families. It consumes no files, websites,
repositories, standards, telemetry, vulnerability records, malware, pretrained
models, provider output, remote APIs, user prompts, clocks, randomness, locale,
host identity, or environment-derived ordering.

The source contains exact format strings and deterministic integer ranges. It
uses only fictional defensive wording, reserved documentation domains, and the
IPv4 documentation ranges `192.0.2.0/24`, `198.51.100.0/24`, and
`203.0.113.0/24`. No external expression is proposed for acquisition.

The fixed identities are:

- generator profile:
  `csgpt-first-party-tokenizer-pilot-v1`;
- review-evidence schema:
  `csgpt-first-party-generator-review-v1`;
- proposed first-party rights expression:
  `LicenseRef-CyberSecGPT-First-Party-Tokenizer-v1`; and
- policy SHA-256:
  `309d41bb1ac80be81f07e461364dc134e621950d32037e7e7d314c1759c19dd3`.

The rights expression is a project-specific proposed identifier, not an SPDX
approval, public dedication, repository-wide licence, or completed owner
decision.

## Content-minimized deterministic evidence

For the exact source in this proposal, the review function reports:

- generator count: `8`;
- proposed sample count: `1,024` (`128` per generator);
- proposed UTF-8/LF byte count: `112,467`;
- builder-policy unsafe count: `0`;
- exact SHA-256 duplicate count: `0`; and
- source-independent output identity SHA-256:
  `5a83ee11f172be9af342c116ef918bb2a88d9e15a9f06e798dd7c24cbcdee309`.

The exact per-generator identities are:

| Generator | Exact domain counts | Bytes | Configuration SHA-256 | Input-provenance SHA-256 | Output-identity SHA-256 |
| --- | --- | ---: | --- | --- | --- |
| `csgpt-p6-natural-language-v1` | `natural-language=128` | 20,352 | `057ea151919287c2c54d3338c0b055a04530fad842fabbca4ae0643e0849f239` | `5c4da9651ba82612f993f4286b4f1bccdafea8c51cb53cddb4a266880a26c3b8` | `8a489e83f177ab82ad6c94d99e62621a198438004bffa1767f4ca7fb52123ab7` |
| `csgpt-p6-code-v1` | `assembly=32`, `code=32`, `powershell=32`, `shell=32` | 11,598 | `34063827f525e224f1b95396da24a07c48e25ee25f7244e43a5160370a40a2e2` | `68bfff490cda2a83c40d0769499f29b5c0baa1e9dcdce048ed1f047d1e7b3754` | `e00c48d09c7cab00a940076ed34a0615a4ff0234cfbb88526fe6702250ab500d` |
| `csgpt-p6-logs-v1` | `linux-log=64`, `windows-log=64` | 13,422 | `55112b7573aea16dc9d8ea07952c07851825a31376be30f5fa9d957c673c8815` | `8a91a6c80cc69ea0fed52bd256a96b57e453fdfb4ae7fbc3560598edf8295007` | `66b89af601f777c4c3ee1b49bd2a4723c4eb0aee0c9a0e3bdb9597952bc9d57f` |
| `csgpt-p6-structured-data-v1` | `iac=32`, `json=32`, `xml=32`, `yaml=32` | 9,376 | `ceebcb32391d50530bd2add176397d13aa35d4ffa7f80fdd977dbda74eaf1521` | `57ac18226b3b576fcb4daffcae431ea375e155887c7d0b9e8bcc4954298f9190` | `2649bc78e563061ffe978ce7aa9753cb06c10e4153105ce425ef95875d3c31ab` |
| `csgpt-p6-network-v1` | `dns=32`, `http=32`, `telemetry=32`, `url=32` | 9,646 | `05d388fbfc0629111a23943d6406018248c31672619699716395af5d457f7cd4` | `787f55856042d5af2d0e827f1025d710e4863e50d7aa5b10f72a25527af075bf` | `d104151564b849d0d7dafa5b841f49e442da7dbeabe7539648621c5bce90df44` |
| `csgpt-p6-security-identifiers-v1` | `hash=128` | 13,952 | `0965ee439bef5c868684cf21d75e807e0be258f377d571f6dc884219b1a07f05` | `9b2ef89233a467ff9464485ac16422a0f04eaae976b900293acb1b284266036b` | `a7b5456e1d5aef61af6630fba099f5640d07ee2976fcd50163b21e3abbedecac` |
| `csgpt-p6-detection-rules-v1` | `firewall=26`, `ids=25`, `siem-query=25`, `sigma=26`, `yara=26` | 13,257 | `c31889ca8f26db345da35ca1b774b131e81f815310d1967222f9d404a6c2a3d2` | `bfe92654e84258dc4786c644f08f6ebc272b8ecb91c6ef8a8b7b06e51a8670f7` | `4cdd201242b14de97cd541b09ff6a023ec7be68f71225c5bb26899d4d9f73087` |
| `csgpt-p6-security-prose-v1` | `malware-analysis=64`, `threat-intelligence=64` | 20,864 | `4ec517f2dad4207c8772c86b3b696c3eb8384b03cd6871ceec8b48cb9effeaff` | `16730aa5e2084f521982aa97768887928cef4bd89924ffa1bf4797b9ad86a107` | `0c2b1d48af9dc23748c1a5af6efe85904915e3c1fb7a09b1e3d7967b3a60f138` |

The evidence retains IDs, counts, byte counts, domain counts, and SHA-256
identities only. Expanded fixture bytes remain in memory and are not written to
Git, distributions, logs, test reports, CI artifacts, caches, or this record.

## Pending owner decisions

No decision is pre-recorded. Exact-head acceptance must explicitly approve or
reject the newly authored source for each of:

1. generation or acquisition;
2. deterministic processing;
3. Tokenizer v1 training;
4. derived statistics; and
5. Tokenizer v1 artifact distribution under the recorded limitations.

It must also decide safety and contamination independently. Until all decisions
are explicitly accepted, the source is ineligible for an approved source record
and cannot be passed to the snapshot builder.

Automated rejection scans are only defence-in-depth evidence. Zero automated
findings do not prove originality, legal usability, safety, or absence of
contamination; the owner review remains mandatory.

## Acceptance effect

Exact-head acceptance of this proposal authorizes only creation of approved
source records and the separately reviewed snapshot-evidence increment defined
by the parent gate. It does not itself create those records, build or admit the
snapshot, run the tokenizer admission projection, authorize training, promote
an artifact, select Tokenizer v1, or begin P7.
