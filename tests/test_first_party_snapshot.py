"""Verify the exact accepted-source snapshot and tokenizer projection evidence."""

from collections import Counter
from dataclasses import replace
from hashlib import sha256

import pytest

from cybersecgpt.datasets import (
    ACCEPTED_GENERATOR_SOURCE_REVISION,
    FIRST_PARTY_CORPUS_ID,
    FIRST_PARTY_GENERATOR_COUNT,
    FIRST_PARTY_LICENSE_EXPRESSION,
    FIRST_PARTY_SAMPLE_COUNT,
    FIRST_PARTY_SNAPSHOT_EVIDENCE_SCHEMA_VERSION,
    FIRST_PARTY_SNAPSHOT_PROFILE_VERSION,
    OWNER_ACCEPTANCE_COMMENT_ID,
    OWNER_ACCEPTANCE_EVIDENCE_URI,
    OWNER_ACCEPTANCE_SHA256,
    TOKENIZER_ADMISSION_SCHEMA_VERSION,
    TOKENIZER_PROJECTION_PROFILE_VERSION,
    TOKENIZER_VERIFIER_REVISION,
    FixtureBuildError,
    ReviewDecision,
    SourceKind,
    approved_first_party_sources,
    build_first_party_snapshot,
    first_party_generator_evidence,
    first_party_snapshot_evidence,
    project_tokenizer_admission_manifest,
)

IMPLEMENTATION_REVISION = "2" * 40
FINE_DOMAIN_COUNTS = {
    "assembly": 32,
    "code": 32,
    "dns": 32,
    "firewall": 26,
    "hash": 128,
    "http": 32,
    "iac": 32,
    "ids": 25,
    "json": 32,
    "linux-log": 64,
    "malware-analysis": 64,
    "natural-language": 128,
    "powershell": 32,
    "shell": 32,
    "siem-query": 25,
    "sigma": 26,
    "telemetry": 32,
    "threat-intelligence": 64,
    "url": 32,
    "windows-log": 64,
    "xml": 32,
    "yaml": 32,
    "yara": 26,
}
TOKENIZER_DOMAIN_COUNTS = {
    "code": 128,
    "detection_rules": 128,
    "logs": 128,
    "natural_language": 128,
    "network": 128,
    "security_identifiers": 128,
    "security_prose": 128,
    "structured_data": 128,
}


def test_owner_decision_creates_exact_approved_source_records() -> None:
    assert ACCEPTED_GENERATOR_SOURCE_REVISION == (
        "1e67188772c9960900769d6e3f74e615c593d049"
    )
    assert TOKENIZER_VERIFIER_REVISION == ("0d3b1bff2328392a5b385b0c5b2bd7d08177b792")
    assert OWNER_ACCEPTANCE_COMMENT_ID == 6_011_109_292
    assert OWNER_ACCEPTANCE_EVIDENCE_URI.endswith("issuecomment-6011109292")
    assert OWNER_ACCEPTANCE_SHA256 == (
        "02b9e9a050189d4b7c7471410a40326efcac07509f86963274eba46c3dae044e"
    )

    generated = first_party_generator_evidence(ACCEPTED_GENERATOR_SOURCE_REVISION)
    output_identities = {
        record.source_id: record.output_identity_sha256
        for record in generated.generators
    }
    sources = approved_first_party_sources()
    assert len(sources) == FIRST_PARTY_GENERATOR_COUNT == 8
    assert len({source.source_id for source in sources}) == len(sources)
    for source in sources:
        assert source.source_kind is SourceKind.FIRST_PARTY_GENERATED
        assert source.source_revision == ACCEPTED_GENERATOR_SOURCE_REVISION
        assert source.source_sha256 == output_identities[source.source_id]
        assert source.rights_evidence_sha256 == OWNER_ACCEPTANCE_SHA256
        assert source.rights_basis == FIRST_PARTY_LICENSE_EXPRESSION
        assert source.rights_decision is ReviewDecision.APPROVED
        assert source.safety_decision is ReviewDecision.APPROVED
        assert source.contamination_decision is ReviewDecision.APPROVED
        assert source.approved()
        assert source.generator_commit == ACCEPTED_GENERATOR_SOURCE_REVISION


def test_exact_snapshot_build_replay_and_identity() -> None:
    result = build_first_party_snapshot()
    manifest = result.manifest
    assert manifest.corpus_id == FIRST_PARTY_CORPUS_ID
    assert len(manifest.sources) == FIRST_PARTY_GENERATOR_COUNT
    assert len(manifest.samples) == FIRST_PARTY_SAMPLE_COUNT == 1_024
    assert sum(sample.byte_count for sample in manifest.samples) == 112_467
    assert Counter(sample.domain for sample in manifest.samples) == FINE_DOMAIN_COUNTS
    assert tuple((item.reason_id, item.count) for item in manifest.exclusions) == (
        ("exact-duplicate", 0),
        ("unsafe-content", 0),
    )
    assert manifest.manifest_sha256 == (
        "374773d05a9aae380ad88f477210da75d40adc90cca1afac9ee8800a93656fef"
    )
    assert result.replay_sha256 == (
        "002ea5b42cd67d94dcc3e03531c272499963a5a9ffa0171ab01adfdb8a554206"
    )
    assert manifest.manifest_sha256 == sha256(manifest.canonical_bytes()).hexdigest()


def test_projection_matches_exact_pinned_tokenizer_shape() -> None:
    snapshot = build_first_party_snapshot()
    projection = project_tokenizer_admission_manifest(
        snapshot.manifest, IMPLEMENTATION_REVISION
    )
    assert projection.schema_version == TOKENIZER_ADMISSION_SCHEMA_VERSION
    assert projection.corpus_id == snapshot.manifest.corpus_id
    assert projection.approved_purpose == snapshot.manifest.approved_purpose
    assert (
        projection.artifact_distribution_terms
        == snapshot.manifest.distribution_limitations
    )
    assert len(projection.sources) == 8
    assert len(projection.samples) == 1_024
    assert Counter(sample.domain for sample in projection.samples) == (
        TOKENIZER_DOMAIN_COUNTS
    )
    assert projection.exclusion_counts == (
        ("exact-duplicate", 0),
        ("unsafe-content", 0),
    )
    assert tuple(stage.stage_id for stage in projection.transformations) == (
        "generate",
        "filter",
        "deduplicate",
        "admission-projection",
    )
    assert projection.transformations[-1].tool_id == (
        f"{TOKENIZER_PROJECTION_PROFILE_VERSION}@{IMPLEMENTATION_REVISION}"
    )
    assert (
        projection.transformations[-1].configuration_sha256
        == snapshot.manifest.manifest_sha256
    )
    assert all(source.rights_decision == "approved" for source in projection.sources)
    assert all(
        source.sensitive_data_decision == "clean"
        and source.contamination_decision == "clean"
        and source.license_expression == FIRST_PARTY_LICENSE_EXPRESSION
        for source in projection.sources
    )
    assert (
        projection.manifest_sha256 == sha256(projection.canonical_bytes()).hexdigest()
    )
    assert projection.manifest_sha256 != snapshot.manifest.manifest_sha256
    assert projection.with_computed_digest() is projection


def test_content_minimized_evidence_is_revision_bound() -> None:
    evidence = first_party_snapshot_evidence(IMPLEMENTATION_REVISION)
    changed = first_party_snapshot_evidence("3" * 40)
    assert evidence.schema_version == FIRST_PARTY_SNAPSHOT_EVIDENCE_SCHEMA_VERSION
    assert evidence.snapshot_profile_version == FIRST_PARTY_SNAPSHOT_PROFILE_VERSION
    assert evidence.projection_profile_version == TOKENIZER_PROJECTION_PROFILE_VERSION
    assert evidence.accepted_generator_source_revision == (
        ACCEPTED_GENERATOR_SOURCE_REVISION
    )
    assert evidence.dataset_implementation_revision == IMPLEMENTATION_REVISION
    assert evidence.tokenizer_verifier_revision == TOKENIZER_VERIFIER_REVISION
    assert evidence.owner_acceptance_sha256 == OWNER_ACCEPTANCE_SHA256
    assert evidence.source_count == 8
    assert evidence.sample_count == 1_024
    assert evidence.total_byte_count == 112_467
    assert dict(evidence.fine_domain_counts) == FINE_DOMAIN_COUNTS
    assert dict(evidence.tokenizer_domain_counts) == TOKENIZER_DOMAIN_COUNTS
    assert evidence.exclusion_counts == (
        ("exact-duplicate", 0),
        ("unsafe-content", 0),
    )
    assert changed.dataset_manifest_sha256 == evidence.dataset_manifest_sha256
    assert changed.dataset_replay_sha256 == evidence.dataset_replay_sha256
    assert (
        changed.tokenizer_admission_manifest_sha256
        != evidence.tokenizer_admission_manifest_sha256
    )
    assert not hasattr(evidence, "content")


@pytest.mark.parametrize(
    "revision",
    ["bad", "1" * 39, "A" * 40, "g" * 40, None],
)
def test_projection_rejects_non_exact_implementation_revision(
    revision: object,
) -> None:
    with pytest.raises(
        FixtureBuildError, match="first-party snapshot evidence rejected"
    ):
        project_tokenizer_admission_manifest(
            build_first_party_snapshot().manifest,
            revision,  # type: ignore[arg-type]
        )


def test_projection_rejects_any_non_exact_snapshot() -> None:
    exact = build_first_party_snapshot().manifest
    changed = replace(
        exact,
        approved_purpose="A different purpose cannot reuse snapshot acceptance.",
        manifest_sha256="",
    ).with_computed_digest()
    with pytest.raises(
        FixtureBuildError, match="first-party snapshot evidence rejected"
    ):
        project_tokenizer_admission_manifest(changed, IMPLEMENTATION_REVISION)
