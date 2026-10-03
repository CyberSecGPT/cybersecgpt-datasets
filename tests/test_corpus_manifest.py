"""Verify bounded deterministic corpus manifest contracts."""

from collections.abc import Callable
from dataclasses import replace
from hashlib import sha256
from typing import Any

import pytest

from cybersecgpt.datasets.corpus_manifest import (
    ExclusionRecord,
    ManifestValidationError,
    ReviewDecision,
    SampleRecord,
    SnapshotManifest,
    SourceApprovalRecord,
    SourceKind,
    TransformationRecord,
)

ZERO = "0" * 64
ONE = "1" * 64
TWO = "2" * 64
THREE = "3" * 64


def source(**changes: Any) -> SourceApprovalRecord:
    values: dict[str, Any] = {
        "source_id": "fixture-source",
        "source_kind": SourceKind.FIRST_PARTY_GENERATED,
        "canonical_origin": "repository:generators/fixture.py",
        "acquisition_method": "deterministic-generator",
        "acquired_at": "2026-10-03",
        "source_revision": "0123456789abcdef",
        "source_sha256": ZERO,
        "rights_evidence_uri": "repository:docs/rights/fixture.md",
        "rights_evidence_sha256": ONE,
        "rights_basis": "CC0-1.0",
        "jurisdiction": "worldwide",
        "limitations": "pilot-only",
        "obligations_sha256": ZERO,
        "restrictions_sha256": ZERO,
        "reviewer_id": "project-owner",
        "reviewed_at": "2026-10-03",
        "rights_decision": ReviewDecision.APPROVED,
        "safety_decision": ReviewDecision.APPROVED,
        "contamination_decision": ReviewDecision.APPROVED,
        "acquisition_allowed": True,
        "processing_allowed": True,
        "tokenizer_training_allowed": True,
        "derived_statistics_allowed": True,
        "tokenizer_artifact_distribution_allowed": True,
        "generator_commit": "0123456789abcdef",
        "generator_policy_sha256": ONE,
        "generator_configuration_sha256": TWO,
        "input_provenance_sha256": THREE,
        "deterministic_seed": "seed-1",
    }
    values.update(changes)
    return SourceApprovalRecord(**values)


def manifest(**changes: Any) -> SnapshotManifest:
    content = b"safe fixture\n"
    values: dict[str, Any] = {
        "corpus_id": "p6-pilot-1",
        "approved_purpose": "Tokenizer v1 bounded pilot evaluation.",
        "distribution_limitations": "Manifest only; raw bytes remain external.",
        "ordering_rule": "sample-id-ascii-ascending-v1",
        "sampling_rule": "all-approved-samples-v1",
        "deduplication_rule": "exact-sha256-first-v1",
        "normalization_rule": "strict-utf8-lf-v1",
        "notices_sha256": ZERO,
        "sources": (source(),),
        "transformations": (TransformationRecord("decode", "csgpt-builder", "1", ONE),),
        "samples": (
            SampleRecord(
                "sample-1",
                "fixture-source",
                "natural-language",
                len(content),
                sha256(content).hexdigest(),
            ),
        ),
        "exclusions": (ExclusionRecord("exact-duplicate", 0),),
    }
    values.update(changes)
    return SnapshotManifest(**values)


def test_manifest_replay_and_identity_sensitivity() -> None:
    unsealed = manifest()
    sealed = unsealed.with_computed_digest()
    assert sealed.manifest_sha256 == sha256(unsealed.canonical_bytes()).hexdigest()
    assert sealed.with_computed_digest() is sealed
    assert sealed.canonical_bytes() == unsealed.canonical_bytes()
    changed = manifest(approved_purpose="A different approved purpose.")
    assert changed.with_computed_digest().manifest_sha256 != sealed.manifest_sha256
    assert sealed.sources[0].approved()


@pytest.mark.parametrize(
    "changes",
    [
        {"rights_decision": ReviewDecision.REJECTED},
        {"safety_decision": ReviewDecision.UNKNOWN},
        {"contamination_decision": ReviewDecision.REVOKED},
        {"acquisition_allowed": False},
        {"processing_allowed": False},
        {"tokenizer_training_allowed": False},
        {"derived_statistics_allowed": False},
        {"tokenizer_artifact_distribution_allowed": False},
    ],
)
def test_source_approval_requires_every_decision(changes: dict[str, object]) -> None:
    assert not source(**changes).approved()


@pytest.mark.parametrize(
    ("factory", "changes"),
    [
        (source, {"source_id": "has space"}),
        (source, {"canonical_origin": ""}),
        (source, {"reviewed_at": "1999-01-01"}),
        (source, {"reviewed_at": "2026/10/03"}),
        (source, {"acquired_at": "2026-13-01"}),
        (source, {"acquired_at": "2026-01-32"}),
        (source, {"acquired_at": "2026-02-31"}),
        (source, {"source_sha256": "A" * 64}),
        (source, {"source_id": "x" * 257}),
        (source, {"canonical_origin": "x" * 2049}),
        (source, {"canonical_origin": "bad\x00origin"}),
        (source, {"canonical_origin": "\ud800"}),
        (source, {"acquisition_allowed": 1}),
        (source, {"source_kind": "first-party-generated"}),
        (source, {"rights_decision": "approved"}),
        (source, {"generator_commit": "none"}),
        (source, {"generator_policy_sha256": ZERO}),
        (source, {"source_kind": SourceKind.CC0, "generator_commit": "unexpected"}),
        (
            source,
            {
                "source_kind": SourceKind.CC0,
                "generator_commit": "none",
                "generator_policy_sha256": ONE,
            },
        ),
        (
            source,
            {
                "source_kind": SourceKind.CC0,
                "generator_commit": "none",
                "generator_policy_sha256": ZERO,
                "generator_configuration_sha256": ZERO,
                "input_provenance_sha256": ZERO,
                "deterministic_seed": "unexpected",
            },
        ),
    ],
)
def test_source_rejects_malformed_values(
    factory: Callable[..., object], changes: dict[str, object]
) -> None:
    with pytest.raises(ManifestValidationError, match="invalid corpus snapshot"):
        factory(**changes)


def test_non_generated_source_without_generator_is_valid() -> None:
    record = source(
        source_kind=SourceKind.PUBLIC_DOMAIN,
        generator_commit="none",
        generator_policy_sha256=ZERO,
        generator_configuration_sha256=ZERO,
        input_provenance_sha256=ZERO,
        deterministic_seed="none",
    )
    assert record.source_kind is SourceKind.PUBLIC_DOMAIN


@pytest.mark.parametrize(
    "operation",
    [
        lambda: TransformationRecord("bad stage", "tool", "1", ZERO),
        lambda: TransformationRecord("stage", "tool", "1", "bad"),
        lambda: SampleRecord("sample", "source", "domain", -1, ZERO),
        lambda: SampleRecord("sample", "source", "domain", 1_048_577, ZERO),
        lambda: SampleRecord("sample", "source", "bad domain", 1, ZERO),
        lambda: ExclusionRecord("reason", -1),
        lambda: ExclusionRecord("reason", 100_001),
    ],
)
def test_component_bounds_fail_closed(operation: Callable[[], object]) -> None:
    with pytest.raises(ManifestValidationError, match="invalid corpus snapshot"):
        operation()


@pytest.mark.parametrize(
    "changes",
    [
        {"schema_version": "unsupported"},
        {"strict_utf8": False},
        {"canonical_newlines": False},
        {"sources": ()},
        {"transformations": ()},
        {"samples": ()},
        {"sources": [source()]},
        {
            "exclusions": tuple(
                ExclusionRecord(f"reason-{index}", 0) for index in range(129)
            )
        },
        {"sources": (source(), source())},
        {
            "samples": (
                SampleRecord("sample-1", "fixture-source", "domain", 1, ONE),
                SampleRecord("sample-1", "fixture-source", "domain", 1, TWO),
            )
        },
        {
            "samples": (
                SampleRecord("sample-1", "fixture-source", "domain", 1, ONE),
                SampleRecord("sample-2", "fixture-source", "domain", 1, ONE),
            )
        },
        {
            "transformations": (
                TransformationRecord("same", "tool", "1", ZERO),
                TransformationRecord("same", "tool", "2", ONE),
            )
        },
        {"exclusions": (ExclusionRecord("same", 1), ExclusionRecord("same", 2))},
        {"samples": (SampleRecord("sample", "unknown", "domain", 1, ZERO),)},
        {"sources": (source(rights_decision=ReviewDecision.UNKNOWN),)},
        {
            "samples": tuple(
                SampleRecord(
                    f"sample-{index}",
                    "fixture-source",
                    "domain",
                    1_048_576,
                    f"{index:064x}",
                )
                for index in range(65)
            )
        },
    ],
)
def test_manifest_rejects_invalid_structure(changes: dict[str, object]) -> None:
    with pytest.raises(ManifestValidationError, match="invalid corpus snapshot"):
        manifest(**changes)


def test_sealed_manifest_detects_mutation_and_bad_digest() -> None:
    sealed = manifest().with_computed_digest()
    with pytest.raises(ManifestValidationError, match="invalid corpus snapshot"):
        replace(sealed, approved_purpose="changed")
    with pytest.raises(ManifestValidationError, match="invalid corpus snapshot"):
        replace(manifest(), manifest_sha256="f" * 64)
