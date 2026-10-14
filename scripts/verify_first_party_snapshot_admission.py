"""Verify the exact first-party snapshot with the pinned tokenizer checkout."""

import json
import socket
from dataclasses import asdict
from importlib import import_module
from typing import NoReturn

from cybersecgpt.datasets import (
    ACCEPTED_GENERATOR_SOURCE_REVISION,
    TOKENIZER_VERIFIER_REVISION,
    build_first_party_snapshot,
    first_party_generators,
    first_party_snapshot_evidence,
    generate_fixtures,
    project_tokenizer_admission_manifest,
)

DATASET_IMPLEMENTATION_REVISION = "cfda1cea94e0501a2b9c67491d47e04294ce35d8"
_ERROR = "first-party snapshot admission verification failed"


class SnapshotAdmissionVerificationError(RuntimeError):
    """Report a content-minimizing cross-repository verification failure."""


def _require(condition: bool) -> None:
    if not condition:
        raise SnapshotAdmissionVerificationError(_ERROR)


def _blocked_socket(*args: object, **kwargs: object) -> NoReturn:
    raise SnapshotAdmissionVerificationError(_ERROR)


def main() -> None:
    original_socket = socket.socket
    socket.socket = _blocked_socket  # type: ignore[assignment,misc]
    try:
        corpus_contract = import_module("cybersecgpt.tokenizer.corpus_manifest")
        evaluation = import_module("cybersecgpt.tokenizer.evaluation")
        snapshot = build_first_party_snapshot()
        projection = project_tokenizer_admission_manifest(
            snapshot.manifest, DATASET_IMPLEMENTATION_REVISION
        )
        tokenizer_manifest = corpus_contract.CorpusAdmissionManifest(
            corpus_id=projection.corpus_id,
            schema_version=projection.schema_version,
            approved_purpose=projection.approved_purpose,
            artifact_distribution_terms=projection.artifact_distribution_terms,
            sources=tuple(
                corpus_contract.CorpusSourceRecord(
                    source_id=source.source_id,
                    origin_ref=source.origin_ref,
                    acquisition_method=source.acquisition_method,
                    acquired_at=source.acquired_at,
                    source_revision=source.source_revision,
                    source_sha256=source.source_sha256,
                    license_expression=source.license_expression,
                    obligations_sha256=source.obligations_sha256,
                    reviewer_id=source.reviewer_id,
                    reviewed_at=source.reviewed_at,
                    rights_decision=corpus_contract.RightsDecision(
                        source.rights_decision
                    ),
                    sensitive_data_decision=corpus_contract.SafetyDecision(
                        source.sensitive_data_decision
                    ),
                    contamination_decision=corpus_contract.SafetyDecision(
                        source.contamination_decision
                    ),
                    acquisition_allowed=source.acquisition_allowed,
                    processing_allowed=source.processing_allowed,
                    training_allowed=source.training_allowed,
                    derived_statistics_allowed=source.derived_statistics_allowed,
                    artifact_distribution_allowed=(
                        source.artifact_distribution_allowed
                    ),
                )
                for source in projection.sources
            ),
            transformations=tuple(
                corpus_contract.CorpusTransformation(
                    stage.stage_id,
                    stage.tool_id,
                    stage.configuration_sha256,
                )
                for stage in projection.transformations
            ),
            samples=tuple(
                corpus_contract.CorpusSampleRecord(
                    sample.sample_id,
                    sample.source_id,
                    evaluation.EvaluationDomain(sample.domain),
                    sample.byte_count,
                    sample.content_sha256,
                )
                for sample in projection.samples
            ),
            exclusion_counts=projection.exclusion_counts,
            manifest_sha256=projection.manifest_sha256,
        )
        fixtures = tuple(
            sorted(
                (
                    fixture
                    for generator in first_party_generators(
                        ACCEPTED_GENERATOR_SOURCE_REVISION
                    )
                    for fixture in generate_fixtures(generator)
                ),
                key=lambda item: (item.domain, item.source_id, item.template_id),
            )
        )
        _require(len(fixtures) == len(projection.samples))
        supplied = tuple(
            corpus_contract.CorpusSampleContent(sample.sample_id, fixture.content)
            for sample, fixture in zip(projection.samples, fixtures, strict=True)
        )
        _require(tokenizer_manifest.canonical_bytes() == projection.canonical_bytes())
        result = corpus_contract.admit_corpus(
            tokenizer_manifest,
            supplied,
            deadline_ns=2,
            now_ns=1,
        )
        evidence = first_party_snapshot_evidence(DATASET_IMPLEMENTATION_REVISION)
        _require(
            result.corpus_id == projection.corpus_id
            and result.manifest_sha256 == projection.manifest_sha256
            and result.sample_count == evidence.sample_count
            and result.total_bytes == evidence.total_byte_count
            and result.source_ids
            == tuple(source.source_id for source in projection.sources)
            and result.sample_digests
            == tuple(sample.content_sha256 for sample in projection.samples)
            and tuple(sorted(domain.value for domain in result.domains))
            == tuple(domain for domain, _ in evidence.tokenizer_domain_counts)
        )
    finally:
        socket.socket = original_socket  # type: ignore[misc]

    report = asdict(evidence)
    report["tokenizer_admission_verified"] = True
    report["network_enabled_during_construction"] = False
    report["tokenizer_verifier_revision"] = TOKENIZER_VERIFIER_REVISION
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
