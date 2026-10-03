"""Canonical, content-minimizing corpus snapshot manifest contracts."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import date
from enum import StrEnum
from hashlib import sha256
from struct import pack
from typing import Final

MANIFEST_SCHEMA_VERSION: Final = "csgpt-dataset-snapshot-v1"
MAX_SOURCES: Final = 1_024
MAX_TRANSFORMATIONS: Final = 128
MAX_SAMPLES: Final = 100_000
MAX_EXCLUSIONS: Final = 128
MAX_IDENTIFIER_BYTES: Final = 256
MAX_TEXT_BYTES: Final = 2_048
MAX_SAMPLE_BYTES: Final = 1_048_576
MAX_SNAPSHOT_BYTES: Final = 67_108_864
_DIGEST_LENGTH: Final = 64
_ERROR: Final = "invalid corpus snapshot manifest"


class ManifestValidationError(ValueError):
    """Report a content-minimizing manifest contract violation."""


class SourceKind(StrEnum):
    """Permitted provenance classes for the bounded pilot."""

    FIRST_PARTY_GENERATED = "first-party-generated"
    PUBLIC_DOMAIN = "public-domain"
    CC0 = "cc0"


class ReviewDecision(StrEnum):
    """Explicit review result; unknown and rejected states fail closed."""

    APPROVED = "approved"
    REJECTED = "rejected"
    UNKNOWN = "unknown"
    REVOKED = "revoked"


def _invalid() -> ManifestValidationError:
    return ManifestValidationError(_ERROR)


def _digest(value: str) -> bytes:
    if len(value) != _DIGEST_LENGTH or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise _invalid()
    return bytes.fromhex(value)


def _text(value: str, *, maximum: int = MAX_TEXT_BYTES) -> bytes:
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise _invalid() from error
    if not encoded or len(encoded) > maximum or "\x00" in value:
        raise _invalid()
    return pack("!I", len(encoded)) + encoded


def _identifier(value: str) -> bytes:
    encoded = _text(value, maximum=MAX_IDENTIFIER_BYTES)
    if not value.isascii() or any(character.isspace() for character in value):
        raise _invalid()
    return encoded


def _date(value: str) -> bytes:
    if (
        len(value) != 10
        or value[4] != "-"
        or value[7] != "-"
        or not (value[:4] + value[5:7] + value[8:]).isdigit()
    ):
        raise _invalid()
    try:
        parsed = date.fromisoformat(value)
    except ValueError as error:
        raise _invalid() from error
    if parsed.year < 2000:
        raise _invalid()
    return _text(value)


def _flag(value: bool) -> bytes:
    if type(value) is not bool:
        raise _invalid()
    return bytes((value,))


@dataclass(frozen=True, slots=True)
class SourceApprovalRecord:
    """A reviewed source decision without raw source content."""

    source_id: str
    source_kind: SourceKind
    canonical_origin: str
    acquisition_method: str
    acquired_at: str
    source_revision: str
    source_sha256: str
    rights_evidence_uri: str
    rights_evidence_sha256: str
    rights_basis: str
    jurisdiction: str
    limitations: str
    obligations_sha256: str
    restrictions_sha256: str
    reviewer_id: str
    reviewed_at: str
    rights_decision: ReviewDecision
    safety_decision: ReviewDecision
    contamination_decision: ReviewDecision
    acquisition_allowed: bool
    processing_allowed: bool
    tokenizer_training_allowed: bool
    derived_statistics_allowed: bool
    tokenizer_artifact_distribution_allowed: bool
    generator_commit: str = "none"
    generator_policy_sha256: str = "0" * 64
    generator_configuration_sha256: str = "0" * 64
    input_provenance_sha256: str = "0" * 64
    deterministic_seed: str = "none"

    def __post_init__(self) -> None:
        if type(self.source_kind) is not SourceKind or any(
            type(decision) is not ReviewDecision
            for decision in (
                self.rights_decision,
                self.safety_decision,
                self.contamination_decision,
            )
        ):
            raise _invalid()
        for value in (
            self.source_id,
            self.acquisition_method,
            self.source_revision,
            self.reviewer_id,
            self.generator_commit,
            self.deterministic_seed,
        ):
            _identifier(value)
        for value in (
            self.canonical_origin,
            self.rights_evidence_uri,
            self.rights_basis,
            self.jurisdiction,
            self.limitations,
        ):
            _text(value)
        _date(self.acquired_at)
        _date(self.reviewed_at)
        for value in (
            self.source_sha256,
            self.rights_evidence_sha256,
            self.obligations_sha256,
            self.restrictions_sha256,
            self.generator_policy_sha256,
            self.generator_configuration_sha256,
            self.input_provenance_sha256,
        ):
            _digest(value)
        for flag in (
            self.acquisition_allowed,
            self.processing_allowed,
            self.tokenizer_training_allowed,
            self.derived_statistics_allowed,
            self.tokenizer_artifact_distribution_allowed,
        ):
            _flag(flag)
        generated = self.source_kind is SourceKind.FIRST_PARTY_GENERATED
        has_generator = self.generator_commit != "none"
        if generated != has_generator:
            raise _invalid()
        generator_digests = (
            self.generator_policy_sha256,
            self.generator_configuration_sha256,
            self.input_provenance_sha256,
        )
        if generated and any(value == "0" * 64 for value in generator_digests):
            raise _invalid()
        if not generated and (
            any(value != "0" * 64 for value in generator_digests)
            or self.deterministic_seed != "none"
        ):
            raise _invalid()

    def approved(self) -> bool:
        """Return whether every independent review and purpose decision passed."""

        return (
            self.rights_decision is ReviewDecision.APPROVED
            and self.safety_decision is ReviewDecision.APPROVED
            and self.contamination_decision is ReviewDecision.APPROVED
            and self.acquisition_allowed
            and self.processing_allowed
            and self.tokenizer_training_allowed
            and self.derived_statistics_allowed
            and self.tokenizer_artifact_distribution_allowed
        )


@dataclass(frozen=True, slots=True)
class TransformationRecord:
    """One pinned deterministic transformation identity."""

    stage_id: str
    tool_id: str
    tool_revision: str
    configuration_sha256: str

    def __post_init__(self) -> None:
        _identifier(self.stage_id)
        _identifier(self.tool_id)
        _identifier(self.tool_revision)
        _digest(self.configuration_sha256)


@dataclass(frozen=True, slots=True)
class SampleRecord:
    """One ordered sample identity without raw content."""

    sample_id: str
    source_id: str
    domain: str
    byte_count: int
    content_sha256: str

    def __post_init__(self) -> None:
        _identifier(self.sample_id)
        _identifier(self.source_id)
        _identifier(self.domain)
        if (
            type(self.byte_count) is not int
            or not 0 <= self.byte_count <= MAX_SAMPLE_BYTES
        ):
            raise _invalid()
        _digest(self.content_sha256)


@dataclass(frozen=True, slots=True)
class ExclusionRecord:
    """A content-minimized exclusion reason and count."""

    reason_id: str
    count: int

    def __post_init__(self) -> None:
        _identifier(self.reason_id)
        if type(self.count) is not int or not 0 <= self.count <= MAX_SAMPLES:
            raise _invalid()


@dataclass(frozen=True, slots=True)
class SnapshotManifest:
    """A sealed exact snapshot identity using canonical length-prefixed bytes."""

    corpus_id: str
    approved_purpose: str
    distribution_limitations: str
    ordering_rule: str
    sampling_rule: str
    deduplication_rule: str
    normalization_rule: str
    notices_sha256: str
    sources: tuple[SourceApprovalRecord, ...]
    transformations: tuple[TransformationRecord, ...]
    samples: tuple[SampleRecord, ...]
    exclusions: tuple[ExclusionRecord, ...]
    schema_version: str = MANIFEST_SCHEMA_VERSION
    strict_utf8: bool = True
    canonical_newlines: bool = True
    manifest_sha256: str = ""

    def __post_init__(self) -> None:
        _identifier(self.corpus_id)
        if self.schema_version != MANIFEST_SCHEMA_VERSION:
            raise _invalid()
        for value in (
            self.approved_purpose,
            self.distribution_limitations,
            self.ordering_rule,
            self.sampling_rule,
            self.deduplication_rule,
            self.normalization_rule,
        ):
            _text(value)
        _digest(self.notices_sha256)
        _flag(self.strict_utf8)
        _flag(self.canonical_newlines)
        if not self.strict_utf8 or not self.canonical_newlines:
            raise _invalid()
        if (
            type(self.sources) is not tuple
            or type(self.transformations) is not tuple
            or type(self.samples) is not tuple
            or type(self.exclusions) is not tuple
            or any(type(value) is not SourceApprovalRecord for value in self.sources)
            or any(
                type(value) is not TransformationRecord
                for value in self.transformations
            )
            or any(type(value) is not SampleRecord for value in self.samples)
            or any(type(value) is not ExclusionRecord for value in self.exclusions)
        ):
            raise _invalid()
        if not 1 <= len(self.sources) <= MAX_SOURCES:
            raise _invalid()
        if not 1 <= len(self.transformations) <= MAX_TRANSFORMATIONS:
            raise _invalid()
        if not 1 <= len(self.samples) <= MAX_SAMPLES:
            raise _invalid()
        if len(self.exclusions) > MAX_EXCLUSIONS:
            raise _invalid()
        source_ids = tuple(source.source_id for source in self.sources)
        sample_ids = tuple(sample.sample_id for sample in self.samples)
        sample_digests = tuple(sample.content_sha256 for sample in self.samples)
        stage_ids = tuple(stage.stage_id for stage in self.transformations)
        exclusion_ids = tuple(exclusion.reason_id for exclusion in self.exclusions)
        if any(
            len(values) != len(set(values))
            for values in (
                source_ids,
                sample_ids,
                sample_digests,
                stage_ids,
                exclusion_ids,
            )
        ):
            raise _invalid()
        if any(not source.approved() for source in self.sources):
            raise _invalid()
        if any(sample.source_id not in source_ids for sample in self.samples):
            raise _invalid()
        if sum(sample.byte_count for sample in self.samples) > MAX_SNAPSHOT_BYTES:
            raise _invalid()
        if self.manifest_sha256:
            _digest(self.manifest_sha256)
            if self.manifest_sha256 != sha256(self.canonical_bytes()).hexdigest():
                raise _invalid()

    def canonical_bytes(self) -> bytes:
        """Return deterministic bytes excluding the self-referential digest."""

        parts = [
            _text("CSGPT-DATASET-SNAPSHOT"),
            _identifier(self.schema_version),
            _identifier(self.corpus_id),
            _text(self.approved_purpose),
            _text(self.distribution_limitations),
            _text(self.ordering_rule),
            _text(self.sampling_rule),
            _text(self.deduplication_rule),
            _text(self.normalization_rule),
            _digest(self.notices_sha256),
            _flag(self.strict_utf8),
            _flag(self.canonical_newlines),
            pack("!I", len(self.sources)),
        ]
        for source in self.sources:
            parts.extend(
                (
                    _identifier(source.source_id),
                    _identifier(source.source_kind.value),
                    _text(source.canonical_origin),
                    _identifier(source.acquisition_method),
                    _date(source.acquired_at),
                    _identifier(source.source_revision),
                    _digest(source.source_sha256),
                    _text(source.rights_evidence_uri),
                    _digest(source.rights_evidence_sha256),
                    _text(source.rights_basis),
                    _text(source.jurisdiction),
                    _text(source.limitations),
                    _digest(source.obligations_sha256),
                    _digest(source.restrictions_sha256),
                    _identifier(source.reviewer_id),
                    _date(source.reviewed_at),
                    _identifier(source.rights_decision.value),
                    _identifier(source.safety_decision.value),
                    _identifier(source.contamination_decision.value),
                    _flag(source.acquisition_allowed),
                    _flag(source.processing_allowed),
                    _flag(source.tokenizer_training_allowed),
                    _flag(source.derived_statistics_allowed),
                    _flag(source.tokenizer_artifact_distribution_allowed),
                    _identifier(source.generator_commit),
                    _digest(source.generator_policy_sha256),
                    _digest(source.generator_configuration_sha256),
                    _digest(source.input_provenance_sha256),
                    _identifier(source.deterministic_seed),
                )
            )
        parts.append(pack("!I", len(self.transformations)))
        for transformation in self.transformations:
            parts.extend(
                (
                    _identifier(transformation.stage_id),
                    _identifier(transformation.tool_id),
                    _identifier(transformation.tool_revision),
                    _digest(transformation.configuration_sha256),
                )
            )
        parts.append(pack("!I", len(self.samples)))
        for sample in self.samples:
            parts.extend(
                (
                    _identifier(sample.sample_id),
                    _identifier(sample.source_id),
                    _identifier(sample.domain),
                    pack("!Q", sample.byte_count),
                    _digest(sample.content_sha256),
                )
            )
        parts.append(pack("!I", len(self.exclusions)))
        for exclusion in self.exclusions:
            parts.extend(
                (_identifier(exclusion.reason_id), pack("!Q", exclusion.count))
            )
        return b"".join(parts)

    def with_computed_digest(self) -> SnapshotManifest:
        """Return an immutable sealed manifest."""

        if self.manifest_sha256:
            return self
        return replace(self, manifest_sha256=sha256(self.canonical_bytes()).hexdigest())
