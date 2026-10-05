"""Deterministic first-party fixture generation and offline corpus replay."""

from __future__ import annotations

import re
from dataclasses import dataclass
from hashlib import sha256
from pathlib import PurePosixPath
from typing import Final

from cybersecgpt.datasets.corpus_manifest import (
    ExclusionRecord,
    SampleRecord,
    SnapshotManifest,
    SourceApprovalRecord,
    SourceKind,
    TransformationRecord,
)

MAX_GENERATORS: Final = 16
MAX_INCLUDED_SAMPLES: Final = 4_096
MAX_FIXTURE_BYTES: Final = 65_536
MAX_INCLUDED_BYTES: Final = 8_388_608
MAX_INPUT_FILES: Final = 1_024
MAX_INPUT_BYTES: Final = 8_388_608
MAX_PATH_DEPTH: Final = 8
MAX_PATH_BYTES: Final = 512
GENERATOR_SCHEMA_VERSION: Final = "csgpt-first-party-fixture-v1"
_ERROR: Final = "fixture construction rejected"
_ALLOWED_DOMAINS: Final = frozenset(
    {
        "assembly",
        "code",
        "dns",
        "firewall",
        "hash",
        "http",
        "iac",
        "ids",
        "json",
        "linux-log",
        "malware-analysis",
        "natural-language",
        "powershell",
        "shell",
        "siem-query",
        "sigma",
        "telemetry",
        "threat-intelligence",
        "url",
        "windows-log",
        "xml",
        "yaml",
        "yara",
    }
)
_REJECTED_MARKERS: Final = (
    b"-----begin private key-----",
    b"authorization: bearer ",
    b"aws_secret_access_key",
    b"confidential",
    b"ignore previous instructions",
    b"password=",
    b"powershell -enc ",
    b"prompt injection",
    b"secret=",
)
_EXECUTABLE_SIGNATURES: Final = (b"MZ", b"\x7fELF", b"#!")
_IPV4_PATTERN: Final = re.compile(rb"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])")
_DOCUMENTATION_IPV4_PREFIXES: Final = (b"192.0.2.", b"198.51.100.", b"203.0.113.")


class FixtureBuildError(ValueError):
    """Report a content-minimizing terminal construction failure."""


def _reject() -> FixtureBuildError:
    return FixtureBuildError(_ERROR)


def _digest(value: str) -> None:
    if len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise _reject()


def _identifier(value: str) -> None:
    try:
        encoded = value.encode("ascii", errors="strict")
    except UnicodeEncodeError as error:
        raise _reject() from error
    if (
        not encoded
        or len(encoded) > 256
        or any(character.isspace() for character in value)
    ):
        raise _reject()


@dataclass(frozen=True, slots=True)
class FixtureTemplate:
    """One reviewed, newly authored template stored as inert source text."""

    template_id: str
    domain: str
    text: str

    def __post_init__(self) -> None:
        _identifier(self.template_id)
        _identifier(self.domain)
        if self.domain not in _ALLOWED_DOMAINS or not self.text:
            raise _reject()
        try:
            encoded = self.text.encode("utf-8", errors="strict")
        except UnicodeEncodeError as error:
            raise _reject() from error
        if len(encoded) > MAX_FIXTURE_BYTES or "\x00" in self.text:
            raise _reject()


@dataclass(frozen=True, slots=True)
class FixtureGenerator:
    """Pinned pure generator definition without callbacks or dynamic loading."""

    generator_id: str
    source_id: str
    source_commit: str
    policy_sha256: str
    configuration_sha256: str
    input_provenance_sha256: str
    deterministic_seed: str
    templates: tuple[FixtureTemplate, ...]
    schema_version: str = GENERATOR_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for value in (
            self.generator_id,
            self.source_id,
            self.source_commit,
            self.deterministic_seed,
        ):
            _identifier(value)
        for value in (
            self.policy_sha256,
            self.configuration_sha256,
            self.input_provenance_sha256,
        ):
            _digest(value)
        if self.schema_version != GENERATOR_SCHEMA_VERSION:
            raise _reject()
        if (
            type(self.templates) is not tuple
            or not self.templates
            or any(type(item) is not FixtureTemplate for item in self.templates)
            or len({item.template_id for item in self.templates}) != len(self.templates)
        ):
            raise _reject()


@dataclass(frozen=True, slots=True)
class GeneratedFixture:
    """One generated fixture held in memory and excluded from distributions."""

    generator_id: str
    source_id: str
    template_id: str
    domain: str
    content: bytes
    content_sha256: str


@dataclass(frozen=True, slots=True)
class BuildRequest:
    """Explicit deterministic construction inputs and resource controls."""

    corpus_id: str
    approved_purpose: str
    distribution_limitations: str
    notices_sha256: str
    sources: tuple[SourceApprovalRecord, ...]
    generators: tuple[FixtureGenerator, ...]
    observed_tick: int
    deadline_tick: int
    cancelled: bool = False

    def __post_init__(self) -> None:
        _identifier(self.corpus_id)
        _digest(self.notices_sha256)
        if (
            type(self.sources) is not tuple
            or type(self.generators) is not tuple
            or any(type(value) is not SourceApprovalRecord for value in self.sources)
            or any(type(value) is not FixtureGenerator for value in self.generators)
            or not 1 <= len(self.generators) <= MAX_GENERATORS
            or type(self.observed_tick) is not int
            or type(self.deadline_tick) is not int
            or type(self.cancelled) is not bool
            or self.observed_tick < 0
            or self.deadline_tick < 0
        ):
            raise _reject()


@dataclass(frozen=True, slots=True)
class BuildResult:
    """Sealed manifest plus content-minimized deterministic replay identity."""

    manifest: SnapshotManifest
    replay_sha256: str


def generate_fixtures(generator: FixtureGenerator) -> tuple[GeneratedFixture, ...]:
    """Generate byte-identical ordered fixtures from reviewed local definitions."""

    fixtures = []
    for template in sorted(generator.templates, key=lambda item: item.template_id):
        content = (
            template.text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")
        )
        if not content.endswith(b"\n"):
            content += b"\n"
        fixtures.append(
            GeneratedFixture(
                generator_id=generator.generator_id,
                source_id=generator.source_id,
                template_id=template.template_id,
                domain=template.domain,
                content=content,
                content_sha256=sha256(content).hexdigest(),
            )
        )
    return tuple(fixtures)


def _validate_path(relative_path: str) -> None:
    encoded = relative_path.encode("ascii", errors="strict")
    path = PurePosixPath(relative_path)
    if (
        not encoded
        or len(encoded) > MAX_PATH_BYTES
        or path.is_absolute()
        or len(path.parts) > MAX_PATH_DEPTH
        or any(part in {"", ".", ".."} or ":" in part for part in path.parts)
        or path.suffix != ".txt"
    ):
        raise _reject()


def _safe_content(content: bytes) -> bool:
    lowered = content.lower()
    ipv4_values = _IPV4_PATTERN.findall(content)
    return not (
        any(
            lowered.startswith(signature.lower())
            for signature in _EXECUTABLE_SIGNATURES
        )
        or any(marker in lowered for marker in _REJECTED_MARKERS)
        or b"@" in content
        or any(
            not value.startswith(_DOCUMENTATION_IPV4_PREFIXES) for value in ipv4_values
        )
        or b"\x00" in content
    )


def _bind_source(
    generator: FixtureGenerator, sources: tuple[SourceApprovalRecord, ...]
) -> SourceApprovalRecord:
    matches = tuple(
        source for source in sources if source.source_id == generator.source_id
    )
    if len(matches) != 1:
        raise _reject()
    source = matches[0]
    if (
        source.source_kind is not SourceKind.FIRST_PARTY_GENERATED
        or not source.approved()
        or source.generator_commit != generator.source_commit
        or source.generator_policy_sha256 != generator.policy_sha256
        or source.generator_configuration_sha256 != generator.configuration_sha256
        or source.input_provenance_sha256 != generator.input_provenance_sha256
        or source.deterministic_seed != generator.deterministic_seed
    ):
        raise _reject()
    return source


def build_fixture_corpus(request: BuildRequest) -> BuildResult:
    """Build and seal a bounded corpus candidate without network or file execution."""

    if request.cancelled or request.observed_tick >= request.deadline_tick:
        raise _reject()
    if len({generator.generator_id for generator in request.generators}) != len(
        request.generators
    ):
        raise _reject()
    bound_sources = tuple(
        _bind_source(generator, request.sources)
        for generator in sorted(request.generators, key=lambda item: item.generator_id)
    )
    if len({source.source_id for source in bound_sources}) != len(bound_sources):
        raise _reject()

    included: list[GeneratedFixture] = []
    seen: set[str] = set()
    exclusions = {"exact-duplicate": 0, "unsafe-content": 0}
    input_count = 0
    input_bytes = 0
    for generator in sorted(request.generators, key=lambda item: item.generator_id):
        for fixture in generate_fixtures(generator):
            _validate_path(f"{fixture.generator_id}/{fixture.template_id}.txt")
            input_count += 1
            input_bytes += len(fixture.content)
            if input_count > MAX_INPUT_FILES or input_bytes > MAX_INPUT_BYTES:
                raise _reject()
            if not _safe_content(fixture.content):
                exclusions["unsafe-content"] += 1
                continue
            if fixture.content_sha256 in seen:
                exclusions["exact-duplicate"] += 1
                continue
            seen.add(fixture.content_sha256)
            included.append(fixture)

    included.sort(key=lambda item: (item.domain, item.source_id, item.template_id))
    # The stricter input-file and input-byte ceilings above also enforce the
    # included-sample and included-byte ceilings for this generator-only slice.
    if not included:
        raise _reject()
    samples = tuple(
        SampleRecord(
            sample_id=f"sample-{index:06d}",
            source_id=item.source_id,
            domain=item.domain,
            byte_count=len(item.content),
            content_sha256=item.content_sha256,
        )
        for index, item in enumerate(included, start=1)
    )
    configuration_digest = sha256(
        "".join(
            generator.configuration_sha256
            for generator in sorted(
                request.generators, key=lambda item: item.generator_id
            )
        ).encode("ascii")
    ).hexdigest()
    manifest = SnapshotManifest(
        corpus_id=request.corpus_id,
        approved_purpose=request.approved_purpose,
        distribution_limitations=request.distribution_limitations,
        ordering_rule="domain-source-template-ascii-v1",
        sampling_rule="all-safe-approved-first-party-fixtures-v1",
        deduplication_rule="exact-sha256-first-v1",
        normalization_rule="strict-utf8-lf-v1",
        notices_sha256=request.notices_sha256,
        sources=bound_sources,
        transformations=(
            TransformationRecord(
                "generate", "csgpt-fixture-generator", "1", configuration_digest
            ),
            TransformationRecord(
                "filter", "csgpt-offline-builder", "1", configuration_digest
            ),
            TransformationRecord(
                "deduplicate", "csgpt-offline-builder", "1", configuration_digest
            ),
        ),
        samples=samples,
        exclusions=tuple(
            ExclusionRecord(reason, count)
            for reason, count in sorted(exclusions.items())
        ),
    ).with_computed_digest()
    replay_sha256 = sha256(
        manifest.canonical_bytes() + bytes.fromhex(manifest.manifest_sha256)
    ).hexdigest()
    return BuildResult(manifest=manifest, replay_sha256=replay_sha256)


def verify_fixture_replay(request: BuildRequest, expected: BuildResult) -> bool:
    """Rebuild from pinned inputs and compare every content-minimized identity."""

    replayed = build_fixture_corpus(request)
    return replayed == expected
