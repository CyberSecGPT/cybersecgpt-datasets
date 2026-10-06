"""Exact first-party Tokenizer v1 pilot generator-source proposal."""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from hashlib import sha256
from struct import pack
from typing import Final

from cybersecgpt.datasets.fixture_builder import (
    FixtureBuildError,
    FixtureGenerator,
    FixtureTemplate,
    GeneratedFixture,
    _safe_content,
    generate_fixtures,
)

FIRST_PARTY_GENERATOR_PROFILE_VERSION: Final = "csgpt-first-party-tokenizer-pilot-v1"
FIRST_PARTY_REVIEW_EVIDENCE_SCHEMA_VERSION: Final = (
    "csgpt-first-party-generator-review-v1"
)
FIRST_PARTY_LICENSE_EXPRESSION: Final = (
    "LicenseRef-CyberSecGPT-First-Party-Tokenizer-v1"
)
FIRST_PARTY_GENERATOR_COUNT: Final = 8
FIRST_PARTY_SAMPLE_COUNT: Final = 1_024
_SOURCE_ORIGIN: Final = "repository:src/cybersecgpt/datasets/first_party_generators.py"
_GIT_REVISION: Final = re.compile(r"[0-9a-f]{40}")
_POLICY_RULES: Final = (
    "source-class:newly-authored-first-party-only",
    "external-input:none",
    "network:forbidden",
    "clock-and-host-input:forbidden",
    "randomness:none",
    "normalization:strict-utf8-lf-v1",
    "ordering:template-id-ascii-v1",
    "sample-count:128-per-generator",
    "content:fictional-inert-defensive-only",
    "targets:reserved-documentation-only",
    "persistent-raw-output:forbidden",
)


def _frame(value: str) -> bytes:
    encoded = value.encode("utf-8", errors="strict")
    return pack("!I", len(encoded)) + encoded


def _digest(*values: str) -> str:
    return sha256(b"".join(_frame(value) for value in values)).hexdigest()


FIRST_PARTY_POLICY_SHA256: Final = _digest(
    "csgpt-first-party-generator-policy-v1", *_POLICY_RULES
)


@dataclass(frozen=True, slots=True)
class _GeneratorDefinition:
    generator_id: str
    source_id: str
    templates: tuple[FixtureTemplate, ...]


@dataclass(frozen=True, slots=True)
class FirstPartyGeneratorRecord:
    """Content-minimized technical evidence for one unapproved generator."""

    generator_id: str
    source_id: str
    configuration_sha256: str
    input_provenance_sha256: str
    sample_count: int
    total_byte_count: int
    domain_counts: tuple[tuple[str, int], ...]
    output_identity_sha256: str


@dataclass(frozen=True, slots=True)
class FirstPartyGeneratorEvidence:
    """Technical evidence that cannot grant rights or snapshot admission."""

    schema_version: str
    profile_version: str
    source_revision: str
    source_origin: str
    policy_sha256: str
    generator_count: int
    sample_count: int
    total_byte_count: int
    unsafe_sample_count: int
    duplicate_sample_count: int
    output_identity_sha256: str
    generators: tuple[FirstPartyGeneratorRecord, ...]


def _natural_language_templates() -> tuple[FixtureTemplate, ...]:
    return tuple(
        FixtureTemplate(
            f"natural-language-{index:03d}",
            "natural-language",
            (
                f"Synthetic defensive review {index:03d}: the isolated exercise "
                "contains a fictional observation that requires calm validation "
                "before a benign conclusion is documented."
            ),
        )
        for index in range(1, 129)
    )


def _code_templates() -> tuple[FixtureTemplate, ...]:
    code = tuple(
        FixtureTemplate(
            f"code-{index:03d}",
            "code",
            (
                f"def inspect_fixture_{index:03d}(record):\n"
                f'    return record.get("synthetic_state_{index:03d}", "review")'
            ),
        )
        for index in range(1, 33)
    )
    powershell = tuple(
        FixtureTemplate(
            f"powershell-{index:03d}",
            "powershell",
            (
                f"function Test-SyntheticRecord{index:03d} {{\n"
                "    param([string]$State)\n"
                f'    if ($State -eq "simulated-{index:03d}") {{ "review" }}\n'
                "}"
            ),
        )
        for index in range(1, 33)
    )
    shell = tuple(
        FixtureTemplate(
            f"shell-{index:03d}",
            "shell",
            (
                'case "$synthetic_state" in\n'
                f'  simulated-{index:03d}) printf "%s\\n" "review-{index:03d}" ;;\n'
                '  *) printf "%s\\n" "unknown" ;;\n'
                "esac"
            ),
        )
        for index in range(1, 33)
    )
    assembly = tuple(
        FixtureTemplate(
            f"assembly-{index:03d}",
            "assembly",
            (
                f"fixture_{index:03d}: MOV R0, {index}\n"
                f"CMP R0, {index}\n"
                f"BEQ reviewed_{index:03d}"
            ),
        )
        for index in range(1, 33)
    )
    return code + powershell + shell + assembly


def _log_templates() -> tuple[FixtureTemplate, ...]:
    windows = tuple(
        FixtureTemplate(
            f"windows-log-{index:03d}",
            "windows-log",
            (
                "2026-01-01T00:00:00Z "
                f"host=WIN-FIXTURE-{index:03d} event_id={4_000 + index} "
                f"source=192.0.2.{index} action=review status=simulated"
            ),
        )
        for index in range(1, 65)
    )
    linux = tuple(
        FixtureTemplate(
            f"linux-log-{index:03d}",
            "linux-log",
            (
                "2026-01-01T00:00:00Z "
                f"node=linux-fixture-{index:03d} facility=local{index % 8} "
                f"source=198.51.100.{index} result=simulated-review"
            ),
        )
        for index in range(1, 65)
    )
    return windows + linux


def _structured_data_templates() -> tuple[FixtureTemplate, ...]:
    json = tuple(
        FixtureTemplate(
            f"json-{index:03d}",
            "json",
            (
                f'{{"fixture_id":"json-{index:03d}","state":"simulated",'
                '"review_required":true}'
            ),
        )
        for index in range(1, 33)
    )
    yaml = tuple(
        FixtureTemplate(
            f"yaml-{index:03d}",
            "yaml",
            (
                f"fixture_id: yaml-{index:03d}\n"
                "state: simulated\n"
                "review_required: true"
            ),
        )
        for index in range(1, 33)
    )
    xml = tuple(
        FixtureTemplate(
            f"xml-{index:03d}",
            "xml",
            (
                f'<fixture id="xml-{index:03d}"><state>simulated</state>'
                "<review>true</review></fixture>"
            ),
        )
        for index in range(1, 33)
    )
    iac = tuple(
        FixtureTemplate(
            f"iac-{index:03d}",
            "iac",
            (
                f'resource "example_fixture" "item_{index:03d}" {{\n'
                f'  label = "simulated-{index:03d}"\n'
                "  enabled = false\n"
                "}"
            ),
        )
        for index in range(1, 33)
    )
    return json + yaml + xml + iac


def _network_templates() -> tuple[FixtureTemplate, ...]:
    http = tuple(
        FixtureTemplate(
            f"http-{index:03d}",
            "http",
            (
                f"GET /fixtures/{index:03d} HTTP/1.1\n"
                f"Host: service-{index:03d}.example.test\n"
                "X-Fixture-State: simulated"
            ),
        )
        for index in range(1, 33)
    )
    dns = tuple(
        FixtureTemplate(
            f"dns-{index:03d}",
            "dns",
            (
                f"query=fixture-{index:03d}.example.test type=TXT "
                f"response=synthetic-{index:03d}"
            ),
        )
        for index in range(1, 33)
    )
    url = tuple(
        FixtureTemplate(
            f"url-{index:03d}",
            "url",
            (
                f"https://fixture-{index:03d}.example.test/review"
                f"?case={index:03d}&state=simulated"
            ),
        )
        for index in range(1, 33)
    )
    telemetry = tuple(
        FixtureTemplate(
            f"telemetry-{index:03d}",
            "telemetry",
            (
                f"flow_id=fixture-{index:03d} src=203.0.113.{index} "
                f"dst=198.51.100.{index} protocol=tcp disposition=observed"
            ),
        )
        for index in range(1, 33)
    )
    return http + dns + url + telemetry


def _synthetic_hash(index: int) -> str:
    value = f"csgpt-hash-fixture-v1:{index:03d}".encode()
    return sha256(value).hexdigest()


def _security_identifier_templates() -> tuple[FixtureTemplate, ...]:
    return tuple(
        FixtureTemplate(
            f"hash-{index:03d}",
            "hash",
            (
                "hash_type=sha256 "
                f"digest={_synthetic_hash(index)} "
                f"label=synthetic-{index:03d}"
            ),
        )
        for index in range(1, 129)
    )


def _detection_rule_templates() -> tuple[FixtureTemplate, ...]:
    sigma = tuple(
        FixtureTemplate(
            f"sigma-{index:03d}",
            "sigma",
            (
                f"title: Synthetic Review {index:03d}\n"
                f"id: 00000000-0000-4000-8000-{index:012d}\n"
                "status: test\n"
                "detection:\n"
                "  selection:\n"
                f"    event_category: synthetic-{index:03d}\n"
                "  condition: selection"
            ),
        )
        for index in range(1, 27)
    )
    yara = tuple(
        FixtureTemplate(
            f"yara-{index:03d}",
            "yara",
            (
                f"rule Synthetic_Fixture_{index:03d} {{\n"
                "  strings:\n"
                f'    $marker = "fixture-{index:03d}"\n'
                "  condition:\n"
                "    $marker\n"
                "}"
            ),
        )
        for index in range(1, 27)
    )
    firewall = tuple(
        FixtureTemplate(
            f"firewall-{index:03d}",
            "firewall",
            (
                f"fixture-rule-{index:03d} action=deny "
                f"src=192.0.2.{index}/32 dst=198.51.100.{index}/32 "
                f"service=test-{index:03d}"
            ),
        )
        for index in range(1, 27)
    )
    ids = tuple(
        FixtureTemplate(
            f"ids-{index:03d}",
            "ids",
            (
                f"alert tcp 192.0.2.{index} any -> 198.51.100.{index} 9 "
                f'(msg:"Synthetic fixture {index:03d}"; '
                f"sid:{9_000_000 + index}; rev:1;)"
            ),
        )
        for index in range(1, 26)
    )
    siem_query = tuple(
        FixtureTemplate(
            f"siem-query-{index:03d}",
            "siem-query",
            (
                f'dataset=synthetic_events event_code="fixture-{index:03d}" '
                "| stats count by review_state"
            ),
        )
        for index in range(1, 26)
    )
    return sigma + yara + firewall + ids + siem_query


def _security_prose_templates() -> tuple[FixtureTemplate, ...]:
    threat_intelligence = tuple(
        FixtureTemplate(
            f"threat-intelligence-{index:03d}",
            "threat-intelligence",
            (
                f"Synthetic threat-intelligence note {index:03d}: a fictional "
                "cluster produced a benign indicator pattern inside an isolated "
                "exercise. No live target or action is identified."
            ),
        )
        for index in range(1, 65)
    )
    malware_analysis = tuple(
        FixtureTemplate(
            f"malware-analysis-{index:03d}",
            "malware-analysis",
            (
                f"Synthetic malware-analysis description {index:03d}: an inert "
                "byte sequence was classified only for tokenizer evaluation; no "
                "executable behavior or delivery path exists."
            ),
        )
        for index in range(1, 65)
    )
    return threat_intelligence + malware_analysis


_DEFINITIONS: Final = (
    _GeneratorDefinition(
        "csgpt-p6-natural-language-v1",
        "csgpt-first-party-natural-language-v1",
        _natural_language_templates(),
    ),
    _GeneratorDefinition(
        "csgpt-p6-code-v1",
        "csgpt-first-party-code-v1",
        _code_templates(),
    ),
    _GeneratorDefinition(
        "csgpt-p6-logs-v1",
        "csgpt-first-party-logs-v1",
        _log_templates(),
    ),
    _GeneratorDefinition(
        "csgpt-p6-structured-data-v1",
        "csgpt-first-party-structured-data-v1",
        _structured_data_templates(),
    ),
    _GeneratorDefinition(
        "csgpt-p6-network-v1",
        "csgpt-first-party-network-v1",
        _network_templates(),
    ),
    _GeneratorDefinition(
        "csgpt-p6-security-identifiers-v1",
        "csgpt-first-party-security-identifiers-v1",
        _security_identifier_templates(),
    ),
    _GeneratorDefinition(
        "csgpt-p6-detection-rules-v1",
        "csgpt-first-party-detection-rules-v1",
        _detection_rule_templates(),
    ),
    _GeneratorDefinition(
        "csgpt-p6-security-prose-v1",
        "csgpt-first-party-security-prose-v1",
        _security_prose_templates(),
    ),
)


def _configuration_sha256(definition: _GeneratorDefinition) -> str:
    values = tuple(
        value
        for template in definition.templates
        for value in (template.template_id, template.domain, template.text)
    )
    return _digest(
        "csgpt-first-party-generator-configuration-v1",
        FIRST_PARTY_GENERATOR_PROFILE_VERSION,
        FIRST_PARTY_POLICY_SHA256,
        definition.generator_id,
        definition.source_id,
        *values,
    )


def _input_provenance_sha256(definition: _GeneratorDefinition) -> str:
    return _digest(
        "csgpt-first-party-input-provenance-v1",
        definition.generator_id,
        definition.source_id,
        _SOURCE_ORIGIN,
        "newly-authored-static-generator-source",
        "external-input:none",
        "deterministic-seed:none",
        FIRST_PARTY_LICENSE_EXPRESSION,
    )


def first_party_generators(source_revision: str) -> tuple[FixtureGenerator, ...]:
    """Bind the exact static definitions to a separately accepted Git revision."""

    if (
        type(source_revision) is not str
        or _GIT_REVISION.fullmatch(source_revision) is None
    ):
        raise FixtureBuildError("fixture construction rejected")
    return tuple(
        FixtureGenerator(
            generator_id=definition.generator_id,
            source_id=definition.source_id,
            source_commit=source_revision,
            policy_sha256=FIRST_PARTY_POLICY_SHA256,
            configuration_sha256=_configuration_sha256(definition),
            input_provenance_sha256=_input_provenance_sha256(definition),
            deterministic_seed="none",
            templates=definition.templates,
        )
        for definition in _DEFINITIONS
    )


def _fixture_identity_sha256(
    generator: FixtureGenerator, fixtures: tuple[GeneratedFixture, ...]
) -> str:
    values = tuple(
        value
        for fixture in fixtures
        for value in (
            fixture.template_id,
            fixture.domain,
            str(len(fixture.content)),
            fixture.content_sha256,
        )
    )
    return _digest(
        "csgpt-first-party-generator-output-v1",
        generator.generator_id,
        generator.source_id,
        generator.configuration_sha256,
        generator.input_provenance_sha256,
        *values,
    )


def first_party_generator_evidence(
    source_revision: str,
) -> FirstPartyGeneratorEvidence:
    """Summarize generated identities without approving or retaining raw bytes."""

    generators = first_party_generators(source_revision)
    generated = tuple(
        (generator, generate_fixtures(generator)) for generator in generators
    )
    records = tuple(
        FirstPartyGeneratorRecord(
            generator_id=generator.generator_id,
            source_id=generator.source_id,
            configuration_sha256=generator.configuration_sha256,
            input_provenance_sha256=generator.input_provenance_sha256,
            sample_count=len(fixtures),
            total_byte_count=sum(len(fixture.content) for fixture in fixtures),
            domain_counts=tuple(
                sorted(Counter(fixture.domain for fixture in fixtures).items())
            ),
            output_identity_sha256=_fixture_identity_sha256(generator, fixtures),
        )
        for generator, fixtures in generated
    )
    fixtures = tuple(
        fixture for _, generator_fixtures in generated for fixture in generator_fixtures
    )
    content_digests = tuple(fixture.content_sha256 for fixture in fixtures)
    output_identity_sha256 = _digest(
        FIRST_PARTY_REVIEW_EVIDENCE_SCHEMA_VERSION,
        FIRST_PARTY_GENERATOR_PROFILE_VERSION,
        FIRST_PARTY_POLICY_SHA256,
        *(
            value
            for record in records
            for value in (
                record.generator_id,
                record.source_id,
                record.configuration_sha256,
                record.input_provenance_sha256,
                str(record.sample_count),
                str(record.total_byte_count),
                record.output_identity_sha256,
            )
        ),
    )
    return FirstPartyGeneratorEvidence(
        schema_version=FIRST_PARTY_REVIEW_EVIDENCE_SCHEMA_VERSION,
        profile_version=FIRST_PARTY_GENERATOR_PROFILE_VERSION,
        source_revision=source_revision,
        source_origin=_SOURCE_ORIGIN,
        policy_sha256=FIRST_PARTY_POLICY_SHA256,
        generator_count=len(generators),
        sample_count=len(fixtures),
        total_byte_count=sum(len(fixture.content) for fixture in fixtures),
        unsafe_sample_count=sum(
            not _safe_content(fixture.content) for fixture in fixtures
        ),
        duplicate_sample_count=len(content_digests) - len(set(content_digests)),
        output_identity_sha256=output_identity_sha256,
        generators=records,
    )
