"""Verify the exact pending first-party generator-source proposal."""

import socket
from pathlib import Path

import pytest

from cybersecgpt.datasets import (
    FIRST_PARTY_GENERATOR_COUNT,
    FIRST_PARTY_GENERATOR_PROFILE_VERSION,
    FIRST_PARTY_LICENSE_EXPRESSION,
    FIRST_PARTY_POLICY_SHA256,
    FIRST_PARTY_REVIEW_EVIDENCE_SCHEMA_VERSION,
    FIRST_PARTY_SAMPLE_COUNT,
    FixtureBuildError,
    first_party_generator_evidence,
    first_party_generators,
    generate_fixtures,
)

SOURCE_REVISION = "1" * 40
EXPECTED_GENERATORS = (
    (
        "csgpt-p6-natural-language-v1",
        "csgpt-first-party-natural-language-v1",
        "057ea151919287c2c54d3338c0b055a04530fad842fabbca4ae0643e0849f239",
        "5c4da9651ba82612f993f4286b4f1bccdafea8c51cb53cddb4a266880a26c3b8",
        128,
        20_352,
        (("natural-language", 128),),
        "8a489e83f177ab82ad6c94d99e62621a198438004bffa1767f4ca7fb52123ab7",
    ),
    (
        "csgpt-p6-code-v1",
        "csgpt-first-party-code-v1",
        "34063827f525e224f1b95396da24a07c48e25ee25f7244e43a5160370a40a2e2",
        "68bfff490cda2a83c40d0769499f29b5c0baa1e9dcdce048ed1f047d1e7b3754",
        128,
        11_598,
        (("assembly", 32), ("code", 32), ("powershell", 32), ("shell", 32)),
        "e00c48d09c7cab00a940076ed34a0615a4ff0234cfbb88526fe6702250ab500d",
    ),
    (
        "csgpt-p6-logs-v1",
        "csgpt-first-party-logs-v1",
        "55112b7573aea16dc9d8ea07952c07851825a31376be30f5fa9d957c673c8815",
        "8a91a6c80cc69ea0fed52bd256a96b57e453fdfb4ae7fbc3560598edf8295007",
        128,
        13_422,
        (("linux-log", 64), ("windows-log", 64)),
        "66b89af601f777c4c3ee1b49bd2a4723c4eb0aee0c9a0e3bdb9597952bc9d57f",
    ),
    (
        "csgpt-p6-structured-data-v1",
        "csgpt-first-party-structured-data-v1",
        "ceebcb32391d50530bd2add176397d13aa35d4ffa7f80fdd977dbda74eaf1521",
        "57ac18226b3b576fcb4daffcae431ea375e155887c7d0b9e8bcc4954298f9190",
        128,
        9_376,
        (("iac", 32), ("json", 32), ("xml", 32), ("yaml", 32)),
        "2649bc78e563061ffe978ce7aa9753cb06c10e4153105ce425ef95875d3c31ab",
    ),
    (
        "csgpt-p6-network-v1",
        "csgpt-first-party-network-v1",
        "05d388fbfc0629111a23943d6406018248c31672619699716395af5d457f7cd4",
        "787f55856042d5af2d0e827f1025d710e4863e50d7aa5b10f72a25527af075bf",
        128,
        9_646,
        (("dns", 32), ("http", 32), ("telemetry", 32), ("url", 32)),
        "d104151564b849d0d7dafa5b841f49e442da7dbeabe7539648621c5bce90df44",
    ),
    (
        "csgpt-p6-security-identifiers-v1",
        "csgpt-first-party-security-identifiers-v1",
        "0965ee439bef5c868684cf21d75e807e0be258f377d571f6dc884219b1a07f05",
        "9b2ef89233a467ff9464485ac16422a0f04eaae976b900293acb1b284266036b",
        128,
        13_952,
        (("hash", 128),),
        "a7b5456e1d5aef61af6630fba099f5640d07ee2976fcd50163b21e3abbedecac",
    ),
    (
        "csgpt-p6-detection-rules-v1",
        "csgpt-first-party-detection-rules-v1",
        "c31889ca8f26db345da35ca1b774b131e81f815310d1967222f9d404a6c2a3d2",
        "bfe92654e84258dc4786c644f08f6ebc272b8ecb91c6ef8a8b7b06e51a8670f7",
        128,
        13_257,
        (
            ("firewall", 26),
            ("ids", 25),
            ("siem-query", 25),
            ("sigma", 26),
            ("yara", 26),
        ),
        "4cdd201242b14de97cd541b09ff6a023ec7be68f71225c5bb26899d4d9f73087",
    ),
    (
        "csgpt-p6-security-prose-v1",
        "csgpt-first-party-security-prose-v1",
        "4ec517f2dad4207c8772c86b3b696c3eb8384b03cd6871ceec8b48cb9effeaff",
        "16730aa5e2084f521982aa97768887928cef4bd89924ffa1bf4797b9ad86a107",
        128,
        20_864,
        (("malware-analysis", 64), ("threat-intelligence", 64)),
        "0c2b1d48af9dc23748c1a5af6efe85904915e3c1fb7a09b1e3d7967b3a60f138",
    ),
)


def test_exact_profile_and_content_minimized_evidence() -> None:
    assert FIRST_PARTY_GENERATOR_PROFILE_VERSION == (
        "csgpt-first-party-tokenizer-pilot-v1"
    )
    assert FIRST_PARTY_REVIEW_EVIDENCE_SCHEMA_VERSION == (
        "csgpt-first-party-generator-review-v1"
    )
    assert FIRST_PARTY_LICENSE_EXPRESSION == (
        "LicenseRef-CyberSecGPT-First-Party-Tokenizer-v1"
    )
    assert FIRST_PARTY_POLICY_SHA256 == (
        "309d41bb1ac80be81f07e461364dc134e621950d32037e7e7d314c1759c19dd3"
    )
    assert FIRST_PARTY_GENERATOR_COUNT == 8
    assert FIRST_PARTY_SAMPLE_COUNT == 1_024

    evidence = first_party_generator_evidence(SOURCE_REVISION)
    assert evidence.source_revision == SOURCE_REVISION
    assert evidence.source_origin == (
        "repository:src/cybersecgpt/datasets/first_party_generators.py"
    )
    assert evidence.policy_sha256 == FIRST_PARTY_POLICY_SHA256
    assert evidence.generator_count == FIRST_PARTY_GENERATOR_COUNT
    assert evidence.sample_count == FIRST_PARTY_SAMPLE_COUNT
    assert evidence.total_byte_count == 112_467
    assert evidence.unsafe_sample_count == 0
    assert evidence.duplicate_sample_count == 0
    assert evidence.output_identity_sha256 == (
        "5a83ee11f172be9af342c116ef918bb2a88d9e15a9f06e798dd7c24cbcdee309"
    )
    assert (
        tuple(
            (
                record.generator_id,
                record.source_id,
                record.configuration_sha256,
                record.input_provenance_sha256,
                record.sample_count,
                record.total_byte_count,
                record.domain_counts,
                record.output_identity_sha256,
            )
            for record in evidence.generators
        )
        == EXPECTED_GENERATORS
    )


def test_generation_is_exact_ordered_unique_and_bounded() -> None:
    generators = first_party_generators(SOURCE_REVISION)
    assert len(generators) == FIRST_PARTY_GENERATOR_COUNT
    assert all(generator.source_commit == SOURCE_REVISION for generator in generators)
    assert all(generator.deterministic_seed == "none" for generator in generators)
    assert all(
        generator.policy_sha256 == FIRST_PARTY_POLICY_SHA256 for generator in generators
    )

    fixtures = tuple(
        fixture for generator in generators for fixture in generate_fixtures(generator)
    )
    assert len(fixtures) == FIRST_PARTY_SAMPLE_COUNT
    assert len({fixture.content_sha256 for fixture in fixtures}) == len(fixtures)
    assert sum(len(fixture.content) for fixture in fixtures) == 112_467
    assert max(len(fixture.content) for fixture in fixtures) < 65_536
    assert all(fixture.content.endswith(b"\n") for fixture in fixtures)
    assert all(b"\r" not in fixture.content for fixture in fixtures)
    assert all(b"\x00" not in fixture.content for fixture in fixtures)
    for generator in generators:
        generated = generate_fixtures(generator)
        assert tuple(item.template_id for item in generated) == tuple(
            sorted(item.template_id for item in generated)
        )


def test_evidence_is_network_and_working_directory_independent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def blocked_socket(*args: object, **kwargs: object) -> None:
        raise AssertionError("network use is forbidden")

    expected = first_party_generator_evidence(SOURCE_REVISION)
    monkeypatch.setattr(socket, "socket", blocked_socket)
    fresh = tmp_path / "fresh-generator-review"
    fresh.mkdir()
    monkeypatch.chdir(fresh)
    assert first_party_generator_evidence(SOURCE_REVISION) == expected


def test_documented_evidence_matches_without_expanded_fixture_text() -> None:
    document = (
        Path(__file__).resolve().parents[1]
        / "docs"
        / "P6_FIRST_PARTY_GENERATOR_SOURCE_EVIDENCE.md"
    ).read_text(encoding="utf-8")
    evidence = first_party_generator_evidence(SOURCE_REVISION)
    assert evidence.policy_sha256 in document
    assert evidence.output_identity_sha256 in document
    for record in evidence.generators:
        assert record.generator_id in document
        assert record.configuration_sha256 in document
        assert record.input_provenance_sha256 in document
        assert record.output_identity_sha256 in document
    assert all(
        fixture.content.decode("utf-8").strip() not in document
        for generator in first_party_generators(SOURCE_REVISION)
        for fixture in generate_fixtures(generator)
    )


@pytest.mark.parametrize(
    "source_revision",
    ["not-an-exact-revision", "1" * 39, "A" * 40, "g" * 40, None],
)
def test_source_revision_must_be_an_exact_git_commit(source_revision: object) -> None:
    with pytest.raises(FixtureBuildError, match="fixture construction rejected"):
        first_party_generators(source_revision)  # type: ignore[arg-type]
