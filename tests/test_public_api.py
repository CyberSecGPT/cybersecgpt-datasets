"""Verify the deliberately small public manifest-contract API."""

import cybersecgpt.datasets as datasets


def test_public_api_is_explicit() -> None:
    assert datasets.__all__ == (
        "MANIFEST_SCHEMA_VERSION",
        "ExclusionRecord",
        "ManifestValidationError",
        "ReviewDecision",
        "SampleRecord",
        "SnapshotManifest",
        "SourceApprovalRecord",
        "SourceKind",
        "TransformationRecord",
        "GENERATOR_SCHEMA_VERSION",
        "BuildRequest",
        "BuildResult",
        "FixtureBuildError",
        "FixtureGenerator",
        "FixtureTemplate",
        "GeneratedFixture",
        "build_fixture_corpus",
        "generate_fixtures",
        "verify_fixture_replay",
        "FIRST_PARTY_GENERATOR_COUNT",
        "FIRST_PARTY_GENERATOR_PROFILE_VERSION",
        "FIRST_PARTY_LICENSE_EXPRESSION",
        "FIRST_PARTY_POLICY_SHA256",
        "FIRST_PARTY_REVIEW_EVIDENCE_SCHEMA_VERSION",
        "FIRST_PARTY_SAMPLE_COUNT",
        "FirstPartyGeneratorEvidence",
        "FirstPartyGeneratorRecord",
        "first_party_generator_evidence",
        "first_party_generators",
    )
    assert datasets.__doc__ == "CyberSecGPT dataset governance package boundary."
