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
    )
    assert datasets.__doc__ == "CyberSecGPT dataset governance package boundary."
