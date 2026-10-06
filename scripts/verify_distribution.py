"""Verify dataset wheel and source-distribution boundaries."""

import argparse
import tarfile
import zipfile
from email.parser import Parser
from pathlib import Path

EXPECTED_SOURCE_MEMBERS = frozenset(
    {
        "cybersecgpt/datasets/__init__.py",
        "cybersecgpt/datasets/corpus_manifest.py",
        "cybersecgpt/datasets/fixture_builder.py",
        "cybersecgpt/datasets/first_party_generators.py",
        "cybersecgpt/datasets/py.typed",
    }
)
EXPECTED_SDIST_MEMBERS = frozenset(
    {
        ".gitignore",
        "CHANGELOG.md",
        "PKG-INFO",
        "README.md",
        "SECURITY.md",
        "pyproject.toml",
        "src/cybersecgpt/datasets/__init__.py",
        "src/cybersecgpt/datasets/corpus_manifest.py",
        "src/cybersecgpt/datasets/fixture_builder.py",
        "src/cybersecgpt/datasets/first_party_generators.py",
        "src/cybersecgpt/datasets/py.typed",
    }
)
PROVIDER_MARKERS = (
    "openai",
    "anthropic",
    "cohere",
    "google-generativeai",
    "google-genai",
)


class DistributionVerificationError(RuntimeError):
    """Report a distribution boundary violation."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise DistributionVerificationError(message)


def verify_wheel(path: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        source_members = {name for name in names if name.startswith("cybersecgpt/")}
        _require(
            source_members == EXPECTED_SOURCE_MEMBERS,
            f"wheel source members are incorrect: {sorted(source_members)}",
        )
        _require(
            "cybersecgpt/__init__.py" not in names,
            "datasets wheel must not own the top-level namespace package",
        )
        metadata_names = [
            name for name in names if name.endswith(".dist-info/METADATA")
        ]
        _require(
            len(metadata_names) == 1, "wheel must contain exactly one METADATA file"
        )
        metadata = Parser().parsestr(archive.read(metadata_names[0]).decode("utf-8"))
        _require(
            metadata.get("Name") == "cybersecgpt-datasets", "wheel Name is incorrect"
        )
        _require(metadata.get("Version") == "0.1.0", "wheel Version is incorrect")
        requirements = [str(item) for item in metadata.get_all("Requires-Dist", [])]
        runtime = [item for item in requirements if "; extra ==" not in item]
        _require(runtime == [], f"unexpected runtime dependencies: {runtime}")
        normalized = "\n".join(requirements).lower()
        _require(
            not any(marker in normalized for marker in PROVIDER_MARKERS),
            "provider SDK dependency detected in wheel metadata",
        )


def verify_sdist(path: Path) -> None:
    with tarfile.open(path, mode="r:gz") as archive:
        members = {
            "/".join(member.name.split("/")[1:])
            for member in archive.getmembers()
            if member.isfile()
        }
    _require(
        members == EXPECTED_SDIST_MEMBERS,
        f"sdist members are incorrect: {sorted(members)}",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    wheels = sorted(args.directory.glob("*.whl"))
    sdists = sorted(args.directory.glob("*.tar.gz"))
    _require(len(wheels) == 1, f"expected one wheel, found {len(wheels)}")
    _require(len(sdists) == 1, f"expected one sdist, found {len(sdists)}")
    verify_wheel(wheels[0])
    verify_sdist(sdists[0])
    print("Dataset distribution verification passed.")


if __name__ == "__main__":
    main()
