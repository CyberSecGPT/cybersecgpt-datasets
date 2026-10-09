"""Validate dataset repository security and dependency boundaries."""

import re
import tomllib
from pathlib import Path
from typing import cast

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_FILES = frozenset(
    {
        ".gitattributes",
        ".github/workflows/ci.yml",
        ".gitignore",
        "AGENTS.md",
        "CHANGELOG.md",
        "CONTRIBUTING.md",
        "README.md",
        "SECURITY.md",
        "docs/ARCHITECTURE.md",
        "docs/P6_CI_VALIDATION_SCAFFOLD.md",
        "docs/P6_CORPUS_MANIFEST_CONTRACTS.md",
        "docs/P6_FIRST_PARTY_GENERATOR_SOURCE_EVIDENCE.md",
        "docs/P6_FIRST_PARTY_SNAPSHOT_GATE.md",
        "docs/P6_FIXTURE_BUILDER_GATE.md",
        "docs/P6_TOKENIZER_CORPUS_GATE.md",
        "pyproject.toml",
        "scripts/validate_repository.py",
        "scripts/verify_distribution.py",
        "src/cybersecgpt/datasets/__init__.py",
        "src/cybersecgpt/datasets/corpus_manifest.py",
        "src/cybersecgpt/datasets/fixture_builder.py",
        "src/cybersecgpt/datasets/first_party_generators.py",
        "src/cybersecgpt/datasets/first_party_snapshot.py",
        "src/cybersecgpt/datasets/py.typed",
        "tests/__init__.py",
        "tests/test_corpus_manifest.py",
        "tests/test_fixture_builder.py",
        "tests/test_first_party_generators.py",
        "tests/test_first_party_snapshot.py",
        "tests/test_public_api.py",
    }
)
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
)
PROVIDER_MARKERS = (
    "openai",
    "anthropic",
    "cohere",
    "google-generativeai",
    "google-genai",
)
FORBIDDEN_SUFFIXES = frozenset(
    {".7z", ".bin", ".bz2", ".csv", ".gz", ".jsonl", ".parquet", ".tar", ".zip"}
)
TEXT_SUFFIXES = frozenset({".json", ".md", ".py", ".toml", ".txt", ".yml", ".yaml"})
TEXT_NAMES = frozenset({".gitattributes", ".gitignore"})


class RepositoryValidationError(RuntimeError):
    """Report a repository policy violation."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RepositoryValidationError(message)


def main() -> None:
    missing = sorted(path for path in REQUIRED_FILES if not (ROOT / path).is_file())
    _require(not missing, f"required repository files are missing: {missing}")

    with (ROOT / "pyproject.toml").open("rb") as stream:
        parsed = cast(dict[str, object], tomllib.load(stream))
    project = parsed.get("project")
    _require(isinstance(project, dict), "pyproject project table is missing")
    dependencies = cast(dict[str, object], project).get("dependencies")
    _require(dependencies == [], f"runtime dependency boundary changed: {dependencies}")
    normalized = "\n".join(cast(list[str], dependencies)).lower()
    _require(
        not any(marker in normalized for marker in PROVIDER_MARKERS),
        "provider SDK dependency detected in runtime dependencies",
    )

    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT)
        if any(
            part.startswith(".") and part not in {".github"} for part in relative.parts
        ):
            continue
        if any(part in {"build", "dist", "__pycache__"} for part in relative.parts):
            continue
        _require(
            path.suffix.lower() not in FORBIDDEN_SUFFIXES,
            f"corpus-like or archive file is forbidden in Git: {relative}",
        )
        if path.suffix not in TEXT_SUFFIXES and path.name not in TEXT_NAMES:
            continue
        text = path.read_text(encoding="utf-8")
        for pattern in SECRET_PATTERNS:
            _require(
                pattern.search(text) is None,
                f"sensitive material pattern detected in {relative}",
            )

    readme = (ROOT / "README.md").read_text(encoding="utf-8").lower()
    _require("offline" in readme, "README must preserve offline operation")
    _require("authorization" in readme, "README must preserve non-authorization")
    proposal = (ROOT / "src/cybersecgpt/datasets/first_party_generators.py").read_text(
        encoding="utf-8"
    )
    _require(
        "SourceApprovalRecord" not in proposal
        and "build_fixture_corpus" not in proposal,
        "generator-source proposal must not create approvals or snapshots",
    )
    print("Dataset repository validation passed.")


if __name__ == "__main__":
    main()
