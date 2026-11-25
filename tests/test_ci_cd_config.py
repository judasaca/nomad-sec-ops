"""Exercise the CI/CD settings schema and merge behavior."""

from pathlib import Path

import pytest

from nomad_sec_ops.config import (
    CONFIG_FILENAME,
    RepositorySettings,
    load_repository_settings,
)


@pytest.mark.parametrize(
    "content",
    [
        "{}",
        "ci-cd: {rules: {}}",
        "ci-cd:\n  rules:\n    unpinned-images: {disable: true}\n"
        "    template-injection: {disable: false}\n",
        "ci-cd: {rules: {unpinned-images: {disable: yes}}}",
        "ci-cd: {rules: {unpinned-images: {disable: 'invalid', disable: false}}}",
    ],
)
def test_valid_config(tmp_path: Path, content: str) -> None:
    path = tmp_path / CONFIG_FILENAME
    path.write_text(content, encoding="utf-8")

    load_repository_settings(path)


@pytest.mark.parametrize(
    ("content", "error"),
    [
        ("rules: {}", "Extra inputs are not permitted"),
        ("ci-cd: {", "Invalid YAML"),
        ("{}\n---\n{}", "Invalid YAML"),
        ("", "Input should be a valid dictionary"),
        ("ci-cd: null", "Input should be a valid dictionary"),
        ("ci-cd: {rules: null}", "Input should be a valid dictionary"),
        ("ci-cd: {rules: {12: {disable: true}}}", "Input should be a valid string"),
        ("ci-cd: {github: {}}", "Extra inputs are not permitted"),
        ("ci-cd: {rules: {unpinned-images: {ignore: []}}}", "Extra inputs"),
        (
            "ci-cd: {rules: {unpinned-images: true}}",
            "Input should be a valid dictionary",
        ),
        (
            "ci-cd: {rules: {unpinned-images: {disable: 1}}}",
            "Input should be a valid boolean",
        ),
        ("ci-cd: {rules: {unpinned-images: {disable: !!int ''}}}", "Invalid YAML"),
        (
            "ci-cd: {rules: {unknown: {}}}",
            "Unknown rule IDs 'unknown'",
        ),
        (
            "ci-cd: {rules: {unpinned-images: {disable: 'false'}}}",
            "Input should be a valid boolean",
        ),
        (
            "ci-cd: {rules: {unpinned-images: {policies: {}}}}",
            "'unpinned-images' does not support policies",
        ),
        (
            "ci-cd: {rules: {unpinned-uses: {policies: {org/tool: invalid}}}}",
            "Input should be 'hash-pin', 'ref-pin' or 'any'",
        ),
    ],
)
def test_rejects_invalid_settings(tmp_path: Path, content: str, error: str) -> None:
    path = tmp_path / CONFIG_FILENAME
    path.write_text(content)

    with pytest.raises(ValueError, match=error):
        load_repository_settings(path)


def test_merges_rules_flags_and_policy_entries(tmp_path: Path) -> None:
    defaults = RepositorySettings.model_validate(
        {
            "ci-cd": {
                "rules": {
                    "unpinned-uses": {
                        "disable": True,
                        "policies": {"org/tool": "ref-pin", "org/other": "ref-pin"},
                    },
                    "unpinned-images": {"disable": True},
                    "dangerous-triggers": {"disable": True},
                }
            }
        }
    ).ci_cd
    path = tmp_path / CONFIG_FILENAME
    path.write_text(
        "ci-cd:\n"
        "  rules:\n"
        "    unpinned-uses:\n"
        "      policies: {org/tool: hash-pin, org/new: ref-pin}\n"
        "    unpinned-images: {disable: false}\n"
        "    template-injection: {disable: true}\n"
    )

    effective = defaults.with_overrides(load_repository_settings(path).ci_cd)

    assert effective.rules["unpinned-uses"].disable is True
    assert effective.rules["unpinned-uses"].policies == {
        "org/tool": "hash-pin",
        "org/other": "ref-pin",
        "org/new": "ref-pin",
    }
    assert effective.rules["unpinned-images"].disable is False
    assert effective.rules["dangerous-triggers"].disable is True
    assert effective.rules["template-injection"].disable is True
    assert defaults.rules["unpinned-images"].disable is True
    assert defaults.rules["unpinned-uses"].policies["org/tool"] == "ref-pin"


@pytest.mark.parametrize("content", ["{}", "ci-cd: {}", "ci-cd: {rules: {}}"])
def test_empty_overrides_inherit_defaults(tmp_path: Path, content: str) -> None:
    defaults = RepositorySettings.model_validate(
        {"ci-cd": {"rules": {"unpinned-images": {"disable": True}}}}
    ).ci_cd
    path = tmp_path / CONFIG_FILENAME
    path.write_text(content)

    assert defaults.with_overrides(load_repository_settings(path).ci_cd) == defaults
