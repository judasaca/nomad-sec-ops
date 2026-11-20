"""Exercise the CI/CD settings schema, including YAML duplicate keys."""

from pathlib import Path

import pytest

from nomad_sec_ops.steps.ci_cd.config import CONFIG_FILENAME, resolve_ci_cd_config


@pytest.mark.parametrize(
    "content",
    [
        "{}",
        "rules: {}",
        "rules:\n  unpinned-images: {disable: true}\n"
        "  template-injection: {disable: false}\n",
        "rules: {unpinned-images: {disable: yes}, template-injection: {disable: on}}",
        "rules: {unpinned-images: {disable: 'invalid', disable: false}}",
    ],
)
def test_valid_config(tmp_path: Path, content: str) -> None:
    path = tmp_path / CONFIG_FILENAME
    path.write_text(content, encoding="utf-8")

    assert resolve_ci_cd_config(path) == path


@pytest.mark.parametrize(
    ("content", "error"),
    [
        ("rules: {", "Invalid YAML"),
        ("{}\n---\n{}", "Invalid YAML"),
        ("", "Input should be a valid dictionary"),
        ("rules: null", "Input should be a valid dictionary"),
        ("rules: {12: {disable: true}}", "Input should be a valid string"),
        ("version: 1", "Extra inputs are not permitted"),
        ("rules: {missing-rule: {disable: true}}", "Unknown rule IDs 'missing-rule'"),
        (
            "rules: {missing-rule: {disable: true}, another-rule: {disable: false}}",
            "Unknown rule IDs 'another-rule', 'missing-rule'",
        ),
        ("rules: {unpinned-images: {ignore: []}}", "Extra inputs are not permitted"),
        ("rules: {unpinned-images: true}", "Input should be a valid dictionary"),
        ("rules: {unpinned-images: {}}", "Field required"),
        (
            "rules: {unpinned-images: {disable: 'true'}}",
            "Input should be a valid boolean",
        ),
        ("rules: {unpinned-images: {disable: 1}}", "Input should be a valid boolean"),
        ("rules: {unpinned-images: {disable: !!int ''}}", "Invalid YAML"),
    ],
)
def test_invalid_config(tmp_path: Path, content: str, error: str) -> None:
    path = tmp_path / CONFIG_FILENAME
    path.write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match=error):
        resolve_ci_cd_config(path)
