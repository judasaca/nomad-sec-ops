"""Verify provider dispatch, scanner execution, and result handling."""

import json
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from nomad_sec_ops.cli import app
from nomad_sec_ops.models import AnalysisStatus, CheckResult
from nomad_sec_ops.repositories import local_remote, parse_remote
from nomad_sec_ops.scanners.zizmor import run_zizmor

runner = CliRunner()


def create_repository(path: Path, remote: str | None) -> None:
    subprocess.run(["git", "init", "--quiet", str(path)], check=True, timeout=10)
    if remote is not None:
        subprocess.run(
            ["git", "-C", str(path), "remote", "add", "origin", remote],
            check=True,
            timeout=10,
        )


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/org/repo.git",
        "https://GITHUB.COM/org/repo/",
        "ssh://git@github.com/org/repo.git",
        "git@github.com:org/repo.git",
        "git://github.com/org/repo.git",
    ],
)
def test_github_urls(url: str) -> None:
    remote = parse_remote(url)
    assert remote.host == "github.com"
    assert remote.github_slug == "org/repo"


@pytest.mark.parametrize(
    "url",
    [
        "not-a-url",
        "https://github.com",
        "https://github.com/org",
        "https://github.com/org/repo/tree/main",
        "https://github.com/-org/repo",
        "https://github.com/org/repo?query=value",
        "https://github.com/org/repo with spaces",
        "file:///tmp/repo",
    ],
)
def test_invalid_urls(url: str) -> None:
    with pytest.raises(ValueError):
        parse_remote(url)


@pytest.mark.parametrize(
    ("url", "expected_code"),
    [
        ("https://github.com.example.org/org/repo.git", 3),
        ("https://github.com@example.org/org/repo.git", 3),
        ("https://gitlab.example.org/group/repo.git", 3),
    ],
)
def test_non_github_does_not_run_scanner(
    url: str, expected_code: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    scanner = Mock()
    monkeypatch.setattr("nomad_sec_ops.scanners.github.run_zizmor", scanner)
    download = Mock()
    monkeypatch.setattr("nomad_sec_ops.repositories.checkout_repository", download)

    result = runner.invoke(app, ["static-analysis", "--repo", url])

    assert result.exit_code == expected_code
    scanner.assert_not_called()
    download.assert_not_called()


@pytest.mark.parametrize("host", ["github.com", "gitlab.com"])
@pytest.mark.parametrize("use_default", [False, True])
def test_local_dispatch(
    host: str, use_default: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    create_repository(tmp_path, f"git@{host}:org/repo.git")
    monkeypatch.chdir(tmp_path)
    scanner = Mock(
        return_value=CheckResult(
            status=AnalysisStatus.PASSED,
            message="zizmor",
            tool="zizmor",
            stdout="audit output\n",
        )
    )
    monkeypatch.setattr("nomad_sec_ops.scanners.github.run_zizmor", scanner)
    args = ["static-analysis"]
    if not use_default:
        args.extend(["--path", str(tmp_path)])

    result = runner.invoke(app, args)

    assert result.exit_code == (0 if host == "github.com" else 3)
    if host == "github.com":
        scanner.assert_called_once_with(
            str(tmp_path.resolve()),
            rule_overrides={"unpinned-uses": False},
            unpinned_uses_policies={
                "judasaca/nomad-sec-ops/.github/workflows/security-scan.yml": "ref-pin"
            },
        )
        assert "audit output" not in result.output
    else:
        scanner.assert_not_called()
        assert "No .gitlab-ci.yml found" in result.output


def test_nested_local_directory(tmp_path: Path) -> None:
    create_repository(tmp_path, "https://github.com/org/repo.git")
    nested = tmp_path / "src"
    nested.mkdir()

    remote = local_remote(nested)

    assert remote is not None
    assert remote.host == "github.com"


def test_nested_scan_loads_repository_root_settings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    create_repository(tmp_path, "https://github.com/org/repo.git")
    nested = tmp_path / "src"
    nested.mkdir()
    (tmp_path / "nomad-sec-ops.yml").write_text(
        "ci-cd: {rules: {template-injection: {disable: true}}}"
    )
    (nested / "nomad-sec-ops.yml").write_text("invalid: [")
    scanner = Mock(
        return_value=CheckResult(status=AnalysisStatus.PASSED, message="zizmor")
    )
    monkeypatch.setattr("nomad_sec_ops.scanners.github.run_zizmor", scanner)

    result = runner.invoke(app, ["static-analysis", "--path", str(nested)])

    assert result.exit_code == 0, result.output
    assert scanner.call_args.args == (str(nested),)
    assert scanner.call_args.kwargs["rule_overrides"]["template-injection"] is True


def test_missing_origin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    create_repository(tmp_path, None)
    scanner = Mock()
    monkeypatch.setattr("nomad_sec_ops.scanners.github.run_zizmor", scanner)

    result = runner.invoke(app, ["static-analysis", "--path", str(tmp_path)])

    assert result.exit_code == 3
    assert "no Git origin" in result.output
    scanner.assert_not_called()


@pytest.mark.parametrize(
    ("scanner_code", "expected"),
    [(0, 0), (11, 1), (12, 1), (13, 1), (14, 1), (1, 2), (2, 2), (3, 3), (-9, 2)],
)
@pytest.mark.parametrize("verbose", [False, True])
def test_scanner_exit_codes(
    scanner_code: int,
    expected: int,
    verbose: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    create_repository(tmp_path, "https://github.com/org/repo.git")
    finding = {
        "ident": "unpinned-uses",
        "desc": "unpinned action reference",
        "url": "https://docs.zizmor.sh/audits/#unpinned-uses",
        "determinations": {
            "severity": "High",
            "confidence": "High",
            "persona": "Regular",
        },
        "locations": [
            {
                "symbolic": {
                    "kind": "Primary",
                    "key": {"Local": {"verbatim_path": str(tmp_path / "action.yml")}},
                    "route": {"route": []},
                    "annotation": "pin this action",
                },
                "concrete": {
                    "location": {"start_point": {"row": 0, "column": 0}},
                    "feature": "scanner evidence",
                },
            }
        ],
    }
    stdout = json.dumps([finding]) if expected == 1 else "scanner stdout\n"
    scanner = Mock(
        return_value=subprocess.CompletedProcess(
            [], scanner_code, stdout, "scanner stderr\n"
        )
    )
    monkeypatch.setattr("nomad_sec_ops.scanners.zizmor.subprocess", Mock(run=scanner))

    args = ["static-analysis", "--path", str(tmp_path)]
    if verbose:
        args.append("--verbose")
    result = runner.invoke(app, args)

    assert result.exit_code == expected
    assert ("scanner stdout" in result.stdout) == (expected in {2, 3})
    assert f"Total findings: {int(expected == 1)}" in result.stdout
    compact = (
        "action.yml:1: unpinned action reference: pin this action  "
        "https://docs.zizmor.sh/audits/#unpinned-uses"
    )
    assert (compact in result.stdout) == (expected == 1 and not verbose)
    assert ("action.yml:1:1: high[unpinned-uses]" in result.stdout) == (
        expected == 1 and verbose
    )
    assert ("scanner evidence" in result.stdout) == (expected == 1 and verbose)
    assert ("fix:" in result.stdout) == (expected == 1 and verbose)
    assert "scanner stderr" in result.stderr


@pytest.mark.parametrize(
    "error",
    [
        FileNotFoundError(2, "Missing executable", "zizmor"),
        subprocess.TimeoutExpired("zizmor", 300),
        PermissionError("Cannot execute zizmor"),
    ],
)
def test_scanner_execution_errors(
    error: Exception, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    create_repository(tmp_path, "https://github.com/org/repo.git")
    monkeypatch.setattr(
        "nomad_sec_ops.scanners.github.run_zizmor", Mock(side_effect=error)
    )

    result = runner.invoke(app, ["static-analysis", "--path", str(tmp_path)])

    assert result.exit_code == 2
    assert "Traceback" not in result.output


def test_scanner_arguments(monkeypatch: pytest.MonkeyPatch) -> None:
    process = Mock(return_value=subprocess.CompletedProcess([], 0, "", ""))
    monkeypatch.setattr("nomad_sec_ops.scanners.zizmor.subprocess.run", process)
    monkeypatch.setattr(
        "nomad_sec_ops.scanners.zizmor._zizmor_executable",
        lambda: ("zizmor", "1.32.0"),
    )
    monkeypatch.setenv("ZIZMOR_CONFIG", "/unrelated/zizmor.yml")

    run_zizmor("/local/repo")

    process.assert_called_once()
    config_path = Path(process.call_args.args[0][6])
    assert process.call_args.args[0] == [
        "zizmor",
        "--quiet",
        "--offline",
        "--format=json-v1",
        "--gh-hostname=github.com",
        "--config",
        str(config_path),
        "--no-ignores",
        "--",
        "/local/repo",
    ]
    assert process.call_args.kwargs["env"].get("ZIZMOR_CONFIG") is None
    assert not config_path.exists()


@pytest.mark.parametrize("output", ["not JSON", "[]", '[{"locations": []}]'])
def test_cannot_decode_reported_findings(
    output: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    process = Mock(return_value=subprocess.CompletedProcess([], 14, output, ""))
    monkeypatch.setattr("nomad_sec_ops.scanners.zizmor.subprocess.run", process)

    result = run_zizmor(str(tmp_path))

    assert result.status == AnalysisStatus.ERROR
    assert result.findings == []
    assert "Could not read zizmor findings" in result.message


@pytest.mark.parametrize("has_warning", [False, True])
def test_real_successful_offline_scan(
    has_warning: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    create_repository(tmp_path, "https://github.com/org/repo.git")
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        "name: Test\n"
        "on: [push]\n"
        "permissions: {}\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo ok\n"
    )
    if has_warning:
        (workflows / "invalid.yml").write_text("invalid: [\n")
    for name in (
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "ZIZMOR_GITHUB_TOKEN",
        "ZIZMOR_OFFLINE",
        "ZIZMOR_NO_ONLINE_AUDITS",
    ):
        monkeypatch.delenv(name, raising=False)

    result = runner.invoke(app, ["static-analysis", "--path", str(tmp_path)])

    assert result.exit_code == 0
    assert "zizmor: no findings." in result.stdout
    assert "No findings to report." not in result.stdout
    assert "INFO" not in result.stderr
    assert "running in offline mode by default" not in result.stderr
    assert ("failed to parse input" in result.stderr) == has_warning


@pytest.mark.parametrize("disable", [None, False, True])
@pytest.mark.parametrize("external_config", [False, True])
def test_real_offline_scan(
    disable: bool | None,
    external_config: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    create_repository(tmp_path, "https://github.com/org/repo.git")
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        "name: Unsafe workflow\n"
        "on: pull_request_target\n"
        "permissions: {}\n"
        "jobs:\n"
        "  example:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo '${{ github.event.pull_request.title }}'"
        " # zizmor: ignore[template-injection]\n"
    )
    (workflows.parent / "zizmor.yml").write_text(
        "rules:\n"
        "  template-injection: {disable: true}\n"
        "  dangerous-triggers: {disable: true}\n"
    )
    if external_config:
        external_path = tmp_path / "external-zizmor.yml"
        external_path.write_text("malformed: [")
        monkeypatch.setenv("ZIZMOR_CONFIG", str(external_path))
    else:
        monkeypatch.delenv("ZIZMOR_CONFIG", raising=False)
    if disable is not None:
        (tmp_path / "nomad-sec-ops.yml").write_text(
            "ci-cd:\n"
            "  rules:\n"
            f"    template-injection: {{disable: {str(disable).lower()}}}"
        )
    monkeypatch.setenv("ZIZMOR_OFFLINE", "true")

    result = runner.invoke(app, ["static-analysis", "--path", str(tmp_path)])

    assert result.exit_code == 1, result.output
    assert "dangerous-triggers" in result.output
    assert ("template-injection" in result.output) == (not disable)


@pytest.mark.parametrize("disable", [None, False, True])
@pytest.mark.parametrize("require_hash", [False, True])
def test_shared_workflow_pinning_policy(
    disable: bool | None, require_hash: bool, tmp_path: Path
) -> None:
    create_repository(tmp_path, "https://github.com/org/repo.git")
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "security.yml").write_text(
        "name: Security\n"
        "on: [pull_request]\n"
        "permissions: {contents: read}\n"
        "jobs:\n"
        "  shared:\n"
        "    uses: judasaca/nomad-sec-ops/.github/workflows/security-scan.yml@develop\n"
        "  other:\n"
        "    uses: judasaca/nomad-sec-ops/.github/workflows/other.yml@develop"
        " # zizmor: ignore[unpinned-uses]\n"
    )
    if require_hash:
        rule_settings = (
            "" if disable is None else f"      disable: {str(disable).lower()}\n"
        )
        (tmp_path / "nomad-sec-ops.yml").write_text(
            "ci-cd:\n"
            "  rules:\n"
            "    unpinned-uses:\n"
            f"{rule_settings}"
            "      policies:\n"
            "        judasaca/nomad-sec-ops/.github/workflows/security-scan.yml:"
            " hash-pin\n"
        )
    elif disable is not None:
        (tmp_path / "nomad-sec-ops.yml").write_text(
            f"ci-cd:\n  rules:\n    unpinned-uses: {{disable: {str(disable).lower()}}}"
        )

    result = runner.invoke(app, ["static-analysis", "--path", str(tmp_path), "-v"])

    assert result.exit_code == (0 if disable else 1), result.output
    assert ("unpinned-uses" in result.output) == (not disable)
    assert ("/other.yml@develop" in result.output) == (not disable)
    assert ("/security-scan.yml@develop" in result.output) == (
        require_hash and not disable
    )
