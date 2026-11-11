"""Check GitLab coverage and compare the policy to installed zizmor offline."""

import json
import subprocess
import sys
from pathlib import Path
from typing import Literal

import pytest
import yaml
from typer.testing import CliRunner

from nomad_sec_ops.cli import app
from nomad_sec_ops.models import AnalysisStatus, CheckResult
from nomad_sec_ops.repositories import RepositoryProvider, RepositoryTarget
from nomad_sec_ops.scanners.gitlab import run_gitlab
from nomad_sec_ops.scanners.gitlab.unpinned_images import UPSTREAM, UnpinnedImages

DIGEST = "sha256:" + "a" * 64


def scan(tmp_path: Path, source: str, *, pedantic: bool = False) -> CheckResult:
    (tmp_path / ".gitlab-ci.yml").write_text(source)
    target = RepositoryTarget(tmp_path, None, RepositoryProvider.GITLAB)
    return run_gitlab(
        target, rules=[UnpinnedImages(persona="pedantic" if pedantic else "regular")]
    )


def test_all_image_declaration_forms_and_mapping(tmp_path: Path) -> None:
    result = scan(
        tmp_path,
        """image: ubuntu
services: [redis:latest]
default:
  image: {name: node:latest}
  services:
    - name: postgres
.template:
  image: alpine
test:
  image: {name: python:latest, entrypoint: ['']}
  services: [docker:dind, {name: redis}]
  script: echo ok
variables:
  image: ignored
workflow:
  name: ignored
""",
    )

    assert result.status == AnalysisStatus.FINDINGS
    assert [finding.location for finding in result.findings] == [
        "image",
        "services[0]",
        "default.image.name",
        "default.services[0].name",
        ".template.image",
        "test.image.name",
        "test.services[1].name",
    ]
    first = result.findings[0]
    assert (first.line, first.column) == (1, 8)
    assert first.evidence == "ubuntu"
    assert first.rule_id == first.upstream.rule_id == "unpinned-images"
    assert first.upstream == UPSTREAM
    assert UPSTREAM.commit in first.upstream.source_url
    assert first.severity == "high"
    assert first.confidence == "high"
    assert first.persona == "regular"
    assert "image@sha256" in first.remediation
    assert (
        result.model_dump(mode="json")["findings"][0]["upstream"]["version"] == "1.32.0"
    )


@pytest.mark.parametrize(
    "reference", ["$IMAGE", "${IMAGE}", "repo:$TAG", "$[[ inputs.image ]]"]
)
def test_dynamic_images_are_low_confidence(tmp_path: Path, reference: str) -> None:
    result = scan(tmp_path, yaml.safe_dump({"test": {"image": reference}}))

    assert result.status == AnalysisStatus.FINDINGS
    assert len(result.findings) == 1
    assert result.findings[0].confidence == "low"
    assert result.findings[0].message == "container image may be unpinned"


def test_aliases_and_unrelated_reference_tags(tmp_path: Path) -> None:
    result = scan(
        tmp_path,
        """default:
  image: &image ubuntu:latest
test:
  image: *image
  script: !reference [.template, script]
""",
    )

    assert len(result.findings) == 2
    assert result.findings[1].location == "test.image"


@pytest.mark.parametrize(
    "source",
    [
        "include: {remote: 'https://example.org/ci.yml'}\n",
        "include: {local: jobs.yml}\n",
        "test:\n  <<: {image: ubuntu:latest}\n",
        "test:\n  image: !reference [.template, image]\n",
        "test:\n  services: !reference [.template, services]\n",
        "",
    ],
)
def test_unresolved_inputs_do_not_pass(tmp_path: Path, source: str) -> None:
    result = scan(tmp_path, source)

    assert result.status == AnalysisStatus.NOT_EVALUATED
    assert "Not evaluated:" in result.stderr


def test_findings_retained_with_incomplete_coverage(tmp_path: Path) -> None:
    result = scan(tmp_path, "include: other.yml\nimage: ubuntu\n")

    assert result.status == AnalysisStatus.FINDINGS
    assert len(result.findings) == 1
    assert "include files are not resolved" in result.stderr


@pytest.mark.parametrize(
    "source",
    [
        "test: [",
        "- not-a-mapping",
        "image: 123\n",
        "image: {entrypoint: []}\n",
        "image: ubuntu\nimage: alpine\n",
        "test:\n  services: redis\n",
        "!!python/object/apply:os.system ['false']",
        "image: &recursive {name: *recursive}",
    ],
)
def test_invalid_inputs_produce_cli_error(tmp_path: Path, source: str) -> None:
    (tmp_path / ".gitlab-ci.yml").write_text(source)

    result = CliRunner().invoke(
        app,
        [
            "static-analysis",
            "--path",
            str(tmp_path),
            "--provider",
            "gitlab",
        ],
    )

    assert result.exit_code == 2
    assert "Traceback" not in result.output


def test_clean_offline_cli(tmp_path: Path) -> None:
    (tmp_path / ".gitlab-ci.yml").write_text(f"image: ubuntu@{DIGEST}\n")

    result = CliRunner().invoke(
        app,
        [
            "static-analysis",
            "--path",
            str(tmp_path),
            "--provider",
            "gitlab",
        ],
    )

    assert result.exit_code == 0
    assert "equivalent: zizmor/unpinned-images@1.32.0" in result.output


@pytest.mark.parametrize("persona", ["regular", "pedantic"])
def test_policy_matches_zizmor_offline(
    tmp_path: Path, persona: Literal["regular", "pedantic"]
) -> None:
    """Compare equivalent declarations against the pinned upstream executable.

    GitHub's opaque vars.IMAGE expression maps to GitLab's $IMAGE. Compare
    identifiers, classification, severity, confidence, and persona per image.
    """
    executable = Path(sys.executable).parent / "zizmor"
    version = subprocess.run(
        [str(executable), "--version"],
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    ).stdout.strip()
    assert version == f"zizmor {UPSTREAM.version}", (
        "Review the upstream mapping on upgrades"
    )
    references = [
        "ubuntu",
        "ubuntu:latest",
        "ubuntu:24.04",
        "registry.example.org:5000/repo",
        "localhost:5000/repo:latest",
        "namespace/repo:tag",
        "ubuntu:",
        f"ubuntu@{DIGEST}",
        f"ubuntu:latest@{DIGEST}",
        "ubuntu@opaque",
        "",
        "$IMAGE",
    ]
    jobs = {}
    gitlab_jobs = {}
    for index, reference in enumerate(references):
        name = f"job-{index}"
        jobs[name] = {
            "runs-on": "ubuntu-latest",
            "container": "${{ vars.IMAGE }}" if reference == "$IMAGE" else reference,
            "steps": [{"run": "echo ok"}],
        }
        gitlab_jobs[name] = {"image": reference, "script": "echo ok"}
    workflow = tmp_path / "workflow.yml"
    workflow.write_text(
        yaml.safe_dump(
            {
                "name": "Image policy parity",
                "on": "push",
                "permissions": {},
                "jobs": jobs,
            }
        )
    )
    process = subprocess.run(
        [
            str(executable),
            "--offline",
            "--no-config",
            "--no-ignores",
            f"--persona={persona}",
            "--format=json",
            str(workflow),
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert process.returncode in {0, 11, 12, 13, 14}, process.stderr
    upstream = {}
    for finding in json.loads(process.stdout):
        if finding["ident"] != "unpinned-images":
            continue
        determination = finding["determinations"]
        if persona == "regular" and determination["persona"] != "Regular":
            continue
        location = finding["locations"][0]["symbolic"]
        job = location["route"]["route"][1]["Key"]
        upstream[job] = (
            location["annotation"],
            determination["severity"].lower(),
            determination["confidence"].lower(),
            determination["persona"].lower(),
        )
    result = scan(tmp_path, yaml.safe_dump(gitlab_jobs), pedantic=persona == "pedantic")
    actual = {
        finding.location.split(".")[0]: (
            finding.message,
            finding.severity,
            finding.confidence,
            finding.persona,
        )
        for finding in result.findings
    }

    assert actual == upstream
