"""GitHub CI/CD scanner adapter; no repository-wide orchestration lives here."""

import json
import os
import subprocess
from collections.abc import Mapping
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path
from tempfile import TemporaryDirectory

import yaml

from nomad_sec_ops.models import (
    AnalysisStatus,
    CheckResult,
    CICDFinding,
    CICDFindingMetadata,
    Finding,
    UpstreamRule,
)
from nomad_sec_ops.scanners.zizmor_catalog import AUDITS, ZIZMOR_COMMIT, ZIZMOR_VERSION


def _zizmor_executable() -> tuple[str, str | None]:
    """Use the installed wheel's executable even when its scripts dir is off PATH."""
    try:
        package = distribution("zizmor")
    except PackageNotFoundError:
        return "zizmor", None
    for file in package.files or ():
        if file.name in {"zizmor", "zizmor.exe"}:
            executable = package.locate_file(file)
            if isinstance(executable, Path) and executable.is_file():
                return str(executable.resolve()), package.version
    return "zizmor", None


def _parse_findings(output: str, directory: Path, version: str | None) -> list[Finding]:
    records = json.loads(output)
    if not isinstance(records, list) or not records:
        raise ValueError("expected a nonempty array of findings")
    catalog = {audit.rule_id: audit for audit in AUDITS}
    findings: list[Finding] = []
    for record in records:
        primary = next(
            (
                item
                for item in record["locations"]
                if item["symbolic"]["kind"] == "Primary"
            ),
            None,
        )
        if primary is None:
            raise ValueError("finding has no primary location")
        symbolic, concrete = primary["symbolic"], primary["concrete"]
        file = Path(symbolic["key"]["Local"]["verbatim_path"]).absolute()
        point = concrete["location"]["start_point"]
        location = ""
        for segment in symbolic["route"]["route"]:
            if "Index" in segment:
                location += f"[{segment['Index']}]"
            else:
                location += f".{segment['Key']}" if location else segment["Key"]

        rule_id = record["ident"]
        audit = catalog.get(rule_id) if version == ZIZMOR_VERSION else None
        documentation_url = record["url"]
        message = record["desc"]
        if symbolic["annotation"] and symbolic["annotation"] != message:
            message += f": {symbolic['annotation']}"
        determinations = record["determinations"]
        fixes = record.get("fixes", [])
        findings.append(
            CICDFinding(
                kind="ci-cd",
                message=message,
                severity=determinations["severity"].lower(),
                metadata=CICDFindingMetadata(
                    rule_id=rule_id,
                    confidence=determinations["confidence"].lower(),
                    persona=determinations["persona"].lower(),
                    file=file.relative_to(directory).as_posix(),
                    line=point["row"] + 1,
                    column=point["column"] + 1,
                    location=location,
                    evidence=concrete["feature"].strip(),
                    remediation=(
                        "; ".join(fix["title"] for fix in fixes)
                        or f"See {documentation_url}"
                    ),
                    upstream=UpstreamRule(
                        tool="zizmor",
                        rule_id=rule_id,
                        version=version,
                        commit=ZIZMOR_COMMIT if audit is not None else None,
                        source_url=audit.source_url if audit is not None else None,
                        documentation_url=documentation_url,
                    ),
                ),
            )
        )
    return findings


def run_zizmor(
    target: str,
    *,
    rule_overrides: Mapping[str, bool] | None = None,
    unpinned_uses_policies: Mapping[str, str] | None = None,
) -> CheckResult:
    executable, version = _zizmor_executable()
    rules: dict[str, dict[str, object]] = {}
    if unpinned_uses_policies:
        rules["unpinned-uses"] = {"config": {"policies": dict(unpinned_uses_policies)}}
    for rule_id, disabled in (rule_overrides or {}).items():
        rules.setdefault(rule_id, {})["disable"] = disabled

    env = os.environ.copy()
    env.pop("ZIZMOR_CONFIG", None)
    with TemporaryDirectory(prefix="nomad-sec-ops-zizmor-") as directory:
        config_path = Path(directory) / "zizmor.yml"
        config_path.write_text(yaml.safe_dump({"rules": rules}), encoding="utf-8")
        result = subprocess.run(
            [
                executable,
                "--quiet",
                "--offline",
                "--format=json-v1",
                "--gh-hostname=github.com",
                "--config",
                str(config_path),
                "--no-ignores",
                "--",
                target,
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    findings: list[Finding] = []
    stdout = result.stdout
    if result.returncode == 0:
        status = AnalysisStatus.PASSED
        message = "zizmor: 0 findings."
    elif result.returncode in {11, 12, 13, 14}:
        status = AnalysisStatus.FINDINGS
        try:
            findings = _parse_findings(result.stdout, Path(target).absolute(), version)
        except (AttributeError, KeyError, TypeError, ValueError) as error:
            status = AnalysisStatus.ERROR
            message = f"Could not read zizmor findings: {error}"
        else:
            count = len(findings)
            message = f"zizmor: {count} {'finding' if count == 1 else 'findings'}."
            stdout = ""
    elif result.returncode == 3:
        status = AnalysisStatus.NOT_EVALUATED
        message = "zizmor not evaluated: no supported inputs were found."
    else:
        status = AnalysisStatus.ERROR
        message = f"zizmor failed with exit code {result.returncode}."
    return CheckResult(
        status=status,
        message=message,
        tool="zizmor",
        stdout=stdout,
        stderr=result.stderr,
        findings=findings,
    )
