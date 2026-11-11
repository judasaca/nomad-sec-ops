"""Offline GitLab adaptation of zizmor v1.32.0's unpinned-images audit.

Match the upstream image classification and persona policy. Inspect declarations
rather than resolved jobs; GitLab variables/expressions remain opaque. See
UPSTREAM for the exact source revision and README.md for the scope mapping.
"""

from dataclasses import dataclass
from typing import Literal

from nomad_sec_ops.models import AnalysisStatus, CheckResult, Finding, UpstreamRule
from nomad_sec_ops.scanners.gitlab.context import GitLabContext
from nomad_sec_ops.scanners.gitlab.pipeline import collect_images

UPSTREAM = UpstreamRule(
    tool="zizmor",
    rule_id="unpinned-images",
    version="1.32.0",
    commit="21bd300700d43d9ba04b0c1fce72a89391ac80b4",
    source_url=(
        "https://github.com/zizmorcore/zizmor/blob/"
        "21bd300700d43d9ba04b0c1fce72a89391ac80b4/"
        "crates/zizmor/src/audit/unpinned_images.rs"
    ),
    documentation_url="https://docs.zizmor.sh/audits/#unpinned-images",
)


@dataclass(frozen=True)
class ImageAssessment:
    message: str
    confidence: Literal["low", "high"] = "high"
    persona: Literal["regular", "pedantic"] = "regular"


def classify_image(reference: str) -> ImageAssessment | None:
    """Apply upstream lexical policy, without querying registries or variables.

    Like upstream, a digest suffix is accepted without validating its contents.
    Registry ports must not be mistaken for image tags.
    """
    reference = reference.strip()
    if not reference:
        return None
    if "$" in reference:
        return ImageAssessment("container image may be unpinned", confidence="low")
    first, separator, remainder = reference.partition("/")
    image = (
        remainder
        if separator and (first == "localhost" or "." in first or ":" in first)
        else reference
    )
    if not image or "@" in image:
        return None
    _, separator, tag = image.partition(":")
    if not separator or not tag:
        return ImageAssessment("container image is unpinned")
    if tag == "latest":
        return ImageAssessment("container image uses the floating 'latest' tag")
    return ImageAssessment(
        "container image is not pinned to a SHA256 hash", persona="pedantic"
    )


@dataclass(frozen=True)
class UnpinnedImages:
    name = "unpinned-images"
    upstream = UPSTREAM
    persona: Literal["regular", "pedantic"] = "regular"

    def run(self, context: GitLabContext) -> CheckResult:
        directory = context.target.local_path
        if directory is None:
            return CheckResult(
                status=AnalysisStatus.NOT_EVALUATED,
                message=(
                    "Offline rule requires a local checkout; "
                    "remote content is not fetched."
                ),
            )
        path = directory / ".gitlab-ci.yml"
        if not path.is_file():
            return CheckResult(
                status=AnalysisStatus.NOT_EVALUATED,
                message=f"No .gitlab-ci.yml found in {directory}.",
            )
        pipeline = collect_images(path)
        findings: list[Finding] = []
        for reference in pipeline.references:
            assessment = classify_image(reference.value)
            if assessment is None or (
                assessment.persona == "pedantic" and self.persona == "regular"
            ):
                continue
            findings.append(
                Finding(
                    rule_id=self.name,
                    severity="high",
                    confidence=assessment.confidence,
                    persona=assessment.persona,
                    file=str(path),
                    line=reference.line,
                    column=reference.column,
                    location=reference.location,
                    message=assessment.message,
                    evidence=reference.value,
                    remediation=(
                        "Pin the image to an immutable digest, "
                        "e.g. image@sha256:<digest>."
                    ),
                    upstream=self.upstream,
                )
            )
        status = (
            AnalysisStatus.FINDINGS
            if findings
            else AnalysisStatus.NOT_EVALUATED
            if pipeline.limitations
            else AnalysisStatus.PASSED
        )
        return CheckResult(
            status=status,
            message=(
                f"{len(findings)} finding(s), {self.persona} persona; "
                f"equivalent: zizmor/{self.upstream.rule_id}@{self.upstream.version}."
            ),
            stdout="".join(
                f"{finding.file}:{finding.line}:{finding.column}: "
                f"{finding.severity}[{finding.rule_id}] {finding.message} "
                f"({finding.location}; confidence: {finding.confidence})\n"
                f"  image: {finding.evidence}\n  fix: {finding.remediation}\n"
                for finding in findings
            ),
            stderr="".join(
                f"Not evaluated: {reason}.\n" for reason in pipeline.limitations
            ),
            findings=findings,
        )
