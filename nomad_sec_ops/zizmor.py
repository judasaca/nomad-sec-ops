"""Execute the GitHub security rule without executing repository code."""

import subprocess


def run_zizmor(target: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["zizmor", "--format=plain", "--gh-hostname=github.com", "--", target],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )


def exit_code(scanner_code: int) -> int:
    """Translate zizmor's severity and error codes to the CLI contract."""
    if scanner_code == 0:
        return 0
    if scanner_code in {11, 12, 13, 14}:
        return 1
    if scanner_code == 3:
        return 3
    return 2
