"""Verify the root defaults are shipped as usable package data."""

import shutil
import subprocess
import tarfile
from pathlib import Path
from zipfile import ZipFile

import pytest


def test_default_settings_in_source_distribution_and_wheel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("uv is required to build distributions")
    root = Path(__file__).resolve().parents[1]
    filename = "nomad-sec-ops.yml"
    expected = (root / filename).read_bytes()
    monkeypatch.setenv("UV_CACHE_DIR", str(tmp_path / "cache"))
    dist = tmp_path / "dist"

    subprocess.run(
        [uv, "build", "--offline", "--out-dir", str(dist), str(root)],
        check=True,
        timeout=60,
    )

    with tarfile.open(next(dist.glob("*.tar.gz"))) as source:
        root_settings = next(
            name for name in source.getnames() if name.split("/")[1:] == [filename]
        )
        contents = source.extractfile(root_settings)
        assert contents is not None
        assert contents.read() == expected
    with ZipFile(next(dist.glob("*.whl"))) as wheel:
        assert wheel.read(f"nomad_sec_ops/{filename}") == expected
