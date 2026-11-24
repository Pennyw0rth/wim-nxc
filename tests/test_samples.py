"""
Checks against WIM files made by Windows DISM.

These samples hold Microsoft binaries and are never committed. Set
WIM_SAMPLES to the folder that holds them to run these tests.
"""

import subprocess
from pathlib import PureWindowsPath

import pytest

from conftest import SAMPLES, SEVEN_ZIP, extract_7z, needs_7z
from wim_nxc import WimError, WimFile

pytestmark = pytest.mark.skipif(SAMPLES is None, reason="set WIM_SAMPLES to the folder of the DISM-made samples")
PATTERNS = ("Bootstrap.ini", "CustomSettings.ini", "*unattend*.xml")


def samples(pattern):
    return sorted(SAMPLES.glob(pattern)) if SAMPLES else []


class CountingFile:
    def __init__(self, path):
        self.file, self.bytes, self.reads = open(path, "rb"), 0, 0  # ruff: ignore[open-file-with-context-handler]

    def seek(self, offset, whence):
        self.file.seek(offset, whence)

    def read(self, size):
        data = self.file.read(size)
        self.bytes += len(data)
        self.reads += 1
        return data


@needs_7z
@pytest.mark.parametrize("path", samples("test-*.wim"), ids=lambda path: path.name)
def test_dism_sample_matches_7z(path, tmp_path):
    result = extract_7z(path, tmp_path)
    assert result.returncode == 0, result.stdout
    with WimFile(path) as wim:
        entries = list(wim.files())
        for name, attributes, digest in entries:
            data = wim.read(digest)
            # 7-Zip keeps reparse points as links, wimcheck.py skips them too
            if not attributes & 0x400:
                assert (tmp_path / name.replace("\\", "/")).read_bytes() == data, name
    assert len(entries) >= 3000


@needs_7z
@pytest.mark.parametrize("path", samples("synth-*.wim"), ids=lambda path: path.name)
def test_synth_sample_matches_7z(path, tmp_path):
    """The reader and 7-Zip accept and reject the same hand-made LZX chunks."""
    result = extract_7z(path, tmp_path)
    with WimFile(path) as wim:
        try:
            content = wim.read(next(digest for _, _, digest in wim.files()))
        except WimError:
            content = None
    assert (content is not None) == (result.returncode == 0)
    if content is not None:
        assert (tmp_path / "raw.bin").read_bytes() == content


def test_multi_image_names():
    with WimFile(SAMPLES / "test-multi.wim") as wim:
        assert wim.image_names() == ["wimtest", "second"]
        assert {path.split("\\")[0] for path, _, _ in wim.files()} == {"1", "2"}


@pytest.mark.skipif(not SAMPLES or not (SAMPLES / "litetouch.wim").is_file(), reason="litetouch.wim is not in WIM_SAMPLES")
def test_litetouch_settings(tmp_path):
    """Listing the 384 MB WinPE image reads about 1.4 MB, then only the matching files are read."""
    file = CountingFile(SAMPLES / "litetouch.wim")
    wim = WimFile(file)
    assert wim.image_names() == ["Microsoft Windows Recovery Environment (x64)"]
    matches = [(path, digest) for path, attributes, digest in wim.files() if not attributes & 0x400 and any(PureWindowsPath(path).match(pattern) for pattern in PATTERNS)]
    assert file.bytes < 2 * 1024 * 1024
    assert [path for path, _ in matches] == ["Unattend.xml", "Deploy\\Scripts\\Bootstrap.ini"]
    if SEVEN_ZIP:
        subprocess.run([SEVEN_ZIP, "x", "-y", f"-o{tmp_path}", str(SAMPLES / "litetouch.wim"), "Unattend.xml", "Deploy/Scripts/Bootstrap.ini"], capture_output=True, check=True)
        for path, digest in matches:
            assert (tmp_path / path.replace("\\", "/")).read_bytes() == wim.read(digest)
