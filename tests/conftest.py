import os
import shutil
import signal
import subprocess
from contextlib import contextmanager
from pathlib import Path

import pytest

import wimgen

SEVEN_ZIP = shutil.which("7z") or shutil.which("7zz")
SAMPLES = Path(os.environ["WIM_SAMPLES"]) if os.environ.get("WIM_SAMPLES") else None
FUZZ_CASES = int(os.environ.get("WIM_FUZZ_CASES", "300"))
needs_7z = pytest.mark.skipif(not SEVEN_ZIP, reason="7-Zip is not installed")
needs_alarm = pytest.mark.skipif(not hasattr(signal, "setitimer"), reason="needs signal.setitimer for the time limit")


class Timeout(BaseException):
    pass


@contextmanager
def time_limit(seconds):
    """Interrupt the block with Timeout after this many seconds (POSIX only)."""
    def expire(signum, frame):
        raise Timeout

    previous = signal.signal(signal.SIGALRM, expire)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def extract_7z(path, out):
    """Extract a WIM with 7-Zip and return the process result."""
    return subprocess.run([SEVEN_ZIP, "x", "-y", "-snl-", f"-o{out}", str(path)], capture_output=True, text=True, check=False)


def sample_files():
    """A small tree with nested directories, an empty file and files the nxc module looks for."""
    files = {f"Windows\\System32\\file{index}.bin": wimgen.sample_content(index, 500 + index * 7000) for index in range(8)}
    files["Deploy\\Control\\Bootstrap.ini"] = b"[Settings]\r\nPriority=Default\r\n\r\n[Default]\r\nUserID=deploy\r\nUserPassword=P@ssw0rd\r\n"
    files["Windows\\Panther\\unattend.xml"] = b"<unattend>" + b"<settings/>" * 400 + b"</unattend>"
    files["big.bin"] = wimgen.sample_content(99, 150000)
    files["empty.txt"] = b""
    return files


# Generated WIMs: the images, then the build_wim options
GENERATED = {
    "lzx": ([sample_files()], {"compression": wimgen.LZX}),
    "lzx-mixed": ([sample_files()], {"compression": wimgen.LZX, "blocks": ("verbatim", "uncompressed", "aligned"), "block_size": 7000}),
    "lzx-aligned": ([sample_files()], {"compression": wimgen.LZX, "blocks": ("aligned", "verbatim"), "block_size": 32768}),
    "lzx-64k": ([sample_files()], {"compression": wimgen.LZX, "chunk_size": 65536, "blocks": ("aligned", "verbatim"), "block_size": 40000}),
    "lzx-tables": ([sample_files()], {"compression": wimgen.LZX, "compress_tables": True}),
    "xpress": ([sample_files()], {"compression": wimgen.XPRESS}),
    "none": ([sample_files()], {"compression": 0}),
    "multi": ([sample_files(), {"second.txt": b"second image", "Deploy\\Control\\Bootstrap.ini": b"[Settings]\r\n"}], {"compression": wimgen.LZX, "names": ["First", "Second"]}),
}


@pytest.fixture(scope="session")
def generated(tmp_path_factory):
    """Write every generated WIM once per session and return {name: (path, images)}."""
    folder = tmp_path_factory.mktemp("generated")
    wims = {}
    for name, (images, options) in GENERATED.items():
        path = folder / f"{name}.wim"
        path.write_bytes(wimgen.build_wim(images, **options))
        wims[name] = (path, images)
    return wims


def expected_files(images):
    """Map every path the reader should yield to its content."""
    return {(f"{number}\\{path}" if len(images) > 1 else path): content for number, files in enumerate(images, 1) for path, content in files.items()}
