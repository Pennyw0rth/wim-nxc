"""
Fuzzers with fixed seeds, from tools/fuzz.py and tools/fuzzchunks.py.

Every case must end with a result or a WimError, within a time limit.
WIM_FUZZ_CASES sets the number of cases per WIM; the DISM samples are added
to the corpus when WIM_SAMPLES is set.
"""

import io
import random
import struct
from collections import Counter
from pathlib import PureWindowsPath

import pytest

from conftest import FUZZ_CASES, SAMPLES, Timeout, needs_alarm, time_limit
from wim_nxc import WimError, WimFile
from wim_nxc.reader import invalid_wim

pytestmark = needs_alarm
PATTERNS = ("Bootstrap.ini", "CustomSettings.ini", "*unattend*.xml")
EVIL = [0, 1, 7, 8, 9, 38, 101, 102, 0x7FFF, 0x8000, 0xFFFF, 0x7FFFFFFF, 0xFFFFFFFF, 0x100000000, 0x7FFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF]
CORPUS = ["lzx", "lzx-mixed", "xpress", "none", "multi"]
SAMPLE_CORPUS = [path.name for path in sorted(SAMPLES.glob("test-*.wim"))] if SAMPLES else []


def corpus(generated, name):
    return (SAMPLES / name).read_bytes() if name.endswith(".wim") else generated[name][0].read_bytes()


def like_module(data, metadata_patch=None):
    """Open, list and read the files the nxc wds_mdt module looks for."""
    wim = WimFile(io.BytesIO(data))
    if metadata_patch:
        original = wim.read
        wim.read = lambda digest: metadata_patch(original(digest)) if digest in wim.images else original(digest)
    found = 0
    for name, attributes, digest in wim.files():
        if attributes & 0x400 or not any(PureWindowsPath(name).match(pattern) for pattern in PATTERNS):
            continue
        wim.read(digest)
        found += 1
    return found


def mutate(buffer, start, end, rng):
    for _ in range(rng.randint(1, 6)):
        pos = rng.randrange(start, end)
        if rng.random() < 0.5:
            buffer[pos] = rng.randrange(256)
        else:
            width = rng.choice((2, 4, 8))
            pos = min(pos, len(buffer) - width)
            buffer[pos:pos + width] = (rng.choice(EVIL) & ((1 << 8 * width) - 1)).to_bytes(width, "little")


@pytest.mark.parametrize("name", CORPUS + SAMPLE_CORPUS)
def test_fuzz_wim(generated, name):
    clean = corpus(generated, name)
    rng = random.Random(1)
    wim = WimFile(io.BytesIO(clean))
    lookup_size, lookup_offset = struct.unpack_from("<QQ", clean, 48)
    lookup_size &= 0xFFFFFFFFFFFFFF
    meta_offset, meta_size = wim.blobs[wim.images[0]][:2]
    matched = [wim.blobs[digest][:2] for path, attributes, digest in wim.files() if not attributes & 0x400 and any(PureWindowsPath(path).match(pattern) for pattern in PATTERNS)]
    assert matched
    results = Counter()
    for _ in range(FUZZ_CASES):
        kind = rng.choice(("header", "lookup", "metadata", "matched", "anywhere", "dentries"))
        data, patch = bytearray(clean), None
        if kind == "header":
            mutate(data, 0, 208, rng)
        elif kind == "lookup":
            mutate(data, lookup_offset, lookup_offset + lookup_size, rng)
        elif kind == "metadata":
            mutate(data, meta_offset, meta_offset + meta_size, rng)
        elif kind == "matched":
            offset, size = rng.choice(matched)
            mutate(data, offset, offset + size, rng)
        elif kind == "anywhere":
            mutate(data, 0, len(data), rng)
        else:
            def patch(metadata, rng=rng):
                metadata = bytearray(metadata)
                mutate(metadata, 0, len(metadata), rng)
                return bytes(metadata)
        try:
            with time_limit(30):
                like_module(bytes(data), patch)
            results[f"{kind} ok"] += 1
        except WimError:
            results[f"{kind} WimError"] += 1
        except (Exception, Timeout) as e:
            results[f"{kind} {type(e).__name__}"] += 1
    assert all(key.endswith((" ok", " WimError")) for key in results), results


@pytest.mark.parametrize("name", CORPUS + SAMPLE_CORPUS)
def test_fuzz_chunks(generated, name):
    clean = corpus(generated, name)
    wim = WimFile(io.BytesIO(clean))
    chunks, original = [], wim.decompress
    wim.decompress = lambda data, size: chunks.append((bytes(data), size)) or original(data, size)
    for _, _, digest in list(wim.files()):
        wim.read(digest)
    if not chunks:
        pytest.skip("uncompressed WIM")
    rng = random.Random(11)
    results = Counter()
    for _ in range(3 * FUZZ_CASES):
        data, size = rng.choice(chunks)
        data = bytearray(data)
        mode = rng.choice(("flip", "flip", "truncate", "zeros", "ones", "random", "splice"))
        if mode == "flip":
            for _ in range(rng.randint(1, 8)):
                data[rng.randrange(len(data))] = rng.randrange(256)
        elif mode == "truncate":
            del data[rng.randrange(len(data)):]
        elif mode == "zeros":
            start = rng.randrange(len(data))
            data[start:start + rng.randint(1, 4096)] = bytes(rng.randint(1, 4096))
        elif mode == "ones":
            start = rng.randrange(len(data))
            data[start:] = b"\xff" * (len(data) - start)
        elif mode == "random":
            data = bytearray(rng.randbytes(rng.randint(1, 32768)))
        else:
            other = rng.choice(chunks)[0]
            cut = rng.randrange(len(data))
            data[cut:] = other[rng.randrange(len(other)):]
        try:
            with time_limit(20), invalid_wim():
                out = original(bytes(data), size)
            results["returned" if len(out) == size else "wrong size"] += 1
        except WimError:
            results["WimError"] += 1
        except (Exception, Timeout) as e:
            results[type(e).__name__] += 1
    assert set(results) <= {"returned", "WimError"}, results
