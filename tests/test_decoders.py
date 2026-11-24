import io
import struct

import pytest

import wimgen
from wim_nxc import WimError, WimFile
from wim_nxc.reader import LZX_BASE, invalid_wim, lzx_decompress, xpress_decompress

BLOCK_PLANS = {
    "verbatim": (("verbatim",), None),
    "aligned": (("aligned",), None),
    "default-size": (("aligned", "verbatim"), 32768),
    "mixed": (("verbatim", "uncompressed", "aligned"), 4999),
    "uncompressed": (("uncompressed",), 3001),
}


@pytest.mark.parametrize("plan", BLOCK_PLANS)
@pytest.mark.parametrize("seed", range(4))
def test_lzx_round_trip(plan, seed):
    content = wimgen.sample_content(seed, 32768 if seed % 2 else 21111)
    blocks, block_size = BLOCK_PLANS[plan]
    assert lzx_decompress(wimgen.lzx_compress(content, 32768, blocks, block_size), len(content), 15) == content


@pytest.mark.parametrize("window_order", [16, 17, 21])
def test_lzx_larger_windows(window_order):
    content = wimgen.sample_content(window_order, 90000)
    content += content[:20000]  # a match further back than 65536 bytes
    packed = wimgen.lzx_compress(content, 1 << window_order, ("aligned", "verbatim"), 50000)
    assert lzx_decompress(packed, len(content), window_order) == content


@pytest.mark.parametrize(("window_order", "slots"), sorted(wimgen.POSITION_SLOTS.items()))
def test_lzx_position_slots(window_order, slots):
    # The reader derives the slot count from the window size, [MS-PATCH] lists it
    count = 30
    while (1 << window_order) - 3 >= LZX_BASE[count] - 2:
        count += 1
    assert count == slots


@pytest.mark.parametrize("seed", range(4))
def test_xpress_round_trip(seed):
    content = wimgen.sample_content(seed, 32768 if seed % 2 else 21111)
    assert xpress_decompress(wimgen.xpress_compress(content, 32768), len(content)) == content


@pytest.mark.parametrize("size", [17, 18, 19, 272, 273, 274, 1000, 32768])
def test_xpress_long_matches(size):
    # Lengths of 18 and more use a raw byte, 273 and more a raw 16-bit value
    content = b"\x00" + b"x" * (size - 1)
    assert xpress_decompress(wimgen.xpress_compress(content, 32768), size) == content


def uncompressed_chunk(payload):
    writer = wimgen.BitWriter()
    writer.write(3, 3)
    writer.write(0, 1)
    writer.write(len(payload), 16)
    writer.write(0, 12)
    return writer.flush() + struct.pack("<III", 1, 1, 1) + payload + bytes(len(payload) & 1)


@pytest.mark.parametrize(("stored", "expected"), [
    (100, 100 - 16),  # absolute target in range: target - position
    (-10, -10 + 12000000),  # negative target down to -position: target + file size
    (-16, -16 + 12000000),
    (-17, -17),  # below -position: unchanged
    (12000000, 12000000),  # file size and above: unchanged
    (11999999, 11999999 - 16),
])
def test_lzx_e8_translation(stored, expected):
    head, tail = b"\x90" * 16, b"\x90" * 20
    chunk = uncompressed_chunk(head + b"\xe8" + stored.to_bytes(4, "little", signed=True) + tail)
    assert lzx_decompress(chunk, 41, 15) == head + b"\xe8" + expected.to_bytes(4, "little", signed=True) + tail


def test_lzx_e8_in_the_last_ten_bytes_is_left_alone():
    payload = b"\x90" * 30 + b"\xe8" + (100).to_bytes(4, "little") + b"\x90" * 5
    assert lzx_decompress(uncompressed_chunk(payload), len(payload), 15) == payload


@pytest.mark.parametrize("name", wimgen.SYNTH_CASES)
def test_lzx_uncompressed_block_padding(name):
    first_matches, aligned_padding, accepted = wimgen.SYNTH_CASES[name]
    chunk, content, _ = wimgen.synth_chunk(first_matches, aligned_padding)
    wim = WimFile(io.BytesIO(wimgen.build_wim([{"raw.bin": content}], compression=wimgen.LZX, packed={content: chunk})))
    digest = next(digest for _, _, digest in wim.files())
    if accepted:
        assert wim.read(digest) == content
    else:
        with pytest.raises(WimError):
            wim.read(digest)


def test_stored_and_oversized_chunks():
    content = bytes(range(256)) * 128
    # A chunk as large as its output is stored as is
    wim = WimFile(io.BytesIO(wimgen.build_wim([{"a": content}], compression=wimgen.LZX, packed={content: content})))
    assert wim.read(next(digest for _, _, digest in wim.files())) == content
    # A chunk larger than its output is invalid
    wim = WimFile(io.BytesIO(wimgen.build_wim([{"a": content}], compression=wimgen.LZX, packed={content: content + b"x"})))
    with pytest.raises(WimError, match="Invalid WIM chunk"):
        wim.read(next(digest for _, _, digest in wim.files()))


@pytest.mark.parametrize("data", [b"", b"\x00", bytes(256), b"\xff" * 300, bytes(range(256)) * 4])
def test_invalid_chunks_raise_wim_error(data):
    for decompress in (lambda: lzx_decompress(data, 32768, 15), lambda: xpress_decompress(data, 32768)):
        try:
            with invalid_wim():
                assert len(decompress()) == 32768
        except WimError:
            pass
