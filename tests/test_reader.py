import io
import struct
from hashlib import sha1

import pytest

import wimgen
from conftest import GENERATED, expected_files
from wim_nxc import WimError, WimFile, reader


class RemoteLikeFile:
    """File object shaped like nxc's RemoteFile: seek needs both arguments and read returns short chunks."""

    def __init__(self, data, max_read=4096):
        self.data, self.pos, self.max_read, self.reads, self.closed = data, 0, max_read, [], False

    def seek(self, offset, whence):
        assert whence == 0
        self.pos = offset

    def read(self, size):
        chunk = self.data[self.pos:self.pos + min(size, self.max_read)]
        self.reads.append((self.pos, len(chunk)))
        self.pos += len(chunk)
        return chunk


def build(files, **options):
    return WimFile(io.BytesIO(wimgen.build_wim([files], **options)))


@pytest.mark.parametrize("name", GENERATED)
def test_generated_wims(generated, name):
    path, images = generated[name]
    with WimFile(path) as wim:
        entries = list(wim.files())
        assert {path: wim.read(digest) for path, attributes, digest in entries} == expected_files(images)
    assert not any(attributes & WimFile.FILE_ATTRIBUTE_DIRECTORY for _, attributes, _ in entries)


def test_short_reads_and_seek_with_whence(generated):
    path, images = generated["lzx"]
    file = RemoteLikeFile(path.read_bytes(), max_read=7)
    wim = WimFile(file)
    assert {path: wim.read(digest) for path, _, digest in wim.files()} == expected_files(images)
    assert all(size <= 7 for _, size in file.reads)


def test_listing_reads_only_the_tables(generated):
    path, _ = generated["lzx"]
    file = RemoteLikeFile(path.read_bytes(), max_read=1 << 30)
    wim = WimFile(file)
    entries = list(wim.files())
    data_ranges = [(offset, offset + size) for offset, size, _, flags in wim.blobs.values() if not flags & WimFile.RESOURCE_METADATA]
    xml_offset = struct.unpack_from("<Q", file.data, 80)[0]
    for start, size in file.reads:
        assert not any(start < end and begin < start + size for begin, end in data_ranges)
        assert start + size <= xml_offset
    assert len(file.reads) == 3 + len(wim.images)

    target = next(digest for path, _, digest in entries if path.endswith("Bootstrap.ini"))
    before = len(file.reads)
    wim.read(target)
    offset, size = wim.blobs[target][:2]
    assert file.reads[before:] == [(offset, size)]


def test_multiple_images(generated):
    path, images = generated["multi"]
    with WimFile(path) as wim:
        paths = [path for path, _, _ in wim.files()]
        assert wim.image_names() == ["First", "Second"]
    assert {path.split("\\")[0] for path in paths} == {"1", "2"}
    assert "2\\Deploy\\Control\\Bootstrap.ini" in paths
    assert len(paths) == sum(len(files) for files in images)


def test_single_image_has_no_prefix(generated):
    with WimFile(generated["lzx"][0]) as wim:
        assert "Deploy\\Control\\Bootstrap.ini" in [path for path, _, _ in wim.files()]
        assert wim.image_names() == ["image 1"]


def test_image_names_with_unicode_and_entities():
    names = ["Lite Touch Windows PE (x64)", "Été & co"]
    data = wimgen.build_wim([{"a": b"a"}, {"b": b"b"}], compression=wimgen.LZX, names=["Lite Touch Windows PE (x64)", "Été &amp; co"])
    assert WimFile(io.BytesIO(data)).image_names() == names


def test_image_without_name():
    data = wimgen.build_wim([{"a": b"a"}, {"b": b"b"}], names=["only one"])
    assert WimFile(io.BytesIO(data)).image_names() == ["only one", ""]


def test_empty_file_and_empty_directory():
    wim = build({"empty.txt": b"", "folder\\empty": {}, "folder\\file.txt": b"content"}, compression=wimgen.XPRESS)
    entries = {path: (attributes, digest) for path, attributes, digest in wim.files()}
    assert set(entries) == {"empty.txt", "folder\\file.txt"}
    assert entries["empty.txt"][1] == bytes(20)
    assert wim.read(bytes(20)) == b""


def test_named_streams_and_unnamed_stream_hash():
    files = {
        "split.xml": wimgen.File(b"<unattend/>", streams={"Zone.Identifier": b"[ZoneTransfer]\r\nZoneId=3"}, split=True),
        "plain.xml": wimgen.File(b"<plain/>", streams={"Zone.Identifier": b"[ZoneTransfer]\r\nZoneId=3"}),
    }
    wim = build(files, compression=wimgen.LZX)
    contents = {path: wim.read(digest) for path, _, digest in wim.files()}
    assert contents == {"split.xml": b"<unattend/>", "plain.xml": b"<plain/>"}


def test_attributes_are_passed_through():
    wim = build({"link.xml": wimgen.File(b"target", attributes=0x420)})
    assert [(path, attributes) for path, attributes, _ in wim.files()] == [("link.xml", 0x420)]


def test_missing_blob():
    wim = build({"a": b"a"})
    with pytest.raises(WimError, match="not found"):
        wim.read(b"\x01" * 20)


def test_sha1_mismatch():
    data = bytearray(wimgen.build_wim([{"a.txt": b"original content"}]))
    data[data.index(b"original content")] ^= 1
    wim = WimFile(io.BytesIO(bytes(data)))
    with pytest.raises(WimError, match="SHA-1"):
        wim.read(next(digest for _, _, digest in wim.files()))


def test_not_a_wim():
    with pytest.raises(WimError) as error:
        WimFile(io.BytesIO(bytes(4096)))
    assert str(error.value) == "Not a WIM file"


@pytest.mark.parametrize("size", [0, 10, 100, 300])
def test_truncated(generated, size):
    data = generated["lzx"][0].read_bytes()[:size]
    with pytest.raises(WimError):
        list(WimFile(io.BytesIO(data)).files())


def set_blob_flags(data, digest, flags):
    """Return the WIM with the resource flags of this blob changed in the lookup table."""
    data = bytearray(data)
    entry = data.index(digest, struct.unpack_from("<Q", data, 56)[0]) - 30
    data[entry + 7] = flags
    return bytes(data)


@pytest.mark.parametrize(("flags", "reason"), [(0x08, "spanned"), (0x10, "solid"), (0x14, "solid"), (0x18, "solid")])
def test_spanned_and_solid_resources(flags, reason):
    content = b"x" * 100
    wim = WimFile(io.BytesIO(set_blob_flags(wimgen.build_wim([{"a": content}]), sha1(content).digest(), flags)))
    with pytest.raises(WimError, match=f"Unsupported WIM resource: {reason}"):
        wim.read(sha1(content).digest())


def test_unsupported_compression():
    data = bytearray(wimgen.build_wim([{"a": wimgen.sample_content(1, 5000)}], compression=wimgen.LZX))
    struct.pack_into("<I", data, 16, 0x80002)
    with pytest.raises(WimError, match="Unsupported WIM compression: LZMS"):
        list(WimFile(io.BytesIO(bytes(data))).files())
    struct.pack_into("<I", data, 16, 0x10002)
    with pytest.raises(WimError, match="Unsupported WIM compression: header flags 0x10002"):
        list(WimFile(io.BytesIO(bytes(data))).files())


@pytest.mark.parametrize(("chunk_size", "valid"), [(0, True), (4096, True), (32768, True), (1 << 21, True), (1, False), (1000, False), (2048, False), (1 << 22, False), (0xFFFFFFFF, False)])
def test_chunk_size(chunk_size, valid):
    data = bytearray(wimgen.build_wim([{"a": b"a"}]))
    struct.pack_into("<I", data, 20, chunk_size)
    if valid:
        assert WimFile(io.BytesIO(bytes(data))).chunk_size == (chunk_size or 32768)
    else:
        with pytest.raises(WimError, match=f"Unsupported WIM chunk size: {chunk_size}"):
            WimFile(io.BytesIO(bytes(data)))


def test_resource_size_limit():
    data = bytearray(wimgen.build_wim([{"a": b"a"}]))
    struct.pack_into("<Q", data, 64, WimFile.MAX_RESOURCE_SIZE + 1)
    with pytest.raises(WimError, match="Unsupported WIM resource: larger than 64 MiB"):
        WimFile(io.BytesIO(bytes(data)))


def test_malformed_metadata_raises_wim_error(monkeypatch):
    wim = build({"a\\b": b"b"}, compression=wimgen.LZX)
    original = wim.read
    monkeypatch.setattr(wim, "read", lambda digest: original(digest)[:150] if digest in wim.images else original(digest))
    with pytest.raises(WimError) as error:
        list(wim.files())
    assert isinstance(error.value.__cause__, struct.error)


def test_directory_loop_stops(monkeypatch):
    wim = build({"a\\b\\c.txt": b"c", "d.txt": b"d"})
    original = wim.read

    def loop(digest):
        data = original(digest)
        if digest not in wim.images:
            return data
        # Point every directory back to the list of the root
        data, root_list = bytearray(data), struct.unpack_from("<Q", data, 24)[0]
        offset = 8
        while offset < len(data) - 8:
            length = struct.unpack_from("<Q", data, offset)[0]
            if length > 8 and struct.unpack_from("<I", data, offset + 8)[0] & 0x10 and offset != 8:
                struct.pack_into("<Q", data, offset + 16, root_list)
            offset += max(8, (length + 7) & ~7)
        return bytes(data)

    monkeypatch.setattr(wim, "read", loop)
    assert sorted(path for path, _, _ in wim.files()) == ["d.txt"]


def test_open_path_and_close(tmp_path, monkeypatch):
    path = tmp_path / "test.wim"
    path.write_bytes(wimgen.build_wim([{"a.txt": b"a"}]))
    opened = []

    def recording_open(*args, **kwargs):
        opened.append(open(*args, **kwargs))  # ruff: ignore[open-file-with-context-handler]
        return opened[-1]

    monkeypatch.setattr(reader, "open", recording_open, raising=False)
    with WimFile(path) as wim:
        assert [path for path, _, _ in wim.files()] == ["a.txt"]
        assert not opened[0].closed
    assert opened[0].closed

    path.write_bytes(b"not a wim" * 10)
    with pytest.raises(WimError):
        WimFile(str(path))
    assert opened[1].closed


def test_file_object_stays_open(generated):
    file = io.BytesIO(generated["lzx"][0].read_bytes())
    with WimFile(file):
        pass
    assert not file.closed


def test_wim_error_is_a_value_error():
    assert issubclass(WimError, ValueError)
