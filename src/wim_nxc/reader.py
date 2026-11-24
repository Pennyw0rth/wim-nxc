import os
import struct
from contextlib import contextmanager
from hashlib import sha1
from itertools import accumulate
from xml.etree import ElementTree as ET

LZX_EXTRA_BITS = [min(17, max(0, slot // 2 - 1)) for slot in range(51)]
LZX_BASE = [0, *accumulate(1 << bits for bits in LZX_EXTRA_BITS)]


class WimError(ValueError):
    """Raised when the input is not a valid WIM file or uses an unsupported feature."""


@contextmanager
def invalid_wim():
    """Raise the errors caused by malformed input as WimError."""
    try:
        yield
    except WimError:
        raise
    except (ValueError, IndexError, OverflowError, struct.error, ET.ParseError) as e:
        raise WimError(f"Invalid WIM file ({type(e).__name__}: {e})") from e


class BitReader:
    """MSB-first bit reader over 16-bit little-endian words, as used by LZX and XPRESS."""

    def __init__(self, data, pos=0):
        self.data = data
        self.pos = pos
        self.buffer = 0
        self.left = 0

    def ensure(self, count):
        while self.left < count:
            self.buffer = (self.buffer << 16) | int.from_bytes(self.data[self.pos:self.pos + 2], "little")
            self.pos += 2
            self.left += 16

    def peek(self, count):
        self.ensure(count)
        return self.buffer >> (self.left - count)

    def skip(self, count):
        self.left -= count
        self.buffer &= (1 << self.left) - 1

    def read(self, count):
        value = self.peek(count)
        self.skip(count)
        return value


def huffman_table(lengths):
    """Build a canonical Huffman lookup table indexed by the next max(lengths) bits."""
    width = max(lengths)
    table, pos = [None] * (1 << width), 0
    for length, symbol in sorted((length, symbol) for symbol, length in enumerate(lengths) if length):
        count = 1 << (width - length)
        if pos + count > len(table):
            raise WimError("Invalid Huffman code")
        table[pos:pos + count] = [(symbol, length)] * count
        pos += count
    return table, width


def huffman_decode(bits, code):
    entry = code[0][bits.peek(code[1])]
    if entry is None:
        raise WimError("Invalid Huffman symbol")
    bits.skip(entry[1])
    return entry[0]


def copy_match(out, offset, length):
    if not 0 < offset <= len(out):
        raise WimError("Invalid match offset")
    start = len(out) - offset
    out += out[start:start + length] if offset >= length else (out[start:] * (length // offset + 1))[:length]


def xpress_decompress(data, size):
    """XPRESS Huffman ([MS-XCA] LZ77+Huffman) with one Huffman table per chunk."""
    code = huffman_table([nibble for byte in data[:256] for nibble in (byte & 15, byte >> 4)])
    bits, out = BitReader(data, 256), bytearray()
    # The bit buffer always holds at least 16 bits, which fixes where the raw length bytes sit
    bits.ensure(32)
    while len(out) < size:
        symbol = huffman_decode(bits, code)
        bits.ensure(16)
        if symbol < 256:
            out.append(symbol)
            continue
        length, offset_bits = symbol & 15, (symbol >> 4) & 15
        if length == 15:
            # Longer lengths follow as a raw byte, then as 16 bits when that byte is 255
            length += data[bits.pos]
            bits.pos += 1
            if length == 270:
                length = int.from_bytes(data[bits.pos:bits.pos + 2], "little")
                bits.pos += 2
        offset = (1 << offset_bits) | bits.read(offset_bits)
        bits.ensure(16)
        copy_match(out, offset, length + 3)
    return out[:size]


def lzx_read_lengths(bits, lengths, start, end):
    """Update lengths[start:end] from the pretree-coded deltas of a block header."""
    pretree = huffman_table([bits.read(4) for _ in range(20)])
    while start < end:
        symbol = huffman_decode(bits, pretree)
        if symbol == 17:
            run, value = 4 + bits.read(4), 0
        elif symbol == 18:
            run, value = 20 + bits.read(5), 0
        elif symbol == 19:
            run = 4 + bits.read(1)
            value = (lengths[start] - huffman_decode(bits, pretree)) % 17
        else:
            run, value = 1, (lengths[start] - symbol) % 17
        run = min(run, end - start)
        lengths[start:start + run] = [value] * run
        start += run


def lzx_decompress(data, size, window_order):
    """
    LZX ([MS-PATCH]) as stored in WIM chunks.

    There is no stream header, the state is reset for every chunk and the
    x86 E8 translation is always on.
    """
    slots = 30
    while (1 << window_order) - 3 >= LZX_BASE[slots] - 2:
        slots += 1
    main_lengths, length_lengths, recent = [0] * (256 + 8 * slots), [0] * 249, [1, 1, 1]
    bits, out = BitReader(data), bytearray()
    while len(out) < size:
        block_type = bits.read(3)
        block_size = 32768 if bits.read(1) else bits.read(16 if window_order < 16 else 24)
        block_end = min(len(out) + block_size, size)
        if block_type == 3:
            # Uncompressed block: skip 1 to 16 padding bits, then give back the words read ahead
            bits.read(bits.left % 16 or 16)
            bits.pos -= bits.left // 8
            bits.left = bits.buffer = 0
            recent = list(struct.unpack_from("<III", data, bits.pos))
            out += data[bits.pos + 12:bits.pos + 12 + block_size]
            bits.pos += 12 + block_size + (block_size & 1)
            continue
        if block_type not in (1, 2):
            raise WimError("Invalid LZX block type")
        aligned = huffman_table([bits.read(3) for _ in range(8)]) if block_type == 2 else None
        lzx_read_lengths(bits, main_lengths, 0, 256)
        lzx_read_lengths(bits, main_lengths, 256, len(main_lengths))
        lzx_read_lengths(bits, length_lengths, 0, 249)
        main_code, length_code = huffman_table(main_lengths), huffman_table(length_lengths)
        while len(out) < block_end:
            symbol = huffman_decode(bits, main_code)
            if symbol < 256:
                out.append(symbol)
                continue
            length, slot = symbol & 7, (symbol - 256) >> 3
            if length == 7:
                length += huffman_decode(bits, length_code)
            if slot < 3:
                offset = recent[slot]
                recent[slot] = recent[0]
            else:
                extra = LZX_EXTRA_BITS[slot]
                if aligned and extra >= 3:
                    offset = (bits.read(extra - 3) << 3) + huffman_decode(bits, aligned)
                else:
                    offset = bits.read(extra)
                offset += LZX_BASE[slot] - 2
                recent[1:] = recent[:2]
            recent[0] = offset
            copy_match(out, offset, length + 2)

    # Undo the x86 CALL (E8) translation, WIM uses a fixed file size of 12000000
    del out[size:]
    pos = out.find(0xE8)
    while 0 <= pos < size - 10:
        target = int.from_bytes(out[pos + 1:pos + 5], "little", signed=True)
        if -pos <= target < 12000000:
            out[pos + 1:pos + 5] = (target - pos if target >= 0 else target + 12000000).to_bytes(4, "little", signed=True)
        pos = out.find(0xE8, pos + 5)
    return out


class WimFile:
    """
    Read-only WIM reader over a local path or a seekable file object.

    Lists the files of every image and extracts them by SHA-1, reading only
    the lookup table, the image metadata and the requested files. A file
    object only needs seek(offset, 0) and read(size), and read may return
    fewer bytes than asked.
    """

    MAGIC = b"MSWIM\x00\x00\x00"
    COMPRESS_XPRESS = 0x20000
    COMPRESS_LZX = 0x40000
    COMPRESS_LZMS = 0x80000
    RESOURCE_METADATA = 0x02
    RESOURCE_COMPRESSED = 0x04
    RESOURCE_SPANNED = 0x08
    RESOURCE_SOLID = 0x10
    FILE_ATTRIBUTE_DIRECTORY = 0x10
    MIN_CHUNK_SIZE = 1 << 12
    MAX_CHUNK_SIZE = 1 << 21
    MAX_RESOURCE_SIZE = 64 * 1024 * 1024

    def __init__(self, file):
        self.owned = isinstance(file, (str, os.PathLike))
        self.file = open(file, "rb") if self.owned else file  # ruff: ignore[open-file-with-context-handler]
        try:
            with invalid_wim():
                magic, self.flags, chunk_size = struct.unpack("<8s8xII", self.read_at(0, 24))
                if magic != self.MAGIC:
                    raise WimError("Not a WIM file")
                self.chunk_size = chunk_size or 32768
                if self.chunk_size & (self.chunk_size - 1) or not self.MIN_CHUNK_SIZE <= self.chunk_size <= self.MAX_CHUNK_SIZE:
                    raise WimError(f"Unsupported WIM chunk size: {self.chunk_size}")

                lookup = self.read_resource(*self.read_descriptor(48))
                self.blobs, self.images = {}, []
                for size, offset, original_size, digest in struct.iter_unpack("<QQQ6x20s", lookup[:len(lookup) - len(lookup) % 50]):
                    self.blobs[digest] = (offset, size & 0xFFFFFFFFFFFFFF, original_size, size >> 56)
                    if size >> 56 & self.RESOURCE_METADATA:
                        self.images.append(digest)
        except BaseException:
            self.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.close()

    def close(self):
        """Close the file if WimFile opened it from a path, a file object stays open."""
        if self.owned:
            self.file.close()

    def read_at(self, offset, size):
        self.file.seek(offset, 0)
        data = bytearray()
        while len(data) < size:
            chunk = self.file.read(size - len(data))
            if not chunk:
                raise WimError("Truncated WIM file")
            data += chunk
        return bytes(data)

    def read_descriptor(self, offset):
        """Return (offset, size, original size, flags) of the resource described in the header at this offset."""
        size, resource_offset, original_size = struct.unpack("<QQQ", self.read_at(offset, 24))
        return resource_offset, size & 0xFFFFFFFFFFFFFF, original_size, size >> 56

    def decompress(self, data, size):
        if self.flags & self.COMPRESS_LZX:
            return lzx_decompress(data, size, self.chunk_size.bit_length() - 1)
        if self.flags & self.COMPRESS_XPRESS:
            return xpress_decompress(data, size)
        raise WimError("Unsupported WIM compression: LZMS" if self.flags & self.COMPRESS_LZMS else f"Unsupported WIM compression: header flags {self.flags:#x}")

    def read_resource(self, offset, size, original_size, flags):
        if flags & self.RESOURCE_SOLID:
            raise WimError("Unsupported WIM resource: solid (ESD)")
        if flags & self.RESOURCE_SPANNED:
            raise WimError("Unsupported WIM resource: spanned")
        if max(size, original_size) > self.MAX_RESOURCE_SIZE:
            raise WimError(f"Unsupported WIM resource: larger than {self.MAX_RESOURCE_SIZE >> 20} MiB")
        if not flags & self.RESOURCE_COMPRESSED or not original_size:
            return self.read_at(offset, original_size)

        # Chunk table (offset of every chunk but the first), then the chunks
        data = self.read_at(offset, size)
        chunks = -(-original_size // self.chunk_size)
        table = 4 * (chunks - 1)
        offsets = [table + value for value in (0, *struct.unpack_from(f"<{chunks - 1}I", data), size - table)]
        out = bytearray()
        for index in range(chunks):
            chunk, chunk_size = data[offsets[index]:offsets[index + 1]], min(self.chunk_size, original_size - len(out))
            if not 0 < len(chunk) <= chunk_size:
                raise WimError("Invalid WIM chunk")
            # A chunk that does not shrink is stored as is
            out += chunk if len(chunk) == chunk_size else self.decompress(chunk, chunk_size)
        return bytes(out)

    def read(self, digest):
        """
        Return the content of the blob with this SHA-1.

        The all-zero hash of an empty file gives empty bytes. Raises WimError
        when the blob is missing or its content does not match the hash.
        """
        if not any(digest):
            return b""
        if digest not in self.blobs:
            raise WimError("WIM content not found")
        with invalid_wim():
            data = self.read_resource(*self.blobs[digest])
        if sha1(data).digest() != digest:
            raise WimError("WIM content does not match its SHA-1")
        return data

    def files(self):
        """
        Yield (path, attributes, SHA-1) for every file of every image.

        Paths use backslashes and start with the image number when the WIM
        holds several images. Directories are not yielded.
        """
        with invalid_wim():
            for number, image in enumerate(self.images, 1):
                data = self.read(image)
                # The root directory entry follows the security data, both 8-byte aligned
                root = (max(struct.unpack_from("<I", data)[0], 8) + 7) & ~7
                pending, seen = [(f"{number}\\" if len(self.images) > 1 else "", struct.unpack_from("<Q", data, root + 16)[0])], set()
                while pending:
                    parent, offset = pending.pop()
                    # A directory ends with an entry of at most 8 bytes; seen stops loops in a crafted tree
                    while offset and offset not in seen and (length := struct.unpack_from("<Q", data, offset)[0]) > 8:
                        seen.add(offset)
                        attributes, subdir, digest, streams, name_size = struct.unpack_from("<8xI4xQ40x20s12xH2xH", data, offset)
                        path = parent + data[offset + 102:offset + 102 + name_size].decode("utf-16-le", "replace")
                        offset += (length + 7) & ~7
                        for _ in range(streams):
                            stream_length, stream_digest, stream_name_size = struct.unpack_from("<Q8x20sH", data, offset)
                            if stream_length < 38:
                                raise WimError("Invalid WIM stream entry")
                            # With named streams, the unnamed one can be stored here instead
                            if not stream_name_size and not any(digest):
                                digest = stream_digest
                            offset += (stream_length + 7) & ~7
                        if attributes & self.FILE_ATTRIBUTE_DIRECTORY:
                            pending.append((f"{path}\\", subdir))
                        else:
                            yield path, attributes, digest

    def image_names(self):
        """
        Return the name of every image, in image order, from the XML data.

        The XML data is only read by this method. An image without a name
        gives an empty string.
        """
        with invalid_wim():
            images = ET.fromstring(self.read_resource(*self.read_descriptor(72))).iter("IMAGE")
            names = {image.get("INDEX"): image.findtext("NAME", "") for image in images}
        return [names.get(str(number), "") for number in range(1, len(self.images) + 1)]
