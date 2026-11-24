"""
Build WIM files for the tests.

The LZX and XPRESS encoders are written from [MS-PATCH] and [MS-XCA] and
only aim at producing valid streams that exercise every decoder path: greedy
LZ77 matching, Huffman code lengths from symbol counts, configurable LZX
block types and sizes. When 7-Zip is installed, the tests check that it
extracts these WIMs to the same content, so the encoders do not only agree
with the reader.
"""

import heapq
import random
import struct
from bisect import bisect_right
from dataclasses import dataclass, field
from hashlib import sha1
from itertools import accumulate, cycle

LZX = 0x40000
XPRESS = 0x20000
EXTRA_BITS = [min(17, max(0, slot // 2 - 1)) for slot in range(51)]
POSITION_BASE = [0, *accumulate(1 << bits for bits in EXTRA_BITS)]
# Number of LZX position slots for each window order, from [MS-PATCH]
POSITION_SLOTS = {15: 30, 16: 32, 17: 34, 18: 36, 19: 38, 20: 42, 21: 50}


class BitWriter:
    """MSB-first bit writer into 16-bit little-endian words."""

    def __init__(self):
        self.out, self.acc, self.count = bytearray(), 0, 0

    def write(self, value, bits):
        self.acc = (self.acc << bits) | (value & ((1 << bits) - 1))
        self.count += bits
        while self.count >= 16:
            self.count -= 16
            self.out += (self.acc >> self.count & 0xFFFF).to_bytes(2, "little")
        self.acc &= (1 << self.count) - 1

    def flush(self):
        self.write(0, -self.count % 16)
        return bytes(self.out)


def code_lengths(counts, limit):
    """Huffman code lengths for these symbol counts, all equal when the tree is deeper than limit."""
    used = [symbol for symbol, count in enumerate(counts) if count]
    lengths = [0] * len(counts)
    if len(used) == 1:
        lengths[used[0]] = 1
        return lengths
    heap = [(counts[symbol], [symbol]) for symbol in used]
    heapq.heapify(heap)
    while len(heap) > 1:
        first, second = heapq.heappop(heap), heapq.heappop(heap)
        for symbol in first[1] + second[1]:
            lengths[symbol] += 1
        heapq.heappush(heap, (first[0] + second[0], first[1] + second[1]))
    if max(lengths, default=0) > limit:
        flat = max(1, (len(used) - 1).bit_length())
        lengths = [flat if count else 0 for count in counts]
    return lengths


def canonical_codes(lengths):
    """Map each symbol to its (code, length) in the canonical Huffman code."""
    codes, code, previous = {}, 0, 0
    for length, symbol in sorted((length, symbol) for symbol, length in enumerate(lengths) if length):
        code <<= length - previous
        codes[symbol] = (code, length)
        code, previous = code + 1, length
    return codes


def lz77(data, ends, min_length, max_length, max_offset):
    """Greedy LZ77: one token list per block ending at each of ends, a token is a byte or (offset, length)."""
    chains, blocks, pos = {}, [], 0
    for end in ends:
        tokens = []
        while pos < end:
            best_offset, best_length = 0, 0
            for candidate in reversed(chains.get(data[pos:pos + 3], ())):
                if pos - candidate > max_offset:
                    break
                limit, length = min(max_length, end - pos), 0
                while length < limit and data[candidate + length] == data[pos + length]:
                    length += 1
                if length > best_length:
                    best_offset, best_length = pos - candidate, length
            step = best_length if best_length >= min_length else 1
            tokens.append((best_offset, best_length) if step > 1 else data[pos])
            for index in range(pos, pos + step):
                chain = chains.setdefault(data[index:index + 3], [])
                chain.append(index)
                del chain[:-8]
            pos += step
        blocks.append(tokens)
    return blocks


def e8_translate(data):
    """Forward x86 CALL translation applied by an LZX encoder, WIM style (file size 12000000, positions in the chunk)."""
    out = bytearray(data)
    pos = out.find(0xE8)
    while 0 <= pos < len(out) - 10:
        value = int.from_bytes(out[pos + 1:pos + 5], "little", signed=True)
        if -pos <= value < 12000000:
            value = value + pos if value < 12000000 - pos else value - 12000000
            out[pos + 1:pos + 5] = value.to_bytes(4, "little", signed=True)
        pos = out.find(0xE8, pos + 5)
    return bytes(out)


def lzx_write_lengths(writer, previous, lengths, start, end):
    """Write lengths[start:end] as pretree-coded deltas from previous[start:end], then update previous."""
    items, index = [], start
    while index < end:
        run = 1
        while index + run < end and lengths[index + run] == lengths[index]:
            run += 1
        delta = (previous[index] - lengths[index]) % 17
        if not lengths[index] and run >= 20:
            run = min(run, 51)
            items.append((18, run - 20, 5, None))
        elif not lengths[index] and run >= 4:
            run = min(run, 19)
            items.append((17, run - 4, 4, None))
        elif run >= 4:
            run = min(run, 5)
            items.append((19, run - 4, 1, delta))
        else:
            run = 1
            items.append((delta, 0, 0, None))
        index += run
    counts = [0] * 20
    for symbol, _, _, follow in items:
        counts[symbol] += 1
        if follow is not None:
            counts[follow] += 1
    pretree = code_lengths(counts, 15)
    for length in pretree:
        writer.write(length, 4)
    codes = canonical_codes(pretree)
    for symbol, extra, extra_bits, follow in items:
        writer.write(*codes[symbol])
        writer.write(extra, extra_bits)
        if follow is not None:
            writer.write(*codes[follow])
    previous[start:end] = lengths[start:end]


class LzxChunk:
    """Per-chunk LZX state: recent offsets and the tree lengths that persist across blocks."""

    def __init__(self, slots):
        self.recent, self.main, self.length = [1, 1, 1], [0] * (256 + 8 * slots), [0] * 249


def lzx_block(writer, state, kind, data, start, end, tokens, window_order):
    size = end - start
    writer.write({"verbatim": 1, "aligned": 2, "uncompressed": 3}[kind], 3)
    if size == 32768:
        writer.write(1, 1)
    else:
        writer.write(0, 1)
        writer.write(size, 24 if window_order >= 16 else 16)
    if kind == "uncompressed":
        # 1 to 16 padding bits up to the next word, then the recent offsets and the raw bytes
        writer.write(0, 16 - writer.count)
        writer.out += struct.pack("<III", *state.recent) + data[start:end] + bytes(size & 1)
        return

    main_counts, length_counts, aligned_counts, symbols = [0] * len(state.main), [0] * 249, [0] * 8, []
    for token in tokens:
        if isinstance(token, int):
            main_counts[token] += 1
            symbols.append((token, None, 0, 0, None))
            continue
        offset, length = token
        header = min(length - 2, 7)
        footer = footer_bits = aligned = None
        if offset in state.recent:
            slot = state.recent.index(offset)
            state.recent[slot] = state.recent[0]
        else:
            formatted = offset + 2
            slot = bisect_right(POSITION_BASE, formatted) - 1
            footer, footer_bits = formatted - POSITION_BASE[slot], EXTRA_BITS[slot]
            if kind == "aligned" and footer_bits >= 3:
                footer, footer_bits, aligned = footer >> 3, footer_bits - 3, footer & 7
                aligned_counts[aligned] += 1
            state.recent[1:] = state.recent[:2]
        state.recent[0] = offset
        symbol = 256 + 8 * slot + header
        main_counts[symbol] += 1
        if header == 7:
            length_counts[length - 9] += 1
        symbols.append((symbol, length - 9 if header == 7 else None, footer or 0, footer_bits or 0, aligned))

    if kind == "aligned":
        aligned_lengths = code_lengths(aligned_counts, 7)
        for length in aligned_lengths:
            writer.write(length, 3)
        aligned_codes = canonical_codes(aligned_lengths)
    main_lengths, length_lengths = code_lengths(main_counts, 16), code_lengths(length_counts, 16)
    lzx_write_lengths(writer, state.main, main_lengths, 0, 256)
    lzx_write_lengths(writer, state.main, main_lengths, 256, len(main_lengths))
    lzx_write_lengths(writer, state.length, length_lengths, 0, 249)
    main_codes, length_codes = canonical_codes(main_lengths), canonical_codes(length_lengths)
    for symbol, length_symbol, footer, footer_bits, aligned in symbols:
        writer.write(*main_codes[symbol])
        if length_symbol is not None:
            writer.write(*length_codes[length_symbol])
        writer.write(footer, footer_bits)
        if aligned is not None:
            writer.write(*aligned_codes[aligned])


def lzx_compress(chunk, chunk_size, blocks=("verbatim",), block_size=None):
    """
    Compress one WIM chunk with LZX.

    The chunk is cut into blocks of block_size bytes (one block when None) whose
    types cycle through blocks.
    """
    window_order = max(15, (chunk_size - 1).bit_length())
    data = e8_translate(chunk)
    ends = [*range(block_size, len(data), block_size), len(data)] if block_size else [len(data)]
    kinds = [kind for kind, _ in zip(cycle(blocks), ends, strict=False)]
    tokens = lz77(data, ends, 2, 257, chunk_size)
    writer, state = BitWriter(), LzxChunk(POSITION_SLOTS[window_order])
    for start, end, kind, block_tokens in zip([0, *ends], ends, kinds, tokens, strict=False):
        lzx_block(writer, state, kind, data, start, end, block_tokens, window_order)
    return writer.flush()


def xpress_compress(chunk, chunk_size):
    """Compress one WIM chunk with XPRESS Huffman, laying out the words as the decoder reads them."""
    tokens = lz77(chunk, [len(chunk)], 3, 65538, 65535)[0]
    symbols, counts = [], [0] * 512
    for token in tokens:
        if isinstance(token, int):
            symbols.append((token, None, 0, 0))
            counts[token] += 1
            continue
        offset, length = token
        offset_bits = offset.bit_length() - 1
        symbol = 256 + (offset_bits << 4) + min(length - 3, 15)
        symbols.append((symbol, length - 3, offset - (1 << offset_bits), offset_bits))
        counts[symbol] += 1
    # End of stream symbol: the reader stops at the chunk size, 7-Zip expects it
    symbols.append((256, None, 0, 0))
    counts[256] += 1
    lengths = code_lengths(counts, 15)
    codes = canonical_codes(lengths)

    # The decoder keeps at least 16 bits buffered and reads raw bytes at its input position,
    # so each 16-bit word goes to a slot reserved when the decoder would load it
    out = bytearray(lengths[index] | lengths[index + 1] << 4 for index in range(0, 512, 2))
    slots, writer, left = [256, 258], BitWriter(), 32
    out += bytes(4)

    def consume(value, count):
        nonlocal left
        writer.write(value, count)
        left -= count
        while left < 16:
            slots.append(len(out))
            out.extend(bytes(2))
            left += 16

    for symbol, length, offset, offset_bits in symbols:
        consume(*codes[symbol])
        if length is not None:
            if length >= 15:
                out.append(min(length - 15, 255))
                if length - 15 >= 255:
                    out.extend(length.to_bytes(2, "little"))
            consume(offset, offset_bits)
    words = writer.flush()
    for index, slot in enumerate(slots):
        out[slot:slot + 2] = words[2 * index:2 * index + 2].ljust(2, b"\x00")
    return bytes(out)


def compress_resource(data, compression, chunk_size, **lzx_options):
    """Return (stored bytes, compressed flag) for a resource, with its chunk table."""
    if not compression or not data:
        return data, False
    chunks = []
    for start in range(0, len(data), chunk_size):
        chunk = data[start:start + chunk_size]
        packed = lzx_compress(chunk, chunk_size, **lzx_options) if compression == LZX else xpress_compress(chunk, chunk_size)
        # A chunk that does not shrink is stored as is
        chunks.append(packed if len(packed) < len(chunk) else chunk)
    offsets = list(accumulate(len(chunk) for chunk in chunks[:-1]))
    return struct.pack(f"<{len(offsets)}I", *offsets) + b"".join(chunks), True


@dataclass
class File:
    """A file in a generated image; split stores the content hash in an unnamed extra stream."""

    content: bytes = b""
    attributes: int = 0x20
    streams: dict = field(default_factory=dict)
    split: bool = False


def dentry(attributes, digest, name, streams=()):
    name = name.encode("utf-16-le")
    length = (102 + (len(name) + 2 if name else 0) + 7) & ~7
    entry = struct.pack("<QIiQ40x20s12xHHH", length, attributes, -1, 0, digest, len(streams), 0, len(name)) + name
    entry = entry.ljust(length, b"\x00")
    for stream_name, stream_digest in streams:
        stream_name = stream_name.encode("utf-16-le")
        stream_length = (38 + (len(stream_name) + 2 if stream_name else 0) + 7) & ~7
        entry += (struct.pack("<Q8x20sH", stream_length, stream_digest, len(stream_name)) + stream_name).ljust(stream_length, b"\x00")
    return entry


def build_metadata(files, blobs):
    """Metadata resource for one image: empty security data, the root entry, then every directory."""
    tree = {}
    for path, item in files.items():
        node, parts = tree, path.split("\\")
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = item if isinstance(item, (File, dict)) else File(item)

    def digest_of(content):
        if not content:
            return bytes(20)
        digest = sha1(content).digest()
        blobs[digest] = content
        return digest

    metadata = bytearray(struct.pack("<II", 8, 0)) + dentry(0x10, bytes(20), "") + bytes(8)

    def write_directory(node):
        start, children = len(metadata), []
        for name, item in node.items():
            children.append((len(metadata), item))
            if isinstance(item, dict):
                metadata.extend(dentry(0x10, bytes(20), name))
                continue
            streams = [(stream, digest_of(content)) for stream, content in item.streams.items()]
            if item.split:
                streams.insert(0, ("", digest_of(item.content)))
            metadata.extend(dentry(item.attributes, bytes(20) if item.split else digest_of(item.content), name, streams))
        metadata.extend(bytes(8))
        for offset, item in children:
            if isinstance(item, dict):
                metadata[offset + 16:offset + 24] = struct.pack("<Q", write_directory(item))
        return start

    metadata[8 + 16:8 + 24] = struct.pack("<Q", write_directory(tree))
    return bytes(metadata)


def build_wim(images, compression=0, chunk_size=32768, names=None, compress_tables=False, packed=None, **lzx_options):
    """
    Return the bytes of a WIM holding these images.

    Each image maps a backslash path to its content, a File, or a dict for an
    empty directory. Images are named from names, or "image N". packed maps a
    file content to a hand-made compressed chunk stored instead of encoding it.
    """
    blobs = {}
    metadata = [build_metadata(files, blobs) for files in images]
    out, lookup = bytearray(208), bytearray()

    def add(data, flags, table=False):
        stored, compressed = (packed[data], True) if packed and data in packed else compress_resource(data, compression if not table or compress_tables else 0, chunk_size, **lzx_options)
        offset = len(out)
        out.extend(stored)
        return len(stored) | (flags | (0x04 if compressed else 0)) << 56, offset, len(data)

    for digest, content in blobs.items():
        lookup += struct.pack("<QQQHI20s", *add(content, 0), 1, 1, digest)
    for data in metadata:
        lookup += struct.pack("<QQQHI20s", *add(data, 0x02), 1, 1, sha1(data).digest())
    lookup_descriptor = add(bytes(lookup), 0, True)
    names = names or [f"image {number}" for number in range(1, len(images) + 1)]
    xml = "".join(f'<IMAGE INDEX="{number}"><NAME>{name}</NAME></IMAGE>' for number, name in enumerate(names, 1))
    xml_descriptor = add(f"\ufeff<WIM>{xml}</WIM>".encode("utf-16-le"), 0, True)
    flags = compression | 0x02 if compression else 0
    header = struct.pack("<8sIIII16sHHI", b"MSWIM\x00\x00\x00", 208, 0x10D00, flags, chunk_size, bytes(range(16)), 1, 1, len(images))
    header += struct.pack("<QQQ", *lookup_descriptor) + struct.pack("<QQQ", *xml_descriptor) + bytes(24 + 4 + 24 + 60)
    out[:208] = header
    return bytes(out)


def sample_content(seed, size):
    """Deterministic data mixing text, runs, x86-like CALL bytes, repeated records and noise."""
    rng = random.Random(seed)
    words = [bytes(rng.choice(b"abcdefghijklmnopqrstuvwxyz") for _ in range(rng.randint(2, 9))) for _ in range(64)]
    out = bytearray()
    while len(out) < size:
        kind = rng.randrange(6)
        if kind == 0:
            out += b" ".join(rng.choice(words) for _ in range(rng.randint(5, 60))) + b"\r\n"
        elif kind == 1:
            out += bytes([rng.randrange(256)]) * rng.randint(3, 600)
        elif kind == 2:
            out += b"\xe8" + rng.randrange(-40000, 40000).to_bytes(4, "little", signed=True)
        elif kind == 3:
            record = rng.randbytes(rng.randint(4, 40))
            out += record * rng.randint(2, 12)
        elif kind == 4:
            out += rng.randbytes(rng.randint(1, 300))
        else:
            back = rng.randint(1, min(len(out), 70000) or 1)
            out += out[-back:][:rng.randint(2, 300)]
    return bytes(out[:size])


def synth_verbatim_block(writer, byte, matches, first):
    """LZX block giving 1 + 257 * matches copies of byte: one literal, then offset-1 matches of length 257."""
    size = 1 + 257 * matches
    writer.write(1, 3)
    writer.write(0, 1)
    writer.write(size, 16)
    for count, ones in ((256, {byte}), (240, {287 - 256}), (249, {0, 248})):
        for index in range(20):
            writer.write(1 if index in {0, 16} else 0, 4)
        for index in range(count):
            # Pretree code 0 keeps the previous length, 1 is the delta giving length 1 (first block only)
            writer.write(1 if first and index in ones else 0, 1)
    writer.write(0, 1)
    for _ in range(matches):
        writer.write(1, 1)
        writer.write(1, 1)
    return bytes([byte]) * size


def synth_chunk(first_matches, aligned_padding):
    """
    LZX chunk with an uncompressed block between two verbatim blocks.

    Returns (chunk, content, padding bits before the uncompressed data).
    first_matches sets where the uncompressed block header ends; when it ends
    on a word boundary, aligned_padding chooses between 16 padding bits
    (what 7-Zip and the reader expect) and none.
    """
    writer, payload = BitWriter(), bytes((7 * index + 3) % 200 for index in range(101))
    content = synth_verbatim_block(writer, 0x41, first_matches, True)
    writer.write(3, 3)
    writer.write(0, 1)
    writer.write(len(payload), 16)
    padding = -writer.count % 16 or (16 if aligned_padding else 0)
    writer.write(0, padding)
    writer.out += struct.pack("<III", 1, 1, 1) + payload + bytes(len(payload) & 1)
    content += payload + synth_verbatim_block(writer, 0x41, 9, False)
    return writer.flush(), content, padding


# Hand-made chunks: first_matches, aligned_padding, and whether the reader and 7-Zip accept the chunk
SYNTH_CASES = {"unaligned": (11, True, True), "aligned-skip16": (7, True, True), "aligned-skip0": (7, False, False)}
