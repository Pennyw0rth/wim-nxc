# wim-nxc

A small, pure-Python, read-only reader for Windows Imaging (WIM) files, maintained by Pennyw0rth for [NetExec](https://github.com/Pennyw0rth/NetExec).

It opens a WIM image, lists its files and extracts the ones you ask for. It has no runtime dependency and no native code, so a WIM file chosen by a remote host is only ever parsed by Python code. It reads only the lookup table, the image metadata and the files you request, which keeps the cost low when the WIM sits on a remote share.

## Install

```bash
pip install wim-nxc
```

Python 3.11 or later.

## Usage

```python
from wim_nxc import WimError, WimFile

with WimFile("boot.wim") as wim:
    print(wim.image_names())
    for path, attributes, digest in wim.files():
        if path.endswith("Bootstrap.ini"):
            print(path, wim.read(digest).decode("utf-8", "replace"))
```

`WimFile` also takes a file object instead of a path. The object only needs `seek(offset, 0)` and `read(size)`, and `read` may return fewer bytes than asked. This is how NetExec reads a WIM over SMB without downloading it:

```python
wim = WimFile(remote_file)
```

## API

| Name | Description |
|---|---|
| `WimFile(file)` | Open a WIM from a path (`str` or `os.PathLike`) or a file object. Reads the header and the lookup table. |
| `WimFile.files()` | Yield `(path, attributes, sha1)` for every file of every image. Directories are not yielded. Paths use backslashes and start with the image number (`1\`, `2\`...) when the WIM holds several images. `attributes` are the Windows file attributes, for example `0x400` for a reparse point. |
| `WimFile.read(sha1)` | Return the content as `bytes`. The all-zero hash of an empty file gives `b""`. Raises `WimError` when the content is missing or does not match its SHA-1. |
| `WimFile.image_names()` | Return the image names from the WIM's XML data, in image order, `""` for an image without a name. Only this method reads the XML data. |
| `WimFile.close()`, `with WimFile(...)` | Close the file when `WimFile` opened it from a path. A file object you pass in is left open. |
| `WimError` | Raised for any input that is not a valid or supported WIM file. It subclasses `ValueError`. Errors raised by your file object, such as `OSError` or an SMB error, pass through unchanged, except `ValueError`, `IndexError` and `OverflowError`, which are wrapped in `WimError` like malformed input. |

## Untrusted input

The reader is meant for WIM files that an attacker may control:

- every malformed input ends with `WimError`, checked by two fuzzers in the test suite (corrupted WIMs and corrupted compressed chunks);
- the 64 MiB resource limit and the chunk size limits bound the memory and time spent on one file;
- a directory tree that loops back on itself is read once;
- the XML data is parsed with `xml.etree.ElementTree`, which relies on expat's protection against entity expansion (expat 2.4.1 and later).

## Development

```bash
uv sync
uv run pytest
uv run ruff check .
```

The tests build their WIM files with small LZX and XPRESS encoders in `tests/wimgen.py`. When 7-Zip (`7z` or `7zz`) is installed, the tests also check that 7-Zip extracts these WIMs to the same content.

Two environment variables extend the tests:

- `WIM_SAMPLES`: a folder with WIM files made by Windows DISM (`test-*.wim`, `synth-*.wim`, `litetouch.wim`). The tests compare every file with a 7-Zip extraction and add the samples to the fuzzing corpus. Such samples hold Microsoft binaries: never commit them.
- `WIM_FUZZ_CASES`: cases per WIM for the WIM fuzzer, three times as many for the chunk fuzzer (default 300).

The fuzz tests need `signal.setitimer` and are skipped on Windows.

## Format references

The reader was written from Microsoft's public documentation: the WIM file format description, [MS-XCA] for XPRESS Huffman and [MS-PATCH] for LZX. It contains no code from wimlib, 7-Zip or libmspack.

## License

BSD-2-Clause, see [LICENSE](LICENSE).
