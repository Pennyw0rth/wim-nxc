import pytest

import wimgen
from conftest import GENERATED, expected_files, extract_7z, needs_7z
from wim_nxc import WimError, WimFile

pytestmark = needs_7z


@pytest.mark.parametrize("name", GENERATED)
def test_generated_wims_match_7z(generated, name, tmp_path):
    """7-Zip and the reader give the content the WIM was built from, so the test encoders follow the format."""
    path, images = generated[name]
    result = extract_7z(path, tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    with WimFile(path) as wim:
        for path_in_wim, _, digest in wim.files():
            assert (tmp_path / path_in_wim.replace("\\", "/")).read_bytes() == wim.read(digest)
    for path_in_wim, content in expected_files(images).items():
        assert (tmp_path / path_in_wim.replace("\\", "/")).read_bytes() == content


@pytest.mark.parametrize("name", wimgen.SYNTH_CASES)
def test_uncompressed_block_padding_matches_7z(name, tmp_path):
    """The reader and 7-Zip accept and reject the same LZX uncompressed block paddings."""
    first_matches, aligned_padding, _ = wimgen.SYNTH_CASES[name]
    chunk, content, _ = wimgen.synth_chunk(first_matches, aligned_padding)
    path = tmp_path / "synth.wim"
    path.write_bytes(wimgen.build_wim([{"raw.bin": content}], compression=wimgen.LZX, packed={content: chunk}))
    extracted = tmp_path / "out" / "raw.bin"
    extract_7z(path, tmp_path / "out")
    seven_zip_ok = extracted.is_file() and extracted.read_bytes() == content
    with WimFile(path) as wim:
        try:
            reader_ok = wim.read(next(digest for _, _, digest in wim.files())) == content
        except WimError:
            reader_ok = False
    assert reader_ok == seven_zip_ok
