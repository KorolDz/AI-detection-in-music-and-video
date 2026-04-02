from media_security.signatures import detect_format_from_signature, is_signature_compatible


def test_detect_wav_signature() -> None:
    header = b"RIFF\x24\x80\x00\x00WAVEfmt "
    result = detect_format_from_signature(header)
    assert result.detected_format == "wav"


def test_detect_avi_signature() -> None:
    header = b"RIFF\x24\x80\x00\x00AVI LIST"
    result = detect_format_from_signature(header)
    assert result.detected_format == "avi"


def test_detect_mp4_signature() -> None:
    header = b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00"
    result = detect_format_from_signature(header)
    assert result.detected_format == "mp4"
    assert result.details["major_brand"] == "isom"


def test_detect_mov_signature() -> None:
    header = b"\x00\x00\x00\x18ftypqt  \x00\x00\x02\x00"
    result = detect_format_from_signature(header)
    assert result.detected_format == "mov"


def test_detect_mp3_signature_by_id3() -> None:
    header = b"ID3\x04\x00\x00\x00\x00\x00\x21"
    result = detect_format_from_signature(header)
    assert result.detected_format == "mp3"


def test_signature_compatibility() -> None:
    assert is_signature_compatible("wav", "wav")
    assert is_signature_compatible("mp4", "mp4")
    assert not is_signature_compatible("wav", "mp3")
