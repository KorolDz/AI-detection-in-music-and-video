from __future__ import annotations

import math
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "datasets" / "audio"


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    wav_path = OUTPUT_DIR / "metadata_device_edit_example.wav"
    mp3_path = OUTPUT_DIR / "metadata_device_edit_example.mp3"

    create_wav_with_info_tags(
        wav_path,
        info_tags={
            "INAM": "metadata demo wav",
            "IART": "Device: Samsung Galaxy S23 microphone",
            "ISFT": "Edited with: Adobe Audition 24.1",
            "ICMT": "Postprocessing: noise reduction and trim",
        },
    )
    create_mp3_with_id3_tags(
        mp3_path,
        tags={
            "TIT2": "metadata demo mp3",
            "TPE1": "Device: iPhone 14 Pro mic source",
            "TENC": "Exported by: Audacity 3.5.1",
            "TSSE": "LAME3.100",
        },
    )

    stale_readme = OUTPUT_DIR / "README.txt"
    if stale_readme.exists():
        stale_readme.unlink()

    print(f"Metadata examples created in: {OUTPUT_DIR}")


def create_wav_with_info_tags(path: Path, info_tags: dict[str, str]) -> None:
    sample_rate = 16000
    channels = 1
    bits_per_sample = 16
    duration_sec = 1.0
    sample_count = int(sample_rate * duration_sec)

    pcm_samples = []
    for i in range(sample_count):
        value = int(8000 * math.sin(2.0 * math.pi * 440.0 * i / sample_rate))
        pcm_samples.append(struct.pack("<h", value))
    pcm_data = b"".join(pcm_samples)

    block_align = channels * bits_per_sample // 8
    byte_rate = sample_rate * block_align
    fmt_data = struct.pack(
        "<HHIIHH",
        1,  # PCM
        channels,
        sample_rate,
        byte_rate,
        block_align,
        bits_per_sample,
    )

    info_payload = b"INFO"
    for tag, value in info_tags.items():
        value_bytes = value.encode("utf-8") + b"\x00"
        info_payload += _riff_chunk(tag.encode("ascii"), value_bytes)

    riff_payload = b"".join(
        [
            b"WAVE",
            _riff_chunk(b"fmt ", fmt_data),
            _riff_chunk(b"LIST", info_payload),
            _riff_chunk(b"data", pcm_data),
        ]
    )
    wav_bytes = b"RIFF" + len(riff_payload).to_bytes(4, byteorder="little") + riff_payload
    path.write_bytes(wav_bytes)


def create_mp3_with_id3_tags(path: Path, tags: dict[str, str]) -> None:
    frames = []
    for frame_id, value in tags.items():
        frame_content = b"\x03" + value.encode("utf-8")
        frame = (
            frame_id.encode("ascii")
            + len(frame_content).to_bytes(4, byteorder="big")
            + b"\x00\x00"
            + frame_content
        )
        frames.append(frame)

    payload = b"".join(frames)
    id3_header = b"ID3" + bytes([3, 0, 0]) + _to_synchsafe(len(payload))
    fake_audio_frame = bytes.fromhex("FFFB9064") + b"\x00" * 1024
    path.write_bytes(id3_header + payload + fake_audio_frame)


def _riff_chunk(chunk_id: bytes, data: bytes) -> bytes:
    if len(data) % 2 == 1:
        data += b"\x00"
    return chunk_id + len(data).to_bytes(4, byteorder="little") + data


def _to_synchsafe(value: int) -> bytes:
    return bytes(
        [
            (value >> 21) & 0x7F,
            (value >> 14) & 0x7F,
            (value >> 7) & 0x7F,
            value & 0x7F,
        ]
    )


if __name__ == "__main__":
    main()
