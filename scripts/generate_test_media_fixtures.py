from __future__ import annotations

import math
import struct
import wave
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DATASET_DIR = ROOT / "datasets"


def main() -> None:
    _ensure_layout()

    _create_wav(
        DATASET_DIR / "audio" / "tone_440hz.wav",
        duration_sec=1.0,
        sample_rate=16_000,
        frequency_hz=440.0,
    )
    _create_minimal_mp3(DATASET_DIR / "audio" / "frame_header.mp3")

    _create_minimal_mp4(DATASET_DIR / "video" / "container.mp4")
    _create_minimal_mov(DATASET_DIR / "video" / "container.mov")
    _create_minimal_avi(DATASET_DIR / "video" / "container.avi")

    _create_mp4_disguised_as_wav(DATASET_DIR / "audio" / "mp4_as_wav.wav")
    _create_wav_disguised_as_mp4(DATASET_DIR / "video" / "wav_as_mp4.mp4")
    _create_text_file(DATASET_DIR / "unsupported" / "not_media.txt")

    print(f"Fixtures generated in: {DATASET_DIR}")


def _ensure_layout() -> None:
    for path in (
        DATASET_DIR / "audio",
        DATASET_DIR / "video",
        DATASET_DIR / "unsupported",
    ):
        path.mkdir(parents=True, exist_ok=True)


def _create_wav(path: Path, duration_sec: float, sample_rate: int, frequency_hz: float) -> None:
    frames = int(duration_sec * sample_rate)
    amplitude = 10_000
    with wave.open(str(path), "wb") as wav_file:
        wav_file.setnchannels(1)
        wav_file.setsampwidth(2)
        wav_file.setframerate(sample_rate)
        for frame_idx in range(frames):
            value = int(amplitude * math.sin(2.0 * math.pi * frequency_hz * frame_idx / sample_rate))
            wav_file.writeframes(struct.pack("<h", value))


def _create_minimal_mp3(path: Path) -> None:
    # MPEG1 Layer III frame header (0xFFFB9064) + payload bytes.
    path.write_bytes(bytes.fromhex("FFFB9064") + b"\x00" * 512)


def _create_minimal_mp4(path: Path) -> None:
    payload = b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isomiso2"
    path.write_bytes(payload)


def _create_minimal_mov(path: Path) -> None:
    payload = b"\x00\x00\x00\x18ftypqt  \x00\x00\x02\x00qt  "
    path.write_bytes(payload)


def _create_minimal_avi(path: Path) -> None:
    payload = b"RIFF" + (120).to_bytes(4, byteorder="little") + b"AVI " + b"\x00" * 120
    path.write_bytes(payload)


def _create_mp4_disguised_as_wav(path: Path) -> None:
    payload = b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isomiso2"
    path.write_bytes(payload)


def _create_wav_disguised_as_mp4(path: Path) -> None:
    payload = b"RIFF" + (36).to_bytes(4, byteorder="little") + b"WAVEfmt " + b"\x00" * 64
    path.write_bytes(payload)


def _create_text_file(path: Path) -> None:
    path.write_text("This file must fail as unsupported format.", encoding="utf-8")


if __name__ == "__main__":
    main()
