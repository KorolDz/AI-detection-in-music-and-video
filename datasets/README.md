# Datasets and Test Media

## Local Test Fixtures

This repository includes a lightweight fixture structure for metadata security checks:

```text
datasets/
|-- test_media/
|   |-- audio/
|   |   |-- real/
|   |   `-- suspicious/
|   `-- video/
|       |-- real/
|       `-- suspicious/
`-- external/
    |-- asvspoof2021/
    |-- faceforensicspp/
    `-- fakeavceleb/
```

Generate local fixture files:

```bash
python scripts/generate_test_media_fixtures.py
```

After generation:
- `test_media/audio/real` contains valid `wav` and `mp3` samples.
- `test_media/video/real` contains valid `mp4`, `mov`, and `avi` container samples.
- `test_media/*/suspicious` contains mismatch and unsupported files for negative tests.

## Recommended Public Datasets

Checked on **2026-04-02**.

1. **FakeAVCeleb** (audio + video deepfake dataset, multimodal)
   - Main repo and access instructions: https://github.com/DASH-Lab/FakeAVCeleb
   - Access is provided via request form (linked in repo README).
   - Best fit when you need both audio and video in one dataset.

2. **ASVspoof 2021** (speech anti-spoofing / deepfake audio)
   - Official page: https://www.asvspoof.org/index2021.html
   - Data links on Zenodo are published on the official page (LA / PA / DF subsets).
   - Use for audio-focused validation and spoofing robustness checks.

3. **FaceForensics++** (video face manipulation detection)
   - Official repo and access details: https://github.com/ondyari/FaceForensics
   - Access is request-based via form (linked in repo README).
   - Strong option for video forgery benchmarks.

## Where to Place Downloaded Data

Suggested mapping:
- ASVspoof 2021 -> `datasets/external/asvspoof2021/`
- FaceForensics++ -> `datasets/external/faceforensicspp/`
- FakeAVCeleb -> `datasets/external/fakeavceleb/`
