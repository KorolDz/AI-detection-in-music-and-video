# AI Detection in Music and Video

Cybersecurity-oriented project for validating media integrity and detecting suspicious files.
This stage implements a production-ready metadata verification module for media files.

## Current Scope

- Supported audio: `wav`, `mp3`
- Supported video: `mp4`, `avi`, `mov`
- Security checks:
  - extension whitelist
  - binary signature (magic bytes)
  - extension/signature mismatch detection
  - MIME consistency checks
  - file hash generation (`sha256`, `md5`)
  - timestamp anomaly checks
  - format-specific metadata validation

## Project Structure

```text
AI-detection-in-music-and-video/
|-- pyproject.toml
|-- project.txt
|-- README.md
|-- datasets/
|   |-- README.md
|   |-- test_media/
|   |   |-- audio/
|   |   `-- video/
|   `-- external/
|       |-- asvspoof2021/
|       |-- faceforensicspp/
|       `-- fakeavceleb/
|-- scripts/
|   |-- generate_test_media_fixtures.py
|   `-- run_metadata_scan.ps1
|-- reports/
|   `-- .gitkeep
|-- src/
|   |-- media_security/
|   |   |-- __init__.py
|   |   |-- cli.py
|   |   |-- constants.py
|   |   |-- models.py
|   |   |-- scanner.py
|   |   |-- signatures.py
|   |   `-- extractors/
|   |       |-- __init__.py
|   |       |-- common.py
|   |       |-- audio.py
|   |       `-- video.py
|   `-- video_detection/
|       `-- mesonet_simple.py
`-- tests/
    |-- test_scanner.py
    `-- test_signatures.py
```

## Quick Start

```bash
python -m pip install -e .[dev]
pytest
```

Generate local audio/video fixtures for scanner tests:

```bash
python scripts/generate_test_media_fixtures.py
```

Run scan for one file:

```bash
python -m media_security.cli path/to/file.mp4 --json-out reports/file_report.json
```

Run recursive directory scan:

```bash
python -m media_security.cli path/to/dataset --recursive --json-out reports/full_report.json
```

PowerShell helper:

```powershell
./scripts/run_metadata_scan.ps1 -Target .\path\to\dataset -Recursive
```

## CLI Exit Codes

- `0` - all files passed (or warning-only mode accepted)
- `1` - at least one file failed validation (or warnings when `--fail-on-warning` is set)

## Next Steps

- Add EXIF and container-deep metadata checks
- Add chain-of-custody storage for scan evidence
- Integrate metadata verdict into audio/video deepfake classifiers
