from pathlib import Path

from media_security.model_integrity import register_models, verify_manifest


def test_register_and_verify_model_manifest(tmp_path: Path) -> None:
    manifest = tmp_path / "model_hash_manifest.json"
    model_file = tmp_path / "audio_detector.onnx"
    model_file.write_bytes(b"trusted-model-weights")

    payload = register_models(manifest, [model_file])
    assert payload["models"][0]["path"] == "audio_detector.onnx"

    results = verify_manifest(manifest)
    assert len(results) == 1
    assert results[0].status == "pass"
    assert results[0].exists is True


def test_verify_manifest_detects_hash_mismatch_and_missing_file(tmp_path: Path) -> None:
    manifest = tmp_path / "model_hash_manifest.json"
    model_file = tmp_path / "video_detector.onnx"
    model_file.write_bytes(b"first-version")

    register_models(manifest, [model_file])

    model_file.write_bytes(b"tampered-version")
    mismatch_results = verify_manifest(manifest)
    assert mismatch_results[0].status == "hash_mismatch"

    model_file.unlink()
    missing_results = verify_manifest(manifest)
    assert missing_results[0].status == "missing"
    assert missing_results[0].exists is False
