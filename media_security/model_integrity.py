from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from media_security.extractors.common import compute_hashes


@dataclass(slots=True)
class ModelVerificationResult:
    path: str
    exists: bool
    sha256_expected: str
    sha256_actual: str | None
    status: str
    size_bytes: int | None = None

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "path": self.path,
            "exists": self.exists,
            "sha256_expected": self.sha256_expected,
            "status": self.status,
        }
        if self.sha256_actual is not None:
            payload["sha256_actual"] = self.sha256_actual
        if self.size_bytes is not None:
            payload["size_bytes"] = self.size_bytes
        return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="media-security-model-integrity",
        description="Register and verify trusted SHA-256 hashes for model weight files.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    register_parser = subparsers.add_parser(
        "register",
        help="Add or refresh SHA-256 hashes for model files in a manifest.",
    )
    register_parser.add_argument("manifest", type=Path, help="Path to JSON manifest file.")
    register_parser.add_argument("paths", nargs="+", type=Path, help="Model weight files to register.")

    verify_parser = subparsers.add_parser(
        "verify",
        help="Verify model files against a trusted SHA-256 manifest.",
    )
    verify_parser.add_argument("manifest", type=Path, help="Path to JSON manifest file.")
    verify_parser.add_argument("--json-out", type=Path, help="Write verification report to JSON.")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "register":
        manifest = register_models(args.manifest, args.paths)
        print(f"Registered {len(manifest['models'])} model file(s) in {args.manifest}.")
        return 0

    if args.command == "verify":
        results = verify_manifest(args.manifest)
        _print_results(results)
        if args.json_out:
            _write_report(args.json_out, args.manifest, results)
            print(f"JSON report written to: {args.json_out}")
        if any(item.status != "pass" for item in results):
            return 1
        return 0

    parser.error("Unknown command.")
    return 2


def register_models(manifest_path: Path, model_paths: list[Path]) -> dict[str, object]:
    manifest = _load_manifest(manifest_path)
    manifest_models = {
        str(entry["path"]): entry
        for entry in manifest.get("models", [])
        if isinstance(entry, dict) and entry.get("path")
    }

    manifest_parent = manifest_path.resolve().parent
    for model_path in model_paths:
        resolved_path = model_path.resolve()
        if not resolved_path.exists() or not resolved_path.is_file():
            raise FileNotFoundError(f"Model file not found: {resolved_path}")

        relative_path = Path(_relative_to_manifest(resolved_path, manifest_parent)).as_posix()
        file_hashes = compute_hashes(resolved_path)
        manifest_models[relative_path] = {
            "path": relative_path,
            "sha256": file_hashes["sha256"],
            "size_bytes": resolved_path.stat().st_size,
            "updated_at_utc": datetime.now(tz=UTC).isoformat(),
        }

    payload = {
        "generated_at_utc": datetime.now(tz=UTC).isoformat(),
        "models": sorted(manifest_models.values(), key=lambda item: str(item["path"]).lower()),
    }
    _write_manifest(manifest_path, payload)
    return payload


def verify_manifest(manifest_path: Path) -> list[ModelVerificationResult]:
    manifest = _load_manifest(manifest_path)
    raw_models = manifest.get("models", [])
    if not isinstance(raw_models, list):
        raise ValueError("Manifest field 'models' must be a list.")

    results: list[ModelVerificationResult] = []
    manifest_parent = manifest_path.resolve().parent

    for entry in raw_models:
        if not isinstance(entry, dict):
            continue
        relative_path = str(entry.get("path", "")).strip()
        expected_sha256 = str(entry.get("sha256", "")).strip().lower()
        if not relative_path or not expected_sha256:
            continue

        resolved_path = (manifest_parent / relative_path).resolve()
        if not resolved_path.exists() or not resolved_path.is_file():
            results.append(
                ModelVerificationResult(
                    path=relative_path,
                    exists=False,
                    sha256_expected=expected_sha256,
                    sha256_actual=None,
                    status="missing",
                )
            )
            continue

        actual_hash = compute_hashes(resolved_path)["sha256"]
        status = "pass" if actual_hash == expected_sha256 else "hash_mismatch"
        results.append(
            ModelVerificationResult(
                path=relative_path,
                exists=True,
                sha256_expected=expected_sha256,
                sha256_actual=actual_hash,
                size_bytes=resolved_path.stat().st_size,
                status=status,
            )
        )

    return results


def _load_manifest(manifest_path: Path) -> dict[str, Any]:
    if not manifest_path.exists():
        return {"models": []}

    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Manifest must contain a JSON object.")
    return payload


def _write_manifest(manifest_path: Path, payload: dict[str, object]) -> None:
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def _relative_to_manifest(path: Path, manifest_parent: Path) -> str:
    return os.path.relpath(path, start=manifest_parent)


def _print_results(results: list[ModelVerificationResult]) -> None:
    if not results:
        print("No model entries found in manifest.")
        return

    for item in results:
        print(f"{item.status.upper():13} {item.path}")
        if item.sha256_actual and item.status != "pass":
            print(f"  expected: {item.sha256_expected}")
            print(f"  actual:   {item.sha256_actual}")

    passed = sum(1 for item in results if item.status == "pass")
    failed = len(results) - passed
    print("")
    print(f"Summary: total={len(results)}, pass={passed}, fail={failed}")


def _write_report(output_path: Path, manifest_path: Path, results: list[ModelVerificationResult]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at_utc": datetime.now(tz=UTC).isoformat(),
        "manifest": str(manifest_path.resolve()),
        "results": [item.to_dict() for item in results],
    }
    output_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
