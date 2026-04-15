from __future__ import annotations

import hmac
import json
import os
from hashlib import sha256
from pathlib import Path
from typing import Any


class ResultIntegrityService:
    VERSION = 1

    def __init__(self, secret_path: str | Path) -> None:
        self._secret_path = Path(secret_path)

    def get_or_create_secret(self) -> bytes:
        self._secret_path.parent.mkdir(parents=True, exist_ok=True)
        if not self._secret_path.exists():
            self._secret_path.write_bytes(os.urandom(32))
        return self._secret_path.read_bytes()

    def sign_result(self, **fields: Any) -> str:
        message = self._build_message(fields)
        secret = self.get_or_create_secret()
        return hmac.new(secret, message, sha256).hexdigest()

    def verify_result(self, *, integrity_signature: str | None, integrity_version: int | None, **fields: Any) -> bool | None:
        if not integrity_signature:
            return None
        if integrity_version != self.VERSION:
            return False
        expected_signature = self.sign_result(**fields)
        return hmac.compare_digest(expected_signature, integrity_signature)

    @staticmethod
    def _build_message(fields: dict[str, Any]) -> bytes:
        normalized = {
            "analysis_id": fields.get("analysis_id"),
            "file_name": fields.get("file_name"),
            "media_type": fields.get("media_type"),
            "uploaded_at": fields.get("uploaded_at") or "",
            "analysis_started_at": fields.get("analysis_started_at") or "",
            "analyzed_at": fields.get("analyzed_at") or "",
            "stored_at": fields.get("stored_at") or "",
            "status": fields.get("status"),
            "is_fake": fields.get("is_fake"),
            "probability": fields.get("probability"),
            "threshold": fields.get("threshold"),
            "summary": fields.get("summary"),
            "error_message": fields.get("error_message") or "",
            "indicators_json": fields.get("indicators_json") or "[]",
            "technical_details_json": fields.get("technical_details_json") or "[]",
            "file_sha256": fields.get("file_sha256") or "",
        }
        serialized = json.dumps(normalized, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        return serialized.encode("utf-8")
