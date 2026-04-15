from __future__ import annotations

import hashlib
from pathlib import Path


class FileHashService:
    def calculate_sha256(self, path: str | Path) -> str:
        target_path = Path(path)
        digest = hashlib.sha256()
        with target_path.open("rb") as file_obj:
            for chunk in iter(lambda: file_obj.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
