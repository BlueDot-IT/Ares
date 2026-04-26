from __future__ import annotations

import os
import tempfile
from pathlib import Path

PRIVATE_DIR_MODE = 0o700
PRIVATE_FILE_MODE = 0o600


def ensure_private_dir(path: Path | str) -> Path:
    directory = Path(path).expanduser()
    directory.mkdir(mode=PRIVATE_DIR_MODE, parents=True, exist_ok=True)
    try:
        directory.chmod(PRIVATE_DIR_MODE)
    except PermissionError:
        # Best effort for unusual filesystems, but normal local paths should be tightened.
        pass
    return directory


def write_private_text(path: Path | str, content: str, *, encoding: str = "utf-8") -> Path:
    destination = Path(path).expanduser()
    ensure_private_dir(destination.parent)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=str(destination.parent), text=True)
    tmp_path = Path(tmp_name)
    try:
        os.fchmod(fd, PRIVATE_FILE_MODE)
        with os.fdopen(fd, "w", encoding=encoding) as handle:
            handle.write(content)
        os.replace(tmp_path, destination)
        try:
            destination.chmod(PRIVATE_FILE_MODE)
        except PermissionError:
            pass
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            tmp_path.unlink()
        except OSError:
            pass
        raise
    return destination
