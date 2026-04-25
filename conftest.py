from __future__ import annotations

import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent
VENDORED_GHOSTMCP = REPO_ROOT / "vendor" / "ghostmcp"

if VENDORED_GHOSTMCP.exists():
    vendored_path = str(VENDORED_GHOSTMCP)
    if vendored_path not in sys.path:
        sys.path.insert(0, vendored_path)
