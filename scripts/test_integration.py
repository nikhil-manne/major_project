"""Compatibility entry point for the verified local evaluation suite.

The prior version of this script incorrectly expected Dockerfile uploads to be marked
built and treated simulated tool output as successful live execution. Those expectations
were removed because they could report false success. This entry point runs the explicit
local simulation/security checks; external infrastructure requires the separate live
verification checklist in README.md.
"""
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.evaluate_local import main  # type: ignore[import-not-found, import-untyped]


if __name__ == "__main__":
    raise SystemExit(main())
