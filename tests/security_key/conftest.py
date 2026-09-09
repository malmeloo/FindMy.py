"""Expose the standalone example and its synthetic fixture helpers for pytest."""

import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS.parents[1] / "examples" / "security_key"))
sys.path.insert(0, str(TESTS))
