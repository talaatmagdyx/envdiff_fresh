import sys
from pathlib import Path

# Ensure repository root is importable when running pytest from subdirs/other CWDs
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
