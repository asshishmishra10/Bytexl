import sys
import os
from pathlib import Path

# Add backend directory to sys.path
_backend_dir = str(Path(__file__).resolve().parent.parent)
if _backend_dir not in sys.path:
    sys.path.insert(0, _backend_dir)

from main import app, handler
