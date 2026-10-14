import sys
import os
from pathlib import Path

# Add backend directory to Python path
backend_dir = str(Path(__file__).resolve().parent.parent / "backend")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from main import app, handler

# Export ASGI app & Mangum handler for Vercel Serverless Function
export = app
