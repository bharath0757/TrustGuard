"""Vercel Serverless Function entrypoint for TrustGuard FastAPI Backend."""

import os
import sys
from pathlib import Path

# Add repository root and backend directory to sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(ROOT_DIR / "backend"))

# Import the existing FastAPI application instance without duplication
from backend.main import app
