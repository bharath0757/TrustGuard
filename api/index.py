"""Vercel Serverless Function Entry Point for FastAPI Backend."""

import os
import sys

# Add root directory and backend directory to Python path for Vercel execution
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
backend_dir = os.path.join(root_dir, "backend")

if root_dir not in sys.path:
    sys.path.insert(0, root_dir)
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

try:
    from backend.main import app
except ImportError:
    from main import app

# Vercel serverless entry point export
app = app
