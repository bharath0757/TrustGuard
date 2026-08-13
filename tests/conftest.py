"""
Shared pytest fixtures for the TrustGuard test suite.

Ensures the project root (D:\\TrustGuard) is on sys.path so the
``database`` package is importable without installing it as a package.
This conftest.py is discovered by pytest before any test module is
imported, so the path manipulation takes effect in time.
"""
import sys
import os

# Project root = parent of the tests/ directory
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
