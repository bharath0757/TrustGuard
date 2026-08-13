"""
Root-level conftest.py — discovered by pytest BEFORE any test module is imported.

Inserts D:\\TrustGuard into sys.path so the ``database`` package is importable
on Python 3.9 (which does not support pytest.ini ``pythonpath =``).
"""
import sys
import os

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
