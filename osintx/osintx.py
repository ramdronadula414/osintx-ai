#!/usr/bin/env python3
"""OSINT-X AI entry point.

Usage:
    python osintx.py --help
    python osintx.py investigate --domain example.com

Or, after `pip install -e .`:
    osintx --help
"""
from cli import app

if __name__ == "__main__":
    app()
