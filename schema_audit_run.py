#!/usr/bin/env python3
"""Thin launcher: `python schema_audit_run.py --input ...` -> schema_audit.cli.main()"""
import sys

from schema_audit.cli import main

if __name__ == "__main__":
    sys.exit(main())
