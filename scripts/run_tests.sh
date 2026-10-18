#!/usr/bin/env bash
set -eu
python -m pytest -q
python -m compileall -q projectsentinel app.py
