#!/usr/bin/env sh
set -eu
exec streamlit run app.py "$@"
