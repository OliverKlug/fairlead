#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2026 Oliver Klug
# SPDX-License-Identifier: Apache-2.0
# Q-LLM adapter for `FAIRLEAD_QLLM`: NuExtract prompt on stdin, completion on stdout.
# Needs llama.cpp (`llama-cli`) and a NuExtract-1.5-tiny Q4_K_M GGUF. CPU only, no tools, no network.
#   export FAIRLEAD_QLLM="/abs/path/to/scripts/qllm-nuextract.sh"
#   export FAIRLEAD_QLLM_MODEL="/abs/path/to/NuExtract-1.5-tiny.Q4_K_M.gguf"
# UNTESTED: llama.cpp was not installed where this was written, and CI never runs this script
# (suite 10 injects stub extractors). Recheck the flags against `llama-cli --help` before trusting it.
set -eu
: "${FAIRLEAD_QLLM_MODEL:?set FAIRLEAD_QLLM_MODEL to the GGUF path}"
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
cat > "$tmp"
exec llama-cli -m "$FAIRLEAD_QLLM_MODEL" -f "$tmp" -n 128 -c 2048 --temp 0 -ngl 0 --no-display-prompt -no-cnv 2>/dev/null
