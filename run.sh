#!/usr/bin/env bash
set -euo pipefail
estimate_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ -n "${SAGE_PYTHON:-}" ]]; then
    exec "$SAGE_PYTHON" "$estimate_root/Kyber.py"
elif command -v sage >/dev/null 2>&1; then
    exec sage -python "$estimate_root/Kyber.py"
elif [[ -x /home/junchannn/miniconda3/envs/sage10/bin/python ]]; then
    exec /home/junchannn/miniconda3/envs/sage10/bin/python "$estimate_root/Kyber.py"
else
    echo 'Run with SageMath, or set SAGE_PYTHON to its Python executable.' >&2
    exit 1
fi
