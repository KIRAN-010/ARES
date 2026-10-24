#!/usr/bin/env bash
# Sourced by setup.sh, which already runs from the repository root.
mj_supported_python() {
    "$1" -c 'import sys; raise SystemExit(not (sys.implementation.name == "cpython" and sys.version_info[:2] in {(3, 11), (3, 12)}))' 2>/dev/null
}

mj_prepare_python() {
    local mj_python="" mj_candidate mj_bootstrap mj_backup
    local -a mj_uv
    if [[ -n "${MJ_PYTHON:-}" ]]; then
        mj_supported_python "$MJ_PYTHON" || {
            echo "MJ_PYTHON must point to CPython 3.11 or 3.12." >&2
            return 1
        }
        mj_python="$MJ_PYTHON"
    elif [[ -x .venv/bin/python ]] && mj_supported_python .venv/bin/python; then
        echo "Reusing supported Python environment."
        .venv/bin/python -m ensurepip --upgrade >/dev/null
        return
    else
        for mj_candidate in python3.12 python3.11 python3; do
            if command -v "$mj_candidate" >/dev/null && mj_supported_python "$mj_candidate"; then
                mj_python="$(command -v "$mj_candidate")"
                break
            fi
        done
    fi

    if [[ -z "$mj_python" ]]; then
        echo "MJ requires Python 3.11/3.12. Installing a user-local Python 3.12 with uv."
        if command -v uv >/dev/null; then
            mj_uv=(uv)
        else
            command -v python3 >/dev/null || { echo "Install Python 3 with venv support, or uv." >&2; return 1; }
            mj_bootstrap="$(mktemp -d "${TMPDIR:-/tmp}/mj-python-bootstrap.XXXXXX")"
            if ! python3 -m venv "$mj_bootstrap"; then
                rm -rf -- "$mj_bootstrap"
                echo "Install python3-venv or uv, then rerun setup." >&2
                return 1
            fi
            if ! "$mj_bootstrap/bin/python" -m pip install --only-binary=:all: 'uv>=0.9,<1'; then
                rm -rf -- "$mj_bootstrap"
                return 1
            fi
            mj_uv=("$mj_bootstrap/bin/uv")
        fi
        if ! "${mj_uv[@]}" python install 3.12; then
            [[ -z "${mj_bootstrap:-}" ]] || rm -rf -- "$mj_bootstrap"
            return 1
        fi
        if ! mj_python="$("${mj_uv[@]}" python find --managed-python 3.12)"; then
            [[ -z "${mj_bootstrap:-}" ]] || rm -rf -- "$mj_bootstrap"
            return 1
        fi
        [[ -z "${mj_bootstrap:-}" ]] || rm -rf -- "$mj_bootstrap"
        mj_supported_python "$mj_python" || { echo "Downloaded Python is unsupported." >&2; return 1; }
    fi

    if [[ -e .venv || -L .venv ]]; then
        mj_backup=".venv-backup-$(date +%Y%m%d-%H%M%S)-$$"
        mv -- .venv "$mj_backup"
        echo "Preserved previous environment as $mj_backup (application data is unchanged)."
    fi
    "$mj_python" -m venv .venv
    .venv/bin/python --version
}
