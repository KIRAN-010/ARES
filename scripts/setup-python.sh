#!/usr/bin/env bash
# Sourced by setup.sh from the repository root. No apt, sudo or ensurepip required.
mj_supported_python() {
    "$1" -c 'import sys; raise SystemExit(not (sys.implementation.name == "cpython" and sys.version_info[:2] in {(3, 11), (3, 12)}))' 2>/dev/null
}

mj_prepare_python() {
    local mj_python="3.12" mj_bootstrap="" mj_backup mj_uv
    if [[ -n "${MJ_PYTHON:-}" ]]; then
        mj_supported_python "$MJ_PYTHON" || {
            echo "MJ_PYTHON must point to CPython 3.11 or 3.12." >&2
            return 1
        }
        # Resolve the base interpreter before backing up a possibly selected venv.
        mj_python="$("$MJ_PYTHON" -c 'import sys; print(sys._base_executable)')"
    elif [[ -x .venv/bin/python ]] && mj_supported_python .venv/bin/python &&
            .venv/bin/python -m pip --version >/dev/null 2>&1; then
        echo "Reusing supported Python environment with working pip."
        return 0
    fi

    if command -v uv >/dev/null; then
        mj_uv="$(command -v uv)"
    else
        # The standalone installer needs neither Python, pip, venv nor root access.
        command -v curl >/dev/null || { echo "Install curl or uv, then rerun setup." >&2; return 1; }
        mj_bootstrap="$(mktemp -d "${TMPDIR:-/tmp}/mj-uv-bootstrap.XXXXXX")"
        echo "Installing a temporary user-local uv (no sudo or Python bootstrap needed)."
        if ! curl --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 120 -fsSL \
                https://astral.sh/uv/install.sh -o "$mj_bootstrap/install.sh" ||
                ! UV_UNMANAGED_INSTALL="$mj_bootstrap/bin" sh "$mj_bootstrap/install.sh"; then
            rm -rf -- "$mj_bootstrap"
            return 1
        fi
        mj_uv="$mj_bootstrap/bin/uv"
    fi

    if [[ -e .venv || -L .venv ]]; then
        mj_backup=".venv-backup-$(date +%Y%m%d-%H%M%S)-$$"
        mv -- .venv "$mj_backup"
        echo "Preserved previous environment as $mj_backup (application data is unchanged)."
    fi
    echo "Creating Python $mj_python environment with uv; pip is seeded without ensurepip."
    if ! "$mj_uv" venv --python "$mj_python" --seed .venv; then
        [[ -z "$mj_bootstrap" ]] || rm -rf -- "$mj_bootstrap"
        echo "Environment creation failed. Any previous environment remains in its backup directory." >&2
        return 1
    fi
    [[ -z "$mj_bootstrap" ]] || rm -rf -- "$mj_bootstrap"
    mj_supported_python .venv/bin/python || { echo "Created Python is unsupported." >&2; return 1; }
    .venv/bin/python -m pip --version
    .venv/bin/python --version
}
