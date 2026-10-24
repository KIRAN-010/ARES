"""Regression coverage for Python 3.14 and Debian's missing ensurepip/pip."""
import os
from pathlib import Path
import shutil
import subprocess

HELPER = Path(__file__).resolve().parents[1] / "scripts" / "setup-python.sh"


def executable(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/bash\n" + content)
    path.chmod(0o755)
    return path


def python_shim(path, supported=True, pip=True):
    return executable(path, f"""
if [[ "$1" == '-c' ]]; then
  if [[ "$2" == *'_base_executable'* ]]; then echo "$0"; exit 0; fi
  exit {0 if supported else 1}
fi
if [[ "$1" == '-m' && "$2" == 'pip' ]]; then exit {0 if pip else 1}; fi
# Both of these intentionally fail, just like the user's Debian environment.
if [[ "$1" == '-m' && ( "$2" == 'venv' || "$2" == 'ensurepip' ) ]]; then exit 91; fi
if [[ "$1" == '--version' ]]; then echo 'Python 3.12.0'; exit 0; fi
exit 9
""")


def sandbox(tmp_path):
    commands = tmp_path / "bin"
    commands.mkdir()
    for name in ("mkdir", "cp", "mv", "date", "rm", "mktemp", "sh"):
        (commands / name).symlink_to(shutil.which(name))
    return commands


def uv_shim(path, ready_python):
    return executable(path, f"""
[[ "$*" == 'venv --python 3.12 --seed .venv' ]] || exit 8
mkdir -p .venv/bin
cp '{ready_python}' .venv/bin/python
echo seeded > uv-marker
""")


def invoke(tmp_path, commands, **extra):
    env = {k: v for k, v in os.environ.items() if k != "MJ_PYTHON"}
    env.update(PATH=str(commands), **extra)
    return subprocess.run(["/bin/bash", "-ec", 'source "$1"; mj_prepare_python', "setup", str(HELPER)],
                          cwd=tmp_path, env=env, text=True, capture_output=True)


def test_python314_environment_is_preserved_and_replaced(tmp_path):
    commands = sandbox(tmp_path)
    python_shim(commands / "python3", supported=False)
    python_shim(tmp_path / ".venv/bin/python", supported=False)
    (tmp_path / ".venv/keep-me").write_text("old environment")
    uv_shim(commands / "uv", python_shim(tmp_path / "ready/python"))
    result = invoke(tmp_path, commands)
    assert result.returncode == 0, result.stderr
    backups = list(tmp_path.glob(".venv-backup-*"))
    assert len(backups) == 1 and (backups[0] / "keep-me").read_text() == "old environment"
    assert (tmp_path / "uv-marker").exists()


def test_python312_without_ensurepip_or_pip_is_repaired(tmp_path):
    commands = sandbox(tmp_path)
    python_shim(commands / "python3.12", pip=False)
    python_shim(tmp_path / ".venv/bin/python", pip=False)
    uv_shim(commands / "uv", python_shim(tmp_path / "ready/python"))
    result = invoke(tmp_path, commands)
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "uv-marker").exists()
    assert len(list(tmp_path.glob(".venv-backup-*"))) == 1


def test_supported_environment_with_pip_reused(tmp_path):
    commands = sandbox(tmp_path)
    python_shim(tmp_path / ".venv/bin/python")
    (tmp_path / ".venv/sentinel").touch()
    result = invoke(tmp_path, commands)
    assert result.returncode == 0
    assert (tmp_path / ".venv/sentinel").exists() and not list(tmp_path.glob(".venv-backup-*"))


def test_invalid_override_fails_before_changing_environment(tmp_path):
    commands = sandbox(tmp_path)
    unsupported = python_shim(commands / "python3", supported=False)
    python_shim(tmp_path / ".venv/bin/python")
    result = invoke(tmp_path, commands, MJ_PYTHON=str(unsupported))
    assert result.returncode != 0 and "3.11 or 3.12" in result.stderr
    assert not list(tmp_path.glob(".venv-backup-*"))


def test_standalone_uv_bootstrap_needs_no_python_or_venv(tmp_path):
    commands = sandbox(tmp_path)
    fixture = uv_shim(tmp_path / "fixture/uv", python_shim(tmp_path / "ready/python"))
    installer = executable(tmp_path / "fixture/install.sh", '''
mkdir -p "$UV_UNMANAGED_INSTALL"
cp "$UV_FIXTURE" "$UV_UNMANAGED_INSTALL/uv"
''')
    executable(commands / "curl", '''
while [[ $# -gt 0 ]]; do
  if [[ "$1" == '-o' ]]; then cp "$INSTALLER_FIXTURE" "$2"; exit 0; fi
  shift
done
exit 8
''')
    scratch = tmp_path / "temporary"
    scratch.mkdir()
    result = invoke(tmp_path, commands, UV_FIXTURE=str(fixture), INSTALLER_FIXTURE=str(installer), TMPDIR=str(scratch))
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "uv-marker").exists()
    assert not list(scratch.iterdir())


def test_failed_bootstrap_keeps_existing_environment(tmp_path):
    commands = sandbox(tmp_path)
    python_shim(tmp_path / ".venv/bin/python", pip=False)
    executable(commands / "curl", "exit 22\n")
    scratch = tmp_path / "temporary"
    scratch.mkdir()
    result = invoke(tmp_path, commands, TMPDIR=str(scratch))
    assert result.returncode != 0
    assert (tmp_path / ".venv/bin/python").exists()
    assert not list(tmp_path.glob(".venv-backup-*")) and not list(scratch.iterdir())
