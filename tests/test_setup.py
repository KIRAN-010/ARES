"""Exercise interpreter selection without downloading Python or modifying the host."""
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


def python_shim(path, supported=True):
    return executable(path, f"""
if [[ "$1" == "-c" ]]; then exit {0 if supported else 1}; fi
if [[ "$1" == "-m" && "$2" == "venv" ]]; then
  mkdir -p "$3/bin"
  cp "$0" "$3/bin/python"
  exit 0
fi
if [[ "$1" == "-m" && "$2" == "ensurepip" ]]; then exit 0; fi
if [[ "$1" == "--version" ]]; then echo 'Python 3.12.0'; exit 0; fi
exit 9
""")


def sandbox(tmp_path):
    commands = tmp_path / "bin"
    commands.mkdir()
    for name in ("mkdir", "cp", "mv", "date", "rm", "mktemp", "dirname"):
        (commands / name).symlink_to(shutil.which(name))
    return commands


def invoke(tmp_path, commands, **extra):
    env = {**os.environ, "PATH": str(commands), **extra}
    env.pop("MJ_PYTHON", None)
    env.update(extra)
    return subprocess.run(["/bin/bash", "-ec", 'source "$1"; mj_prepare_python', "setup", str(HELPER)],
                          cwd=tmp_path, env=env, text=True, capture_output=True)


def test_python314_environment_is_preserved_and_replaced(tmp_path):
    commands = sandbox(tmp_path)
    python_shim(commands / "python3", supported=False)
    python_shim(commands / "python3.12")
    python_shim(tmp_path / ".venv/bin/python", supported=False)
    (tmp_path / ".venv/keep-me").write_text("old environment")
    result = invoke(tmp_path, commands)
    assert result.returncode == 0, result.stderr
    backups = list(tmp_path.glob(".venv-backup-*"))
    assert len(backups) == 1 and (backups[0] / "keep-me").read_text() == "old environment"
    assert subprocess.run([str(tmp_path / ".venv/bin/python"), "-c", "check"]).returncode == 0


def test_unsupported_system_python_downloads_managed312(tmp_path):
    commands = sandbox(tmp_path)
    python_shim(commands / "python3", supported=False)
    managed = python_shim(tmp_path / "managed/python")
    executable(commands / "uv", f"""
if [[ "$*" == 'python install 3.12' ]]; then echo installed > download-marker; exit 0; fi
if [[ "$*" == 'python find --managed-python 3.12' ]]; then echo '{managed}'; exit 0; fi
exit 8
""")
    result = invoke(tmp_path, commands)
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "download-marker").exists()
    assert (tmp_path / ".venv/bin/python").exists()


def test_supported_environment_reused(tmp_path):
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
    assert (tmp_path / ".venv/bin/python").exists() and not list(tmp_path.glob(".venv-backup-*"))


def test_bootstraps_uv_without_touching_system_python(tmp_path):
    commands = sandbox(tmp_path)
    managed = python_shim(tmp_path / "managed/python")
    uv = executable(tmp_path / "fixture/uv", f"""
if [[ "$*" == 'python install 3.12' ]]; then exit 0; fi
if [[ "$*" == 'python find --managed-python 3.12' ]]; then echo '{managed}'; exit 0; fi
exit 8
""")
    executable(commands / "python3", """
if [[ "$1" == '-c' ]]; then exit 1; fi
if [[ "$1" == '-m' && "$2" == 'venv' ]]; then
  mkdir -p "$3/bin"; cp "$0" "$3/bin/python"; exit 0
fi
if [[ "$1" == '-m' && "$2" == 'pip' ]]; then
  cp "$UV_FIXTURE" "$(dirname "$0")/uv"; exit 0
fi
exit 9
""")
    scratch = tmp_path / "temporary"
    scratch.mkdir()
    result = invoke(tmp_path, commands, UV_FIXTURE=str(uv), TMPDIR=str(scratch))
    assert result.returncode == 0, result.stderr
    assert (tmp_path / ".venv/bin/python").exists()
    assert not list(scratch.iterdir()), "Temporary bootstrap environment must be removed"
