import json
import shutil
import subprocess
import sys
from pathlib import Path


def run_py(script, *args, cwd=None):
    # Use installed entry points if available, otherwise fall back to script files
    if script == "envdiff.py":
        # Try entry point first (works when package is installed in CI)
        entry_point = shutil.which("envdiff")
        if entry_point:
            cmd = [entry_point, *args]
        else:
            # Fall back to running script file directly (for local development)
            script_path = Path(__file__).parent.parent / "envdiff.py"
            cmd = [sys.executable, str(script_path), *args]
    elif script == "envset.py":
        entry_point = shutil.which("envset")
        if entry_point:
            cmd = [entry_point, *args]
        else:
            script_path = Path(__file__).parent.parent / "envset.py"
            cmd = [sys.executable, str(script_path), *args]
    else:
        cmd = [sys.executable, script, *args]
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)


def test_envdiff_cli_json_and_check(tmp_path: Path):
    source_yml = tmp_path / "src.yml"
    target_env = tmp_path / ".env"
    source_yml.write_text("APP: one\nX: 1\n", encoding="utf-8")
    target_env.write_text("APP=one\n", encoding="utf-8")

    r = run_py(
        "envdiff.py",
        "--source",
        str(source_yml),
        "--target",
        str(target_env),
        "--format",
        "json",
        "--check",
    )
    assert r.returncode == 5
    data = json.loads(r.stdout)
    assert data["summary"]["missing"] == 1
    assert data["check"]["status"] == "fail"


def test_envdiff_apply_dry_run(tmp_path: Path):
    source_yml = tmp_path / "src.yml"
    target_env = tmp_path / ".env"
    source_yml.write_text("A: 1\n", encoding="utf-8")
    target_env.write_text("", encoding="utf-8")
    r = run_py(
        "envdiff.py",
        "--source",
        str(source_yml),
        "--target",
        str(target_env),
        "--apply",
        "--apply-dry-run",
    )
    assert r.returncode == 0
    assert "would write the following .env content" in r.stdout


def test_envset_cli_env_and_yaml(tmp_path: Path):
    envp = tmp_path / ".env"
    ymlp = tmp_path / "c.yml"
    envp.write_text("A=1\n", encoding="utf-8")
    ymlp.write_text("a: {b: 1}\n", encoding="utf-8")

    r1 = run_py("envset.py", "--files", str(envp), str(ymlp), "--key", "A", "--value", "2")
    assert r1.returncode == 0
    assert "updated" in r1.stdout
    assert "A=2" in envp.read_text(encoding="utf-8")


def test_envset_cli_configpy_rewrite_constant(tmp_path: Path):
    cfg = tmp_path / "config.py"
    cfg.write_text("RABBITMQ_USER='old'\n", encoding="utf-8")
    r = run_py(
        "envset.py", "--files", str(cfg), "--key", "RABBITMQ_USER", "--value", "root", "--rewrite"
    )
    assert r.returncode == 0
    out = cfg.read_text(encoding="utf-8")
    assert "RABBITMQ_USER = 'root'" in out or 'RABBITMQ_USER = "root"' in out
