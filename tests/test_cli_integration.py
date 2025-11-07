import json
import subprocess
import sys
from pathlib import Path


def run_py(script, *args, cwd=None):
    cmd = [sys.executable, script, *args]
    return subprocess.run(
        cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False
    )


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
