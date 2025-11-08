import re
from pathlib import Path

import envset


def test_configpy_append_constant():
    base = "CONFIG = {}\n"
    out = envset.set_configpy_assign_block(base, "API_KEY", "abc")
    assert "CONFIG['API_KEY'] = 'abc'" in out


def test_configpy_append_dict_into_config():
    base = "CONFIG = {}\n"
    out = envset.set_configpy_assign_block(base, "database.host", "db.local")
    assert "CONFIG['database']['host'] = " in out


def test_configpy_append_dict_create_config_when_missing():
    base = "# no CONFIG here\n"
    out = envset.set_configpy_assign_block(base, "service.timeout", 5)
    assert "CONFIG = {}" in out
    assert "CONFIG['service']['timeout'] = 5" in out


def test_single_quoted_constant(tmp_path: Path):
    """Test handling of single-quoted constants like RABBITMQ_USER='TATA'."""
    cfg = tmp_path / "config.py"
    cfg.write_text("RABBITMQ_USER='TATA'\n", encoding="utf-8")

    from tests.test_cli_integration import run_py

    # Test rewriting single-quoted constant
    r = run_py(
        "envset.py",
        "--files",
        str(cfg),
        "--key",
        "RABBITMQ_USER",
        "--value",
        "NEW_VALUE",
        "--rewrite",
    )
    assert r.returncode == 0
    content = cfg.read_text(encoding="utf-8")
    assert "RABBITMQ_USER" in content
    assert "NEW_VALUE" in content
    # Should use single quotes (Python's repr prefers single quotes for strings)
    assert "'NEW_VALUE'" in content or '"NEW_VALUE"' in content

    # Test adding new single-quoted constant
    cfg2 = tmp_path / "config2.py"
    cfg2.write_text("# Empty\n", encoding="utf-8")
    r2 = run_py("envset.py", "--files", str(cfg2), "--key", "RABBITMQ_USER", "--value", "TATA")
    assert r2.returncode == 0
    content2 = cfg2.read_text(encoding="utf-8")
    assert "RABBITMQ_USER" in content2
    assert "TATA" in content2


def test_rewrite_constant_inplace_when_present():
    base = "RABBITMQ_USER = 'old'\n"
    const_re = re.compile(rf"^(\s*){'RABBITMQ_USER'}\s*=\s*.*?$", re.M)
    new_line = rf"\1{'RABBITMQ_USER'} = {repr('new')}"
    out = const_re.sub(new_line, base, count=1)
    assert "RABBITMQ_USER = 'new'" in out


def test_rewrite_dict_assignment_when_present():
    base = "CONFIG['database']['host'] = 'db.old'\n"
    parts = ["database", "host"]
    idx = "".join([f"[{repr(p)}]" for p in parts])
    dict_re = re.compile(rf"^(\s*)(CONFIG|ENV){re.escape(idx)}\s*=\s*.*?$", re.M)
    new_line = rf"\1\2{idx} = {repr('db.new')}"
    out = dict_re.sub(new_line, base, count=1)
    assert "CONFIG['database']['host'] = 'db.new'" in out
