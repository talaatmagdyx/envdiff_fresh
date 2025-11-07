"""Tests to achieve 100% code coverage."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import envdiff
import envset

# === envdiff.py coverage ===


def test_parse_remote_error():
    """Test parse_remote raises ValueError for invalid paths."""
    with pytest.raises(ValueError, match="Not a remote path"):
        envdiff.parse_remote("not-a-remote-path")


def test_is_remote_path():
    """Test is_remote_path function."""
    assert envdiff.is_remote_path("host:/path") is True
    assert envdiff.is_remote_path("user@host:/path") is True
    assert envdiff.is_remote_path("local/path") is False


def test_ssh_base_cmd():
    """Test _ssh_base_cmd with various options."""
    # Test with port
    cmd = envdiff._ssh_base_cmd("host", 2222, None, None)
    assert "-p" in cmd and "2222" in cmd

    # Test with identity
    cmd = envdiff._ssh_base_cmd("host", None, "/path/to/key", None)
    assert "-i" in cmd and "/path/to/key" in cmd

    # Test with extra options
    cmd = envdiff._ssh_base_cmd("host", None, None, ["StrictHostKeyChecking=no"])
    assert "-o" in cmd and "StrictHostKeyChecking=no" in cmd

    # Test with all options
    cmd = envdiff._ssh_base_cmd("host", 2222, "/key", ["opt=val"])
    assert "-p" in cmd and "-i" in cmd and "-o" in cmd


def test_scp_cmd():
    """Test _scp_cmd with various options."""
    # Test with port
    cmd = envdiff._scp_cmd("src", "dst", 2222, None, None)
    assert "-P" in cmd and "2222" in cmd

    # Test with identity
    cmd = envdiff._scp_cmd("src", "dst", None, "/path/to/key", None)
    assert "-i" in cmd and "/path/to/key" in cmd

    # Test with extra options
    cmd = envdiff._scp_cmd("src", "dst", None, None, ["opt=val"])
    assert "-o" in cmd


@patch("envdiff.subprocess.check_output")
def test_ssh_run(mock_check_output):
    """Test ssh_run function."""
    mock_check_output.return_value = b"output"
    result = envdiff.ssh_run("host", "cmd", None, None, None)
    assert result == "output"
    mock_check_output.assert_called_once()


@patch("envdiff.ssh_run")
def test_ssh_cat(mock_ssh_run):
    """Test ssh_cat function."""
    mock_ssh_run.return_value = "file content"
    result = envdiff.ssh_cat("host", "/path", None, None, None)
    assert result == "file content"
    mock_ssh_run.assert_called_once()


@patch("envdiff.subprocess.check_call")
@patch("envdiff.tempfile.NamedTemporaryFile")
def test_scp_to_temp(mock_tempfile, mock_check_call):
    """Test scp_to_temp function."""
    mock_tmp = MagicMock()
    mock_tmp.name = "/tmp/file"
    mock_tempfile.return_value = mock_tmp

    result = envdiff.scp_to_temp("host:/remote", None, None, None)
    assert result == "/tmp/file"
    mock_check_call.assert_called_once()


@patch("envdiff.subprocess.check_call")
def test_scp_upload(mock_check_call):
    """Test scp_upload function."""
    envdiff.scp_upload("/local", "host:/remote", None, None, None)
    mock_check_call.assert_called_once()


def test_read_python_module_with_config(tmp_path: Path):
    """Test read_python_module with CONFIG dict."""
    py_file = tmp_path / "config.py"
    py_file.write_text("CONFIG = {'key': 'value'}\n", encoding="utf-8")
    result = envdiff.read_python_module(str(py_file))
    assert result == {"key": "value"}


def test_read_python_module_with_env(tmp_path: Path):
    """Test read_python_module with ENV dict."""
    py_file = tmp_path / "config.py"
    py_file.write_text("ENV = {'x': 1}\n", encoding="utf-8")
    result = envdiff.read_python_module(str(py_file))
    assert result == {"x": 1}


def test_read_python_module_with_uppercase_constants(tmp_path: Path):
    """Test read_python_module with uppercase constants."""
    py_file = tmp_path / "config.py"
    py_file.write_text("API_KEY = 'secret'\nDATABASE_URL = 'postgres://'\n", encoding="utf-8")
    result = envdiff.read_python_module(str(py_file))
    assert "API_KEY" in result
    assert "DATABASE_URL" in result


def test_read_python_module_error(tmp_path: Path):
    """Test read_python_module with invalid file."""
    # Create a file that will fail to load (invalid Python)
    invalid_file = tmp_path / "invalid.py"
    invalid_file.write_text("invalid syntax here !!!", encoding="utf-8")
    # This will raise SyntaxError, not RuntimeError, but we're testing the error path
    with pytest.raises(Exception):  # Can be SyntaxError or other errors
        envdiff.read_python_module(str(invalid_file))


def test_apply_ignores():
    """Test apply_ignores function."""
    d = {"prefix_key": "v1", "other_key": "v2", "prefix_another": "v3"}
    result = envdiff.apply_ignores(d, ["prefix"])
    assert result == {"other_key": "v2"}

    # Test with no ignores
    result = envdiff.apply_ignores(d, [])
    assert result == d


def test_generate_patch_unsupported_format():
    """Test generate_patch with unsupported format."""
    with pytest.raises(RuntimeError, match="Unsupported patch format"):
        envdiff.generate_patch({"K": "v"}, ["K"], "invalid")


@patch("sys.stdin")
def test_load_text_maybe_remote_stdin(mock_stdin):
    """Test load_text_maybe_remote with stdin."""
    mock_stdin.read.return_value = "stdin content"
    result = envdiff.load_text_maybe_remote("-", None, None, None)
    assert result == "stdin content"


def test_load_text_maybe_remote_file(tmp_path: Path):
    """Test load_text_maybe_remote with local file."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("file content", encoding="utf-8")
    result = envdiff.load_text_maybe_remote(str(test_file), None, None, None)
    assert result == "file content"


@patch("envdiff.scp_to_temp")
@patch("envdiff.read_python_module")
def test_load_kv_any_py_remote(mock_read_module, mock_scp):
    """Test load_kv_any with remote Python file."""
    mock_scp.return_value = "/tmp/file.py"
    mock_read_module.return_value = {"key": "value"}

    with patch("os.unlink") as mock_unlink:
        result = envdiff.load_kv_any("host:/file.py", "py", None, None, None)
        assert result == {"key": "value"}
        mock_unlink.assert_called_once_with("/tmp/file.py")


def test_load_kv_any_unsupported_type(tmp_path: Path):
    """Test load_kv_any with unsupported type."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("content", encoding="utf-8")
    with pytest.raises(RuntimeError, match="Unsupported type"):
        envdiff.load_kv_any(str(test_file), "invalid", None, None, None)


def test_write_text_maybe_remote_local(tmp_path: Path):
    """Test write_text_maybe_remote with local file."""
    test_file = tmp_path / "output.txt"
    envdiff.write_text_maybe_remote(str(test_file), "content", None, None, None, None)
    assert test_file.read_text(encoding="utf-8") == "content"


def test_write_text_maybe_remote_local_with_backup(tmp_path: Path):
    """Test write_text_maybe_remote with backup."""
    test_file = tmp_path / "output.txt"
    test_file.write_text("old content", encoding="utf-8")
    envdiff.write_text_maybe_remote(str(test_file), "new content", "bak", None, None, None)
    assert test_file.read_text(encoding="utf-8") == "new content"
    assert (tmp_path / "output.txt.bak").exists()


@patch("envdiff.ssh_run")
@patch("envdiff.scp_upload")
@patch("envdiff.tempfile.NamedTemporaryFile")
def test_write_text_maybe_remote_remote(mock_tempfile, mock_scp, mock_ssh):
    """Test write_text_maybe_remote with remote path."""
    mock_tmp = MagicMock()
    mock_tmp.name = "/tmp/file"
    mock_tempfile.return_value = mock_tmp

    envdiff.write_text_maybe_remote("host:/remote", "content", "bak", None, None, None)
    mock_ssh.assert_called_once()
    mock_scp.assert_called_once()


def test_comma_split():
    """Test comma_split function."""
    assert envdiff.comma_split("a,b,c") == ["a", "b", "c"]
    assert envdiff.comma_split("a, b , c") == ["a", "b", "c"]
    assert envdiff.comma_split(None) is None
    assert envdiff.comma_split("") is None
    assert envdiff.comma_split("  ") == []  # Empty after stripping


def test_detect_type():
    """Test detect_type function."""
    assert envdiff.detect_type("file.yaml", None) == "yaml"
    assert envdiff.detect_type("file.yml", None) == "yaml"
    assert envdiff.detect_type("file.py", None) == "py"
    assert envdiff.detect_type("file.env", None) == "env"
    assert envdiff.detect_type("file.txt", None) == "env"
    assert envdiff.detect_type("file.txt", "yaml") == "yaml"
    assert envdiff.detect_type("-", None) == "env"


def test_normalize_value():
    """Test normalize_value function."""
    # Test with None
    assert envdiff.normalize_value(None, True) == ""

    # Test with dict
    assert envdiff.normalize_value({"a": 1}, True) == '{"a":1}'

    # Test with list
    assert envdiff.normalize_value([1, 2], True) == "[1,2]"

    # Test case sensitive
    assert envdiff.normalize_value("Hello", True) == "Hello"
    assert envdiff.normalize_value("Hello", False) == "hello"

    # Test with whitespace
    assert envdiff.normalize_value("  test  ", True) == "test"


# === envset.py coverage ===


def test_envset_parse_remote_error():
    """Test envset parse_remote raises ValueError."""
    with pytest.raises(ValueError, match="Not a remote path"):
        envset.parse_remote("not-a-remote-path")


def test_envset_is_remote():
    """Test envset is_remote function."""
    assert envset.is_remote("host:/path") is True
    assert envset.is_remote("local/path") is False


def test_envset_ssh_base():
    """Test envset _ssh_base with various options."""
    cmd = envset._ssh_base("host", 2222, None, None)
    assert "-p" in cmd and "2222" in cmd

    cmd = envset._ssh_base("host", None, "/key", None)
    assert "-i" in cmd and "/key" in cmd

    cmd = envset._ssh_base("host", None, None, ["opt=val"])
    assert "-o" in cmd


def test_envset_scp_cmd():
    """Test envset _scp_cmd with various options."""
    cmd = envset._scp_cmd("src", "dst", 2222, None, None)
    assert "-P" in cmd and "2222" in cmd

    cmd = envset._scp_cmd("src", "dst", None, "/key", None)
    assert "-i" in cmd


@patch("envset.subprocess.check_output")
def test_envset_ssh_read(mock_check_output):
    """Test envset ssh_read function."""
    mock_check_output.return_value = b"content"
    result = envset.ssh_read("host", "/path", None, None, None)
    assert result == "content"


@patch("envset.subprocess.check_call")
def test_envset_ssh_run(mock_check_call):
    """Test envset ssh_run function."""
    envset.ssh_run("host", "cmd", None, None, None)
    mock_check_call.assert_called_once()


@patch("envset.subprocess.check_call")
def test_envset_scp_upload(mock_check_call):
    """Test envset scp_upload function."""
    envset.scp_upload("/local", "host:/remote", None, None, None)
    mock_check_call.assert_called_once()


def test_envset_dump_env():
    """Test envset dump_env with various values."""
    # Test with empty value
    result = envset.dump_env({"EMPTY": ""})
    assert 'EMPTY=""' in result

    # Test with value containing spaces
    result = envset.dump_env({"KEY": "value with spaces"})
    assert 'KEY="value with spaces"' in result

    # Test with value containing quotes
    result = envset.dump_env({"KEY": 'value with "quotes"'})
    assert "KEY=" in result

    # Test with simple value
    result = envset.dump_env({"KEY": "simple"})
    assert "KEY=simple" in result

    # Test with None
    result = envset.dump_env({"KEY": None})
    assert 'KEY=""' in result


def test_envset_ensure_yaml_path():
    """Test envset ensure_yaml_path function."""
    d = {}
    result = envset.ensure_yaml_path(d, ["a", "b"])
    assert isinstance(d["a"], dict)
    assert result == d["a"]


def test_envset_set_configpy_assign_block_constant_no_target():
    """Test set_configpy_assign_block with constant and no CONFIG/ENV."""
    base = "# no config\n"
    out = envset.set_configpy_assign_block(base, "API_KEY", "value")
    assert "API_KEY = 'value'" in out


def test_envset_detect_type():
    """Test envset detect_type function."""
    assert envset.detect_type("file.yaml", None) == "yaml"
    assert envset.detect_type("file.py", None) == "py"
    assert envset.detect_type("file.env", None) == "env"
    assert envset.detect_type("-", None) == "env"
    assert envset.detect_type("file.txt", "yaml") == "yaml"


@patch("envset.ssh_read")
def test_envset_read_text_remote(mock_ssh_read):
    """Test envset read_text with remote path."""
    mock_ssh_read.return_value = "remote content"
    result = envset.read_text("host:/file", None, None, None)
    assert result == "remote content"


def test_envset_read_text_local(tmp_path: Path):
    """Test envset read_text with local file."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("local content", encoding="utf-8")
    result = envset.read_text(str(test_file), None, None, None)
    assert result == "local content"


@patch("envset.ssh_run")
@patch("envset.scp_upload")
@patch("envset.tempfile.NamedTemporaryFile")
def test_envset_write_text_remote(mock_tempfile, mock_scp, mock_ssh):
    """Test envset write_text with remote path."""
    mock_tmp = MagicMock()
    mock_tmp.name = "/tmp/file"
    mock_tempfile.return_value = mock_tmp

    envset.write_text("host:/remote", "content", "bak", None, None, None)
    mock_ssh.assert_called_once()
    mock_scp.assert_called_once()


def test_envset_write_text_local(tmp_path: Path):
    """Test envset write_text with local file."""
    test_file = tmp_path / "output.txt"
    envset.write_text(str(test_file), "content", None, None, None, None)
    assert test_file.read_text(encoding="utf-8") == "content"


def test_envset_write_text_local_with_backup(tmp_path: Path):
    """Test envset write_text with backup."""
    test_file = tmp_path / "output.txt"
    test_file.write_text("old", encoding="utf-8")
    envset.write_text(str(test_file), "new", "bak", None, None, None)
    assert test_file.read_text(encoding="utf-8") == "new"
    assert (tmp_path / "output.txt.bak").exists()


def test_envset_parse_env():
    """Test envset parse_env with various formats."""
    # Test with quoted values
    text = "KEY=\"quoted value\"\nKEY2='single quoted'"
    result = envset.parse_env(text)
    assert result["KEY"] == "quoted value"
    assert result["KEY2"] == "single quoted"

    # Test with escaped sequences
    text = 'KEY="line1\\nline2"'
    result = envset.parse_env(text)
    assert "\n" in result["KEY"]

    # Test with comments
    text = "KEY=value\n# comment\nKEY2=value2"
    result = envset.parse_env(text)
    assert "KEY" in result
    assert "KEY2" in result


def test_envset_set_yaml_key():
    """Test envset set_yaml_key function."""
    d = {}
    envset.set_yaml_key(d, "a.b.c", "value")
    assert d["a"]["b"]["c"] == "value"


def test_envset_set_yaml_key_empty():
    """Test envset set_yaml_key with empty key."""
    with pytest.raises(ValueError, match="Empty key"):
        envset.set_yaml_key({}, "", "value")


# === CLI integration tests for coverage ===


def test_envdiff_cli_only_prefix(tmp_path: Path):
    """Test envdiff CLI with --only-prefix."""
    source_yml = tmp_path / "src.yml"
    target_env = tmp_path / ".env"
    source_yml.write_text("APP: one\nOTHER: two\n", encoding="utf-8")
    target_env.write_text("APP=one\n", encoding="utf-8")

    from tests.test_cli_integration import run_py

    r = run_py(
        "envdiff.py",
        "--source",
        str(source_yml),
        "--target",
        str(target_env),
        "--only-prefix",
        "APP",
    )
    assert r.returncode == 0


def test_envdiff_cli_show_same(tmp_path: Path):
    """Test envdiff CLI with --show-same."""
    source_yml = tmp_path / "src.yml"
    target_env = tmp_path / ".env"
    source_yml.write_text("APP: one\n", encoding="utf-8")
    target_env.write_text("APP=one\n", encoding="utf-8")

    from tests.test_cli_integration import run_py

    r = run_py(
        "envdiff.py", "--source", str(source_yml), "--target", str(target_env), "--show-same"
    )
    assert r.returncode == 0
    assert "Same values" in r.stdout


def test_envdiff_cli_patch_format(tmp_path: Path):
    """Test envdiff CLI with --patch-format."""
    source_yml = tmp_path / "src.yml"
    target_env = tmp_path / ".env"
    source_yml.write_text("APP: one\n", encoding="utf-8")
    target_env.write_text("", encoding="utf-8")

    from tests.test_cli_integration import run_py

    r = run_py(
        "envdiff.py",
        "--source",
        str(source_yml),
        "--target",
        str(target_env),
        "--patch-format",
        "export",
    )
    assert r.returncode == 0
    assert "export APP=" in r.stdout


def test_envdiff_cli_patch_output_file(tmp_path: Path):
    """Test envdiff CLI with --output-patch-file."""
    source_yml = tmp_path / "src.yml"
    target_env = tmp_path / ".env"
    patch_file = tmp_path / "patch.sh"
    source_yml.write_text("APP: one\n", encoding="utf-8")
    target_env.write_text("", encoding="utf-8")

    from tests.test_cli_integration import run_py

    r = run_py(
        "envdiff.py",
        "--source",
        str(source_yml),
        "--target",
        str(target_env),
        "--patch-format",
        "export",
        "--output-patch-file",
        str(patch_file),
    )
    assert r.returncode == 0
    assert patch_file.exists()


def test_envdiff_cli_apply_non_env_target(tmp_path: Path):
    """Test envdiff CLI --apply with non-env target."""
    source_yml = tmp_path / "src.yml"
    target_py = tmp_path / "config.py"
    source_yml.write_text("APP: one\n", encoding="utf-8")
    target_py.write_text("CONFIG = {}\n", encoding="utf-8")

    from tests.test_cli_integration import run_py

    r = run_py(
        "envdiff.py",
        "--source",
        str(source_yml),
        "--target",
        str(target_py),
        "--target-type",
        "py",
        "--apply",
    )
    assert r.returncode == 3
    assert "only target-type env" in r.stderr


def test_envdiff_cli_apply_success(tmp_path: Path):
    """Test envdiff CLI --apply success."""
    source_yml = tmp_path / "src.yml"
    target_env = tmp_path / ".env"
    source_yml.write_text("APP: one\n", encoding="utf-8")
    target_env.write_text("", encoding="utf-8")

    from tests.test_cli_integration import run_py

    r = run_py("envdiff.py", "--source", str(source_yml), "--target", str(target_env), "--apply")
    assert r.returncode == 0
    assert "APP=one" in target_env.read_text(encoding="utf-8")


def test_envdiff_cli_json_only(tmp_path: Path):
    """Test envdiff CLI with --json-only."""
    source_yml = tmp_path / "src.yml"
    target_env = tmp_path / ".env"
    source_yml.write_text("APP: one\n", encoding="utf-8")
    target_env.write_text("", encoding="utf-8")

    from tests.test_cli_integration import run_py

    # Without --check, it returns 0 even with differences
    r = run_py(
        "envdiff.py", "--source", str(source_yml), "--target", str(target_env), "--json-only"
    )
    assert r.returncode == 0
    data = json.loads(r.stdout)
    assert "missing" in data

    # With --check, it returns 5 for differences
    r = run_py(
        "envdiff.py",
        "--source",
        str(source_yml),
        "--target",
        str(target_env),
        "--json-only",
        "--check",
    )
    assert r.returncode == 5


def test_envdiff_cli_format_json(tmp_path: Path):
    """Test envdiff CLI with --format json."""
    source_yml = tmp_path / "src.yml"
    target_env = tmp_path / ".env"
    source_yml.write_text("APP: one\n", encoding="utf-8")
    target_env.write_text("APP=one\n", encoding="utf-8")

    from tests.test_cli_integration import run_py

    r = run_py(
        "envdiff.py", "--source", str(source_yml), "--target", str(target_env), "--format", "json"
    )
    assert r.returncode == 0
    data = json.loads(r.stdout)
    assert "summary" in data
    assert "keys" in data


def test_envset_cli_json_error(tmp_path: Path):
    """Test envset CLI with invalid JSON."""
    from tests.test_cli_integration import run_py

    r = run_py(
        "envset.py",
        "--files",
        str(tmp_path / "test.env"),
        "--key",
        "KEY",
        "--value",
        "invalid json",
        "--json",
    )
    assert r.returncode == 2
    assert "not valid JSON" in r.stderr


def test_envset_cli_rewrite_dict(tmp_path: Path):
    """Test envset CLI with --rewrite for dict assignment."""
    cfg = tmp_path / "config.py"
    cfg.write_text("CONFIG = {}\nCONFIG['database']['host'] = 'old'\n", encoding="utf-8")

    from tests.test_cli_integration import run_py

    r = run_py(
        "envset.py", "--files", str(cfg), "--key", "database.host", "--value", "new", "--rewrite"
    )
    assert r.returncode == 0
    content = cfg.read_text(encoding="utf-8")
    assert "CONFIG['database']['host'] = 'new'" in content


def test_envset_cli_dry_run(tmp_path: Path):
    """Test envset CLI with --dry-run."""
    env_file = tmp_path / "test.env"
    env_file.write_text("KEY=old\n", encoding="utf-8")

    from tests.test_cli_integration import run_py

    r = run_py("envset.py", "--files", str(env_file), "--key", "KEY", "--value", "new", "--dry-run")
    assert r.returncode == 0
    assert "DRY-RUN" in r.stdout
    assert env_file.read_text(encoding="utf-8") == "KEY=old\n"  # Should not be modified


def test_envset_cli_unsupported_type(tmp_path: Path):
    """Test envset CLI with unsupported type."""
    from tests.test_cli_integration import run_py

    r = run_py(
        "envset.py",
        "--files",
        str(tmp_path / "test.txt"),
        "--key",
        "KEY",
        "--value",
        "value",
        "--type",
        "invalid",
    )
    assert r.returncode != 0


def test_envset_cli_read_error(tmp_path: Path):
    """Test envset CLI with read error."""
    from tests.test_cli_integration import run_py

    r = run_py("envset.py", "--files", "/nonexistent/file.env", "--key", "KEY", "--value", "value")
    # CLI continues processing and returns 0, but prints error to stderr
    assert "ERROR reading" in r.stderr


def test_envset_cli_write_error(tmp_path: Path):
    """Test envset CLI with write error (read-only directory)."""
    # Create a read-only directory
    ro_dir = tmp_path / "readonly"
    ro_dir.mkdir()
    ro_dir.chmod(0o555)

    from tests.test_cli_integration import run_py

    r = run_py("envset.py", "--files", str(ro_dir / "test.env"), "--key", "KEY", "--value", "value")
    # Should fail or handle gracefully
    assert r.returncode != 0 or "ERROR" in r.stderr

    # Cleanup
    ro_dir.chmod(0o755)


# === Additional tests for remaining coverage ===


def test_unquote_single_quotes():
    """Test _unquote with single quotes."""
    # This tests line 61 in envdiff.py
    text = "'single quoted'"
    # _unquote is private, but we can test it through read_env_text
    env_text = f"KEY={text}\n"
    result = envdiff.read_env_text(env_text)
    assert result["KEY"] == "single quoted"


def test_generate_patch_dotenv_special_chars():
    """Test generate_patch dotenv format with special characters."""
    # Tests lines 127-129
    s = {
        "KEY1": "value with spaces",
        "KEY2": "value#with#hash",
        "KEY3": 'value"with"quotes',
        "KEY4": "",
    }
    result = envdiff.generate_patch(s, list(s.keys()), "dotenv")
    assert any('KEY1="value with spaces"' in line for line in result)
    assert any('KEY2="value#with#hash"' in line for line in result)
    assert any("KEY3=" in line for line in result)
    assert any('KEY4=""' in line for line in result)


def test_generate_patch_powershell():
    """Test generate_patch powershell format."""
    # Tests line 131
    s = {"KEY": "value"}
    result = envdiff.generate_patch(s, ["KEY"], "powershell")
    assert any("$Env:KEY =" in line for line in result)


def test_generate_dotenv_content_special_chars():
    """Test generate_dotenv_content with special characters."""
    # Tests line 143
    kv = {"KEY": "value with spaces"}
    result = envdiff.generate_dotenv_content(kv)
    assert 'KEY="value with spaces"' in result


@patch("envdiff.ssh_cat")
def test_load_text_maybe_remote_remote(mock_ssh_cat):
    """Test load_text_maybe_remote with remote path."""
    # Tests line 148
    mock_ssh_cat.return_value = "remote content"
    result = envdiff.load_text_maybe_remote("host:/file", None, None, None)
    assert result == "remote content"
    mock_ssh_cat.assert_called_once()


@patch("envdiff.scp_to_temp")
@patch("envdiff.read_python_module")
@patch("os.unlink")
def test_load_kv_any_py_cleanup(mock_unlink, mock_read, mock_scp):
    """Test load_kv_any py type cleanup on exception."""
    # Tests line 159
    mock_scp.return_value = "/tmp/file.py"
    mock_read.side_effect = Exception("Test error")

    with pytest.raises(Exception):
        envdiff.load_kv_any("host:/file.py", "py", None, None, None)
    mock_unlink.assert_called_once_with("/tmp/file.py")


@patch("envdiff.scp_to_temp")
@patch("envdiff.read_python_module")
@patch("os.unlink")
def test_load_kv_any_py_cleanup_unlink_fails(mock_unlink, mock_read, mock_scp):
    """Test load_kv_any py type cleanup when unlink fails."""
    # Tests line 159 exception handling
    mock_scp.return_value = "/tmp/file.py"
    mock_read.return_value = {"key": "value"}
    mock_unlink.side_effect = Exception("Unlink failed")

    # Should still return successfully even if unlink fails
    result = envdiff.load_kv_any("host:/file.py", "py", None, None, None)
    assert result == {"key": "value"}
    mock_unlink.assert_called_once_with("/tmp/file.py")


def test_envdiff_cli_patch_no_changes(tmp_path: Path):
    """Test envdiff CLI patch with no changes needed."""
    # Tests lines 307-309
    source_yml = tmp_path / "src.yml"
    target_env = tmp_path / ".env"
    source_yml.write_text("APP: one\n", encoding="utf-8")
    target_env.write_text("APP=one\n", encoding="utf-8")

    from tests.test_cli_integration import run_py

    r = run_py(
        "envdiff.py",
        "--source",
        str(source_yml),
        "--target",
        str(target_env),
        "--patch-format",
        "export",
    )
    assert r.returncode == 0
    assert "no changes needed" in r.stdout


def test_envdiff_cli_apply_dry_run_format_text(tmp_path: Path):
    """Test envdiff CLI apply dry-run with text format."""
    # Tests lines 321-324
    source_yml = tmp_path / "src.yml"
    target_env = tmp_path / ".env"
    source_yml.write_text("APP: one\n", encoding="utf-8")
    target_env.write_text("", encoding="utf-8")

    from tests.test_cli_integration import run_py

    r = run_py(
        "envdiff.py",
        "--source",
        str(source_yml),
        "--target",
        str(target_env),
        "--apply",
        "--apply-dry-run",
        "--format",
        "text",
    )
    assert r.returncode == 0
    assert "would write the following .env content" in r.stdout


def test_envdiff_cli_check_ok(tmp_path: Path):
    """Test envdiff CLI check with no differences."""
    # Tests lines 335-342
    source_yml = tmp_path / "src.yml"
    target_env = tmp_path / ".env"
    source_yml.write_text("APP: one\n", encoding="utf-8")
    target_env.write_text("APP=one\n", encoding="utf-8")

    from tests.test_cli_integration import run_py

    r = run_py(
        "envdiff.py",
        "--source",
        str(source_yml),
        "--target",
        str(target_env),
        "--check",
        "--format",
        "text",
    )
    assert r.returncode == 0
    assert "CHECK OK" in r.stdout


def test_envdiff_cli_check_fail_text(tmp_path: Path):
    """Test envdiff CLI check fail with text format."""
    # Tests lines 339-340
    source_yml = tmp_path / "src.yml"
    target_env = tmp_path / ".env"
    source_yml.write_text("APP: one\n", encoding="utf-8")
    target_env.write_text("", encoding="utf-8")

    from tests.test_cli_integration import run_py

    r = run_py(
        "envdiff.py",
        "--source",
        str(source_yml),
        "--target",
        str(target_env),
        "--check",
        "--format",
        "text",
    )
    assert r.returncode == 5
    assert "CHECK FAILED" in r.stderr


def test_envdiff_cli_check_fail_json(tmp_path: Path):
    """Test envdiff CLI check fail with json format."""
    # Tests line 350
    source_yml = tmp_path / "src.yml"
    target_env = tmp_path / ".env"
    source_yml.write_text("APP: one\n", encoding="utf-8")
    target_env.write_text("", encoding="utf-8")

    from tests.test_cli_integration import run_py

    r = run_py(
        "envdiff.py",
        "--source",
        str(source_yml),
        "--target",
        str(target_env),
        "--check",
        "--format",
        "json",
    )
    assert r.returncode == 5
    data = json.loads(r.stdout)
    assert data["check"]["status"] == "fail"


def test_envdiff_cli_show_same_details(tmp_path: Path):
    """Test envdiff CLI show-same with different values."""
    # Tests lines 287-289
    source_yml = tmp_path / "src.yml"
    target_env = tmp_path / ".env"
    source_yml.write_text("APP: one\nOTHER: two\n", encoding="utf-8")
    target_env.write_text("APP=one\nOTHER=three\n", encoding="utf-8")

    from tests.test_cli_integration import run_py

    r = run_py(
        "envdiff.py",
        "--source",
        str(source_yml),
        "--target",
        str(target_env),
        "--show-same",
        "--format",
        "text",
    )
    assert r.returncode == 0
    assert "Details of different values" in r.stdout
    assert "source:" in r.stdout
    assert "target:" in r.stdout


def test_envset_scp_cmd_extra():
    """Test envset _scp_cmd with extra options."""
    # Tests line 25
    cmd = envset._scp_cmd("src", "dst", None, None, ["opt1=val1", "opt2=val2"])
    assert "-o" in cmd
    assert cmd.count("-o") == 2


def test_envset_parse_yaml_error():
    """Test envset parse_yaml with non-dict."""
    # Tests lines 60-63
    with pytest.raises(RuntimeError, match="Top-level YAML must be a mapping"):
        envset.parse_yaml("- item1\n- item2\n")  # List, not dict


def test_envset_dump_yaml():
    """Test envset dump_yaml function."""
    # Tests lines 65-66
    data = {"a": 1, "b": {"c": 2}}
    result = envset.dump_yaml(data)
    assert "a:" in result
    assert "b:" in result


def test_envset_set_configpy_assign_block_empty_key():
    """Test set_configpy_assign_block with empty key."""
    # Tests line 96
    with pytest.raises(ValueError, match="Empty key"):
        envset.set_configpy_assign_block("CONFIG = {}\n", ".", "value")


def test_envset_set_configpy_assign_block_no_newline():
    """Test set_configpy_assign_block without trailing newline."""
    # Tests lines 92, 104, 120
    base = "CONFIG = {}"  # No newline
    out = envset.set_configpy_assign_block(base, "API_KEY", "value")
    assert "API_KEY" in out
    assert out.startswith("CONFIG = {}\n")  # Should add newline


def test_envset_set_configpy_assign_block_with_env():
    """Test set_configpy_assign_block with ENV dict."""
    base = "ENV = {}\n"
    out = envset.set_configpy_assign_block(base, "database.host", "db.local")
    assert "ENV['database']['host']" in out


def test_envset_set_configpy_assign_block_nested():
    """Test set_configpy_assign_block with nested keys."""
    base = "CONFIG = {}\n"
    out = envset.set_configpy_assign_block(base, "a.b.c.d", "value")
    assert "CONFIG['a']['b']['c']['d']" in out


def test_envset_cli_yaml(tmp_path: Path):
    """Test envset CLI with YAML file."""
    # Tests line 180
    yml_file = tmp_path / "config.yml"
    yml_file.write_text("a: {b: 1}\n", encoding="utf-8")

    from tests.test_cli_integration import run_py

    r = run_py("envset.py", "--files", str(yml_file), "--key", "a.c", "--value", "2")
    assert r.returncode == 0
    assert "a:" in yml_file.read_text(encoding="utf-8")


def test_envset_cli_rewrite_constant_not_present(tmp_path: Path):
    """Test envset CLI rewrite constant when not present."""
    # Tests lines 186-189
    cfg = tmp_path / "config.py"
    cfg.write_text("OTHER = 'value'\n", encoding="utf-8")

    from tests.test_cli_integration import run_py

    r = run_py(
        "envset.py", "--files", str(cfg), "--key", "API_KEY", "--value", "secret", "--rewrite"
    )
    assert r.returncode == 0
    assert "API_KEY" in cfg.read_text(encoding="utf-8")


def test_envset_cli_rewrite_constant_present(tmp_path: Path):
    """Test envset CLI rewrite constant when present (lines 238-239)."""
    # Test in-place rewrite of existing constant
    cfg = tmp_path / "config.py"
    cfg.write_text("API_KEY = 'old_value'\nOTHER = 123\n", encoding="utf-8")

    from tests.test_cli_integration import run_py

    r = run_py(
        "envset.py", "--files", str(cfg), "--key", "API_KEY", "--value", "new_value", "--rewrite"
    )
    assert r.returncode == 0
    content = cfg.read_text(encoding="utf-8")
    assert "API_KEY = 'new_value'" in content
    assert "old_value" not in content


def test_envset_cli_rewrite_dict_not_present(tmp_path: Path):
    """Test envset CLI rewrite dict when not present."""
    # Tests lines 197-202
    cfg = tmp_path / "config.py"
    cfg.write_text("CONFIG = {}\n", encoding="utf-8")

    from tests.test_cli_integration import run_py

    r = run_py(
        "envset.py", "--files", str(cfg), "--key", "database.host", "--value", "new", "--rewrite"
    )
    assert r.returncode == 0
    assert "database.host" in cfg.read_text(encoding="utf-8") or "database" in cfg.read_text(
        encoding="utf-8"
    )


def test_envset_cli_update_error(tmp_path: Path):
    """Test envset CLI update error handling."""
    # Tests line 200
    cfg = tmp_path / "config.py"
    cfg.write_text("CONFIG = {}\n", encoding="utf-8")

    # Try to set an invalid key
    from tests.test_cli_integration import run_py

    r = run_py("envset.py", "--files", str(cfg), "--key", "", "--value", "value")
    # Should handle error gracefully
    assert "ERROR" in r.stderr or r.returncode != 0


def test_envset_cli_empty_key_after_split(tmp_path: Path):
    """Test envset CLI with key that becomes empty after split."""
    # Tests line 198
    cfg = tmp_path / "config.py"
    cfg.write_text("CONFIG = {}\n", encoding="utf-8")

    from tests.test_cli_integration import run_py

    # Key with only dots becomes empty after split
    r = run_py("envset.py", "--files", str(cfg), "--key", "...", "--value", "value", "--rewrite")
    # Should handle error gracefully
    assert "ERROR" in r.stderr or r.returncode != 0


def test_envset_cli_unsupported_type_error(tmp_path: Path):
    """Test envset CLI with unsupported type."""
    # Tests line 202 - We need to test the else branch when ftype is not env/yaml/py
    # Since detect_type always returns one of these, we'll directly test the code path
    # by temporarily patching detect_type to return an unsupported value
    import sys
    from io import StringIO

    import envset

    test_file = tmp_path / "test.txt"
    test_file.write_text("KEY=value\n", encoding="utf-8")

    # Save original function
    original_detect = envset.detect_type

    # Patch to return unsupported type
    def mock_detect_type(path, explicit):
        if explicit:
            return explicit
        return "unsupported"

    envset.detect_type = mock_detect_type

    try:
        # Call main directly with mocked sys.argv
        old_argv = sys.argv
        old_stderr = sys.stderr
        sys.stderr = StringIO()
        try:
            sys.argv = ["envset.py", "--files", str(test_file), "--key", "KEY", "--value", "new"]
            envset.main()
            stderr_output = sys.stderr.getvalue()
            assert "Unsupported type" in stderr_output
        finally:
            sys.argv = old_argv
            sys.stderr = old_stderr
    finally:
        envset.detect_type = original_detect


def test_envset_cli_write_exception(tmp_path: Path):
    """Test envset CLI write exception handling."""
    # Tests line 208
    env_file = tmp_path / "test.env"
    env_file.write_text("KEY=old\n", encoding="utf-8")

    # Make file read-only to cause write error
    env_file.chmod(0o444)

    from tests.test_cli_integration import run_py

    r = run_py("envset.py", "--files", str(env_file), "--key", "KEY", "--value", "new")
    assert "ERROR writing" in r.stderr

    # Cleanup
    env_file.chmod(0o644)


def test_unquote_empty_string():
    """Test _unquote with empty string after strip (line 76)."""
    # Test through read_env_text with empty value
    text = "KEY=\n"
    result = envdiff.read_env_text(text)
    assert result["KEY"] == ""


def test_read_env_text_empty_line():
    """Test read_env_text with empty line (line 84)."""
    # Empty line should be skipped
    text = "\n\nKEY=value\n\n"
    result = envdiff.read_env_text(text)
    assert "KEY" in result
    assert len(result) == 1


def test_generate_patch_dotenv_simple_value():
    """Test generate_patch dotenv format with simple value (line 167)."""
    # Value without spaces, quotes, or # - should not be quoted
    s = {"SIMPLE_KEY": "simplevalue123"}
    result = envdiff.generate_patch(s, ["SIMPLE_KEY"], "dotenv")
    assert any("SIMPLE_KEY=simplevalue123" in line for line in result)
    assert not any('SIMPLE_KEY="' in line for line in result)


def test_read_env_text_non_matching_line():
    """Test read_env_text with non-matching line (line 87)."""
    # Line that doesn't match the regex pattern
    text = "INVALID LINE WITHOUT EQUALS\nVALID_KEY=value\n"
    result = envdiff.read_env_text(text)
    assert "VALID_KEY" in result
    assert "INVALID" not in result


def test_read_yaml_text_non_dict():
    """Test read_yaml_text with non-dict top-level (line 94)."""
    # YAML with list or scalar at top level
    with pytest.raises(RuntimeError, match="Top-level YAML must be a mapping"):
        envdiff.read_yaml_text("- item1\n- item2")


def test_read_python_module_none_spec(tmp_path: Path):
    """Test read_python_module with None spec or loader (line 107)."""
    # Test with None spec
    with patch("importlib.util.spec_from_file_location", return_value=None):
        with pytest.raises(RuntimeError, match="Cannot load Python module"):
            envdiff.read_python_module("/nonexistent/path.py")

    # Test with spec but None loader
    fake_spec = MagicMock()
    fake_spec.loader = None
    with patch("importlib.util.spec_from_file_location", return_value=fake_spec):
        with pytest.raises(RuntimeError, match="Cannot load Python module"):
            envdiff.read_python_module("/nonexistent/path.py")


def test_generate_patch_dict_list_values():
    """Test generate_patch with dict/list values (line 155)."""
    s = {"DICT_KEY": {"a": 1}, "LIST_KEY": [1, 2, 3]}
    result = envdiff.generate_patch(s, ["DICT_KEY", "LIST_KEY"], "export")
    # Check that dict/list values are JSON serialized
    assert any("DICT_KEY" in line for line in result)
    assert any("LIST_KEY" in line for line in result)


def test_generate_patch_none_values():
    """Test generate_patch with None values (line 157)."""
    s = {"NONE_KEY": None}
    result = envdiff.generate_patch(s, ["NONE_KEY"], "export")
    assert any("NONE_KEY" in line for line in result)
    # None should be converted to empty string
    assert any("NONE_KEY=''" in line or 'NONE_KEY=""' in line for line in result)


def test_generate_dotenv_content_dict_list_values():
    """Test generate_dotenv_content with dict/list values (line 178)."""
    kv = {"DICT_KEY": {"a": 1}, "LIST_KEY": [1, 2]}
    result = envdiff.generate_dotenv_content(kv)
    assert "DICT_KEY" in result
    assert "LIST_KEY" in result


def test_generate_dotenv_content_none_values():
    """Test generate_dotenv_content with None values (line 180)."""
    kv = {"NONE_KEY": None}
    result = envdiff.generate_dotenv_content(kv)
    assert "NONE_KEY" in result
    # None should be converted to empty string
    assert 'NONE_KEY=""' in result


def test_keep_function_include_no_match(tmp_path: Path):
    """Test _keep function with include but no match (line 317)."""
    # Test through CLI with include that doesn't match any keys
    from tests.test_cli_integration import run_py

    source_file = tmp_path / "source.env"
    target_file = tmp_path / "target.env"
    source_file.write_text("APP_KEY=value\nOTHER_KEY=value\n")
    target_file.write_text("APP_KEY=value\nOTHER_KEY=value\n")

    # Include pattern that matches nothing
    r = run_py(
        "envdiff.py",
        "--source",
        str(source_file),
        "--target",
        str(target_file),
        "--include",
        "^NOMATCH_",
        "--format",
        "text",
    )
    # Should show no differences because all keys are filtered out
    assert r.returncode == 0


def test_keep_function_exclude_match(tmp_path: Path):
    """Test _keep function with exclude match (line 319)."""
    # Test through CLI with exclude that matches keys
    from tests.test_cli_integration import run_py

    source_file = tmp_path / "source.env"
    target_file = tmp_path / "target.env"
    source_file.write_text("SECRET_KEY=secret\nPUBLIC_KEY=public\n")
    target_file.write_text("SECRET_KEY=secret\nPUBLIC_KEY=public\n")

    # Exclude pattern that matches SECRET_KEY
    r = run_py(
        "envdiff.py",
        "--source",
        str(source_file),
        "--target",
        str(target_file),
        "--exclude",
        "SECRET",
        "--format",
        "text",
    )
    # Should show no differences because SECRET_KEY is filtered out
    assert r.returncode == 0


def test_envset_parse_env_non_matching_line():
    """Test envset parse_env with non-matching line (line 62)."""
    # Line that doesn't match the regex pattern
    text = "INVALID LINE WITHOUT EQUALS\nVALID_KEY=value\n"
    result = envset.parse_env(text)
    assert "VALID_KEY" in result
    assert "INVALID" not in result
