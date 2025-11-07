import json
from pathlib import Path

import envdiff


def test_read_env_text_and_generate_dotenv_content(tmp_path: Path):
    text = 'APP=one\nQUOTED="two two"\nEMPTY=""\n# comment\nSPACES=has space\n'
    parsed = envdiff.read_env_text(text)
    assert parsed["APP"] == "one"
    assert parsed["QUOTED"] == "two two"
    assert parsed["EMPTY"] == ""
    assert parsed["SPACES"] == "has space"

    out = envdiff.generate_dotenv_content(parsed)
    again = envdiff.read_env_text(out)
    assert again == parsed


def test_read_yaml_text_flattens():
    yaml_text = """a:
  b: 1
  c:
    d: two
LIST:
  - x
"""
    flat = envdiff.read_yaml_text(yaml_text)
    assert flat["a.b"] == 1
    assert flat["a.c.d"] == "two"
    assert isinstance(flat["LIST"], list)


def test_detect_type_and_normalize():
    assert envdiff.detect_type("file.yaml", None) == "yaml"
    assert envdiff.detect_type("file.yml", None) == "yaml"
    assert envdiff.detect_type("file.py", None) == "py"
    assert envdiff.detect_type("file.env", None) == "env"
    assert envdiff.normalize_value({"a": 1}, True) == json.dumps(
        {"a": 1}, sort_keys=True, separators=(",", ":")
    )
    assert envdiff.normalize_value("X", False) == "x"


def test_compute_diff_and_patch():
    s = {"A": "1", "B": "2", "C": "3"}
    t = {"B": "22", "C": "3", "D": "4"}
    missing, extra, different, per_key = envdiff.compute_diff(s, t, True)
    assert missing == ["A"]
    assert extra == ["D"]
    assert different == ["B"]
    lines = envdiff.generate_patch(s, ["A", "B"], "export")
    assert any(line.startswith("export A=") for line in lines)
    assert any(line.startswith("export B=") for line in lines)


def test_generate_patch_formats():
    s = {"K": "v space", "NQ": "plain", "EMPTY": ""}
    ex = envdiff.generate_patch(s, list(s.keys()), "export")
    dz = envdiff.generate_patch(s, list(s.keys()), "dotenv")
    ps = envdiff.generate_patch(s, list(s.keys()), "powershell")
    assert any("export K='" in line for line in ex)
    assert any('K="' in line for line in dz)
    assert any("$Env:K =" in line for line in ps)
