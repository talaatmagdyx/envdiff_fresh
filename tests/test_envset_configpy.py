import re

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
