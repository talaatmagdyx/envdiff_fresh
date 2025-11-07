#!/usr/bin/env python3
"""
envdiff - Compare and patch environment configurations across local and remote systems.

This module provides functionality to:
- Compare environment configurations between source (YAML/.env) and target (.env/config.py)
- Generate patches in multiple formats (export, dotenv, PowerShell)
- Apply changes directly to target files with automatic backups
- Support remote file operations via SSH/SCP
- Filter keys using prefix patterns or regex
- Integrate with CI/CD pipelines via --check flag

Supported file formats:
- .env files (standard KEY=VALUE format)
- YAML files (with nested key flattening)
- Python config.py files (CONFIG/ENV dicts and UPPERCASE constants)
"""

import argparse
import importlib.util
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# --- Remote helpers ---
# Functions for handling remote file paths and SSH/SCP operations
# Regex pattern to match remote paths: user@host:/path or host:/path
REMOTE_RE = re.compile(r"^(?P<host>[^:@/]+(?:@[^:@/]+)?):(?P<path>.+)$")


def is_remote_path(path: str) -> bool:
    """
    Check if a path is a remote path (SSH/SCP format).

    Args:
        path: Path string to check

    Returns:
        True if path matches remote format (host:/path), False otherwise

    Examples:
        >>> is_remote_path("user@server:/etc/config.yml")
        True
        >>> is_remote_path("/local/path/.env")
        False
    """
    return bool(REMOTE_RE.match(path))


def parse_remote(path: str) -> Tuple[str, str]:
    """
    Parse a remote path into host and remote path components.

    Args:
        path: Remote path in format "host:/path" or "user@host:/path"

    Returns:
        Tuple of (host, remote_path)

    Raises:
        ValueError: If path is not a valid remote path format

    Examples:
        >>> parse_remote("user@server:/etc/config.yml")
        ('user@server', '/etc/config.yml')
        >>> parse_remote("server:/home/user/.env")
        ('server', '/home/user/.env')
    """
    m = REMOTE_RE.match(path)
    if not m:
        raise ValueError(f"Not a remote path: {path}")
    return m.group("host"), m.group("path")


def _ssh_base_cmd(
    host: str, port: Optional[int], identity: Optional[str], extra: Optional[List[str]]
) -> List[str]:
    """
    Build base SSH command with optional port, identity file, and extra options.

    Args:
        host: SSH hostname (may include user@ prefix)
        port: Optional SSH port number
        identity: Optional path to SSH identity (private key) file
        extra: Optional list of SSH options (e.g., ["StrictHostKeyChecking=no"])

    Returns:
        List of command arguments for SSH command

    Example:
        >>> _ssh_base_cmd("server", 2222, "/path/to/key", ["StrictHostKeyChecking=no"])
        ['ssh', '-p', '2222', '-i', '/path/to/key', '-o', 'StrictHostKeyChecking=no', 'server']
    """
    cmd = ["ssh"]
    if port:
        cmd += ["-p", str(port)]
    if identity:
        cmd += ["-i", identity]
    if extra:
        for opt in extra:
            cmd += ["-o", opt]
    cmd.append(host)
    return cmd


def _scp_cmd(
    src: str, dst: str, port: Optional[int], identity: Optional[str], extra: Optional[List[str]]
) -> List[str]:
    """
    Build SCP command with optional port, identity file, and extra options.

    Args:
        src: Source path (local or remote)
        dst: Destination path (local or remote)
        port: Optional SSH port number
        identity: Optional path to SSH identity (private key) file
        extra: Optional list of SSH options

    Returns:
        List of command arguments for SCP command

    Note:
        SCP uses -P (uppercase) for port, unlike SSH which uses -p (lowercase)
    """
    cmd = ["scp"]
    if port:
        cmd += ["-P", str(port)]
    if identity:
        cmd += ["-i", identity]
    if extra:
        for opt in extra:
            cmd += ["-o", opt]
    cmd += [src, dst]
    return cmd


def ssh_run(
    host: str,
    cmd_str: str,
    port: Optional[int],
    identity: Optional[str],
    extra: Optional[List[str]],
    timeout: int = 30,
) -> str:
    """
    Execute a command on remote host via SSH and return stdout.

    Args:
        host: SSH hostname
        cmd_str: Command string to execute remotely
        port: Optional SSH port
        identity: Optional SSH identity file path
        extra: Optional SSH options
        timeout: Command timeout in seconds (default: 30)

    Returns:
        Decoded stdout output from remote command

    Raises:
        subprocess.CalledProcessError: If command fails
        subprocess.TimeoutExpired: If command times out
    """
    base = _ssh_base_cmd(host, port, identity, extra)
    out = subprocess.check_output(base + [cmd_str], stderr=subprocess.STDOUT, timeout=timeout)
    return out.decode("utf-8", errors="replace")


def ssh_cat(
    host: str,
    rpath: str,
    port: Optional[int],
    identity: Optional[str],
    extra: Optional[List[str]],
    timeout: int = 30,
) -> str:
    """
    Read remote file content via SSH cat command.

    Args:
        host: SSH hostname
        rpath: Remote file path
        port: Optional SSH port
        identity: Optional SSH identity file path
        extra: Optional SSH options
        timeout: Command timeout in seconds (default: 30)

    Returns:
        File contents as string

    Note:
        Uses shlex.quote() to safely escape the remote path in shell command
    """
    return ssh_run(host, f"cat {shlex.quote(rpath)}", port, identity, extra, timeout)


def scp_to_temp(
    remote: str,
    port: Optional[int],
    identity: Optional[str],
    extra: Optional[List[str]],
    timeout: int = 60,
) -> str:
    """
    Download remote file to temporary local file via SCP.

    Args:
        remote: Remote file path (host:/path format)
        port: Optional SSH port
        identity: Optional SSH identity file path
        extra: Optional SSH options
        timeout: Command timeout in seconds (default: 60)

    Returns:
        Path to temporary local file

    Note:
        Temporary file is not automatically deleted - caller must clean up
    """
    tmp = tempfile.NamedTemporaryFile(prefix="envdiff_", delete=False)
    tmp.close()
    cmd = _scp_cmd(remote, tmp.name, port, identity, extra)
    subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, timeout=timeout)
    return tmp.name


def scp_upload(
    local_path: str,
    remote: str,
    port: Optional[int],
    identity: Optional[str],
    extra: Optional[List[str]],
    timeout: int = 60,
) -> None:
    """
    Upload local file to remote location via SCP.

    Args:
        local_path: Local file path
        remote: Remote destination (host:/path format)
        port: Optional SSH port
        identity: Optional SSH identity file path
        extra: Optional SSH options
        timeout: Command timeout in seconds (default: 60)

    Raises:
        subprocess.CalledProcessError: If upload fails
    """
    cmd = _scp_cmd(local_path, remote, port, identity, extra)
    subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, timeout=timeout)


# --- Parsers ---
# Functions for parsing different file formats (.env, YAML, Python)

# Regex pattern for matching .env file lines: KEY=VALUE format
# Supports quoted values (single or double quotes) and inline comments
_ENV_LINE_RE = re.compile(
    r"""
    ^\s*
    (?P<key>[A-Za-z_][A-Za-z0-9_\.]*)  # Variable name (alphanumeric + underscore + dot)
    \s*=\s*
    (?P<val>
        "(?:\\.|[^"])*"      |  # Double-quoted string with escapes
        '(?:\\.|[^'])*'      |  # Single-quoted string with escapes
        [^\n\r#]*              # Unquoted value (up to # or newline)
    )
    (?:\s+\#.*|\s*)$          # Optional inline comment
""",
    re.VERBOSE,
)


def _unquote(s: str) -> str:
    """
    Remove quotes and unescape special characters from a string value.

    Args:
        s: String that may be quoted and contain escape sequences

    Returns:
        Unquoted and unescaped string

    Examples:
        >>> _unquote('"hello\\nworld"')
        'hello\nworld'
        >>> _unquote("'test'")
        'test'
        >>> _unquote("plain")
        'plain'
    """
    s = s.strip()
    if not s:
        return ""
    # Remove surrounding quotes if present
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        s = s[1:-1]
    # Unescape common escape sequences
    return s.replace("\\n", "\n").replace("\\r", "\r").replace("\\t", "\t")


def read_env_text(text: str) -> Dict[str, str]:
    """
    Parse .env file content into a dictionary of key-value pairs.

    Args:
        text: Content of .env file as string

    Returns:
        Dictionary mapping variable names to values

    Notes:
        - Skips empty lines and lines starting with #
        - Handles quoted values (single or double quotes)
        - Unescapes \\n, \\r, \\t sequences
        - Ignores lines that don't match KEY=VALUE pattern

    Example:
        >>> read_env_text("APP_NAME=myapp\\nDATABASE_URL='postgres://...'")
        {'APP_NAME': 'myapp', 'DATABASE_URL': 'postgres://...'}
    """
    out: Dict[str, str] = {}
    for raw in text.splitlines():
        # Skip empty lines and comments
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        m = _ENV_LINE_RE.match(raw)
        if not m:
            continue
        out[m.group("key")] = _unquote(m.group("val").strip())
    return out


def read_yaml_text(text: str) -> Dict[str, Any]:
    """
    Parse YAML file content and flatten nested structure into dot-notation keys.

    Args:
        text: YAML file content as string

    Returns:
        Flattened dictionary with dot-notation keys (e.g., "app.database.host")

    Raises:
        RuntimeError: If top-level YAML is not a dictionary/mapping

    Example:
        >>> yaml_text = "app:\\n  database:\\n    host: localhost"
        >>> read_yaml_text(yaml_text)
        {'app.database.host': 'localhost'}
    """
    import yaml

    data = yaml.safe_load(text) or {}
    if not isinstance(data, dict):
        raise RuntimeError("Top-level YAML must be a mapping (dict).")
    flat: Dict[str, Any] = {}

    def _flatten(prefix: str, node: Any):
        """
        Recursively flatten nested dictionary structure.

        Args:
            prefix: Current key prefix (empty for root level)
            node: Current node (dict or leaf value)
        """
        if isinstance(node, dict):
            # Recursively process nested dictionaries
            for k, v in node.items():
                _flatten(f"{prefix}.{k}" if prefix else str(k), v)
        else:
            # Leaf value - store with current prefix as key
            flat[prefix] = node

    _flatten("", data)
    return flat


def read_python_module(path: str) -> Dict[str, Any]:
    """
    Load Python config.py file and extract configuration values.

    This function looks for:
    1. CONFIG or ENV dictionaries (preferred) - returns flattened dict keys
    2. UPPERCASE constants - returns all uppercase module-level variables

    Args:
        path: Path to Python config file

    Returns:
        Dictionary mapping configuration keys to values

    Raises:
        RuntimeError: If file cannot be loaded or spec is invalid

    Example:
        # config.py:
        # CONFIG = {'database': {'host': 'localhost'}}
        # API_KEY = 'secret'

        >>> read_python_module("config.py")
        {'database.host': 'localhost'}  # CONFIG takes precedence

        # If no CONFIG/ENV:
        >>> read_python_module("config.py")
        {'API_KEY': 'secret', 'OTHER_CONSTANT': 123}
    """
    spec = importlib.util.spec_from_file_location("envdiff_target", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load Python module from {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore

    # Priority 1: Look for CONFIG or ENV dictionaries
    for name in ("CONFIG", "ENV"):
        if hasattr(mod, name) and isinstance(getattr(mod, name), dict):
            d = getattr(mod, name)
            # Return flattened dict keys (similar to YAML flattening)
            return {str(k): d[k] for k in d}

    # Priority 2: Collect all UPPERCASE constants
    out: Dict[str, Any] = {}
    for attr in dir(mod):
        if attr.isupper():
            out[attr] = getattr(mod, attr)
    return out


# --- Helpers ---
# Utility functions for value normalization, type detection, and formatting


def normalize_value(v: Any, case_sensitive: bool) -> str:
    """
    Normalize a value to a string for comparison purposes.

    Args:
        v: Value to normalize (can be any type)
        case_sensitive: If False, convert result to lowercase

    Returns:
        Normalized string representation

    Notes:
        - None becomes empty string
        - Dict/list values are JSON-serialized (compact format)
        - Other values are converted to string and stripped
        - Case conversion applied if case_sensitive=False

    Example:
        >>> normalize_value({"a": 1}, True)
        '{"a":1}'
        >>> normalize_value("Hello", False)
        'hello'
    """
    if v is None:
        s = ""
    elif isinstance(v, (dict, list)):
        # Serialize complex types to JSON for comparison
        s = json.dumps(v, sort_keys=True, separators=(",", ":"))
    else:
        s = str(v)
    s = s.strip()
    return s if case_sensitive else s.lower()


def detect_type(path: str, explicit: Optional[str]) -> str:
    """
    Detect file type from path or use explicit type if provided.

    Args:
        path: File path (may be remote: host:/path)
        explicit: Explicitly specified type (overrides detection)

    Returns:
        File type: "env", "yaml", or "py"

    Notes:
        - "-" (stdin) defaults to "env"
        - Remote paths are parsed to extract local extension
        - File extensions: .yml/.yaml -> "yaml", .py -> "py", else -> "env"
    """
    if explicit:
        return explicit
    if path == "-":
        return "env"
    # Extract local path from remote path if needed
    local = parse_remote(path)[1] if is_remote_path(path) else path
    ext = os.path.splitext(local)[1].lower()
    if ext in (".yml", ".yaml"):
        return "yaml"
    if ext == ".py":
        return "py"
    return "env"


def apply_ignores(d: Dict[str, Any], ignore_prefixes: List[str]) -> Dict[str, Any]:
    """
    Filter dictionary to remove keys matching any ignore prefix.

    Args:
        d: Dictionary to filter
        ignore_prefixes: List of prefixes to ignore (keys starting with these are removed)

    Returns:
        Filtered dictionary (or original if no prefixes provided)

    Example:
        >>> apply_ignores({"APP_KEY": "1", "DEBUG_MODE": "true"}, ["DEBUG"])
        {'APP_KEY': '1'}
    """
    if not ignore_prefixes:
        return d
    return {k: v for k, v in d.items() if not any(k.startswith(p) for p in ignore_prefixes)}


def _quote_export(val: str) -> str:
    """
    Quote a value for shell export statement, handling single quotes.

    Args:
        val: Value to quote

    Returns:
        Quoted string safe for shell export

    Notes:
        - Empty string becomes ''
        - Single quotes in value are escaped as '"'"' (bash-style)

    Example:
        >>> _quote_export("value with 'quotes'")
        "'value with '\"'\"'quotes'\"'\"''"
    """
    if val == "":
        return "''"
    # Escape single quotes by closing quote, adding escaped quote, reopening quote
    return "'" + val.replace("'", "'\"'\"'") + "'"


def generate_patch(source: Dict[str, Any], keys_to_set: List[str], fmt: str) -> List[str]:
    """
    Generate patch lines for specified keys in the requested format.

    Args:
        source: Source dictionary containing values
        keys_to_set: List of keys to include in patch
        fmt: Patch format - "export", "dotenv", or "powershell"

    Returns:
        List of patch lines (one per key)

    Raises:
        RuntimeError: If format is not supported

    Notes:
        - Dict/list values are JSON-serialized
        - None values become empty strings
        - Export format: shell export statements (bash/zsh)
        - Dotenv format: standard .env format (quoted if needed)
        - PowerShell format: PowerShell environment variable syntax

    Example:
        >>> generate_patch({"KEY": "value"}, ["KEY"], "export")
        ["export KEY='value'"]
    """
    lines: List[str] = []
    for k in keys_to_set:
        v_raw = source[k]
        # Convert complex types to JSON strings
        if isinstance(v_raw, (dict, list)):
            v = json.dumps(v_raw, sort_keys=True)
        elif v_raw is None:
            v = ""
        else:
            v = str(v_raw)

        if fmt == "export":
            # Shell export format: export KEY='value'
            lines.append(f"export {k}={_quote_export(v)}")
        elif fmt == "dotenv":
            # .env format: KEY=value or KEY="value" (if quotes/spaces needed)
            if re.search(r"\s|#|['\"]", v) or v == "":
                # Quote value and escape special characters
                dq = v.replace("\\", "\\\\").replace('"', '\\"')
                lines.append(f'{k}="{dq}"')
            else:
                # Simple value, no quoting needed
                lines.append(f"{k}={v}")
        elif fmt == "powershell":
            # PowerShell format: $Env:KEY = 'value'
            lines.append(f"$Env:{k} = {_quote_export(v)}")
        else:
            raise RuntimeError(f"Unsupported patch format: {fmt}")
    return lines


def generate_dotenv_content(kv: Dict[str, Any]) -> str:
    """
    Generate complete .env file content from key-value dictionary.

    Args:
        kv: Dictionary of key-value pairs (sorted by key)

    Returns:
        Complete .env file content as string (with trailing newline)

    Notes:
        - Keys are sorted alphabetically
        - Values are quoted if they contain spaces, #, quotes, or are empty
        - Dict/list values are JSON-serialized
        - None values become empty strings

    Example:
        >>> generate_dotenv_content({"APP": "myapp", "DEBUG": True})
        'APP=myapp\\nDEBUG=true\\n'
    """
    lines: List[str] = []
    for k in sorted(kv.keys()):
        v_raw = kv[k]
        # Convert complex types to JSON strings
        if isinstance(v_raw, (dict, list)):
            v = json.dumps(v_raw, sort_keys=True)
        elif v_raw is None:
            v = ""
        else:
            v = str(v_raw)

        # Quote if value contains special characters or is empty
        if re.search(r"\s|#|['\"]", v) or v == "":
            dq = v.replace("\\", "\\\\").replace('"', '\\"')
            lines.append(f'{k}="{dq}"')
        else:
            lines.append(f"{k}={v}")
    return "\n".join(lines) + "\n"


def load_text_maybe_remote(
    path: str, port: Optional[int], identity: Optional[str], extra: Optional[List[str]]
) -> str:
    """
    Load text content from local file, remote file, or stdin.

    Args:
        path: File path (local, remote "host:/path", or "-" for stdin)
        port: Optional SSH port for remote paths
        identity: Optional SSH identity file for remote paths
        extra: Optional SSH options for remote paths

    Returns:
        File content as string

    Notes:
        - Remote paths are read via SSH cat command
        - "-" reads from stdin
        - Local paths are read from filesystem
    """
    if is_remote_path(path):
        host, rp = parse_remote(path)
        return ssh_cat(host, rp, port, identity, extra)
    if path == "-":
        return sys.stdin.read()
    with open(path, encoding="utf-8") as f:
        return f.read()


def load_kv_any(
    path: str, kind: str, port: Optional[int], identity: Optional[str], extra: Optional[List[str]]
) -> Dict[str, Any]:
    """
    Load key-value pairs from any supported file type (local or remote).

    Args:
        path: File path (local, remote, or "-" for stdin)
        kind: File type - "env", "yaml", or "py"
        port: Optional SSH port for remote paths
        identity: Optional SSH identity file for remote paths
        extra: Optional SSH options for remote paths

    Returns:
        Dictionary of key-value pairs

    Raises:
        RuntimeError: If file type is unsupported or file cannot be loaded

    Notes:
        - Python files require local access, so remote files are downloaded temporarily
        - Temporary files are cleaned up after loading
        - Other file types can be read directly via SSH
    """
    if kind == "py":
        # Python files need to be executed, so download remote files first
        local = path
        tmp = None
        if is_remote_path(path):
            local = scp_to_temp(path, port, identity, extra)
            tmp = local
        try:
            return read_python_module(local)
        finally:
            # Clean up temporary file if we downloaded one
            if tmp:
                try:
                    os.unlink(tmp)
                except Exception:
                    pass
    else:
        # For env/yaml, read text and parse
        text = load_text_maybe_remote(path, port, identity, extra)
        if kind == "env":
            return read_env_text(text)
        if kind == "yaml":
            return read_yaml_text(text)
        raise RuntimeError(f"Unsupported type: {kind}")


def compute_diff(source: Dict[str, Any], target: Dict[str, Any], case_sensitive: bool):
    """
    Compute differences between source and target dictionaries.

    Args:
        source: Source dictionary
        target: Target dictionary
        case_sensitive: Whether to compare values case-sensitively

    Returns:
        Tuple of (missing, extra, different, per_key):
        - missing: Keys in source but not in target (sorted)
        - extra: Keys in target but not in source (sorted)
        - different: Keys in both but with different values (sorted)
        - per_key: Dict mapping each common key to (source_value, target_value) tuple

    Example:
        >>> compute_diff({"A": "1", "B": "2"}, {"B": "3", "C": "4"}, True)
        (['A'], ['C'], ['B'], {'B': ('2', '3')})
    """
    skeys, tkeys = set(source.keys()), set(target.keys())
    missing = sorted(list(skeys - tkeys))
    extra = sorted(list(tkeys - skeys))
    different: List[str] = []
    per_key: Dict[str, Tuple[str, str]] = {}

    # Compare values for keys present in both
    for k in sorted(skeys & tkeys):
        sv, tv = (
            normalize_value(source[k], case_sensitive),
            normalize_value(target[k], case_sensitive),
        )
        if sv != tv:
            different.append(k)
        per_key[k] = (sv, tv)
    return missing, extra, different, per_key


def write_text_maybe_remote(
    dest_path: str,
    text: str,
    backup_suffix: Optional[str],
    port: Optional[int],
    identity: Optional[str],
    extra: Optional[List[str]],
):
    """
    Write text content to local file or remote file, optionally creating backup.

    Args:
        dest_path: Destination path (local, remote "host:/path", or "-" for stdout)
        text: Content to write
        backup_suffix: Optional backup suffix (e.g., "bak-20240101120000")
        port: Optional SSH port for remote paths
        identity: Optional SSH identity file for remote paths
        extra: Optional SSH options for remote paths

    Notes:
        - Remote files: backup created via SSH cp command, then upload via SCP
        - Local files: backup created via shutil.copy2, then write new content
        - Backup is skipped if backup_suffix is None
        - Directory is created if it doesn't exist (for local paths)
    """
    if is_remote_path(dest_path):
        host, rp = parse_remote(dest_path)
        # Create backup on remote server if requested
        if backup_suffix:
            _ = ssh_run(
                host,
                f"cp {shlex.quote(rp)} {shlex.quote(rp + '.' + backup_suffix)} 2>/dev/null || true",
                port,
                identity,
                extra,
                timeout=30,
            )
        # Write to temp file, then upload
        tmp = tempfile.NamedTemporaryFile(prefix="envdiff_apply_", delete=False)
        tmp.write(text.encode("utf-8"))
        tmp.flush()
        tmp.close()
        try:
            scp_upload(tmp.name, f"{host}:{rp}", port, identity, extra, timeout=60)
        finally:
            try:
                os.unlink(tmp.name)
            except Exception:
                pass
    else:
        # Local file: create backup if requested and file exists
        if backup_suffix and os.path.exists(dest_path):
            import shutil

            shutil.copy2(dest_path, dest_path + "." + backup_suffix)
        # Ensure directory exists
        os.makedirs(os.path.dirname(dest_path) or ".", exist_ok=True)
        with open(dest_path, "w", encoding="utf-8") as f:
            f.write(text)


def comma_split(s: Optional[str]) -> Optional[List[str]]:
    """
    Split comma-separated string into list of non-empty trimmed values.

    Args:
        s: Comma-separated string (e.g., "opt1, opt2, opt3")

    Returns:
        List of non-empty values, or None if input is None/empty

    Example:
        >>> comma_split("opt1, opt2, opt3")
        ['opt1', 'opt2', 'opt3']
        >>> comma_split("  ")
        None
    """
    if not s:
        return None
    return [x for x in (p.strip() for p in s.split(",")) if x]


def main():
    """
    Main entry point for envdiff CLI tool.

    Compares environment configurations between source and target files,
    generates patches, and optionally applies changes. Supports local and
    remote files via SSH/SCP.

    Exit codes:
        - 0: Success, no differences (or differences ignored by filters)
        - 3: Error applying changes (e.g., target is Python file)
        - 5: Differences found when --check is used
    """
    ap = argparse.ArgumentParser(
        description="Diff envs (YAML/.env) vs target (.env/config.py), local or remote via ssh/scp.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    ap.add_argument("--source", required=True)
    ap.add_argument("--target", required=True)
    ap.add_argument("--source-type", choices=["yaml", "env"])
    ap.add_argument("--target-type", choices=["env", "py"])
    ap.add_argument("--case-sensitive", default="true", choices=["true", "false"])
    ap.add_argument("--ignore-prefix", action="append", default=[])
    ap.add_argument("--only-prefix", action="append", default=[])
    ap.add_argument(
        "--include", action="append", default=[], help="Regex of keys to include (repeatable)."
    )
    ap.add_argument(
        "--exclude", action="append", default=[], help="Regex of keys to exclude (repeatable)."
    )
    ap.add_argument("--patch-format", choices=["export", "dotenv", "powershell"])
    ap.add_argument("--output-patch-file")
    ap.add_argument("--show-same", action="store_true")
    ap.add_argument("--keys-json", action="store_true")
    ap.add_argument("--json-only", action="store_true")
    ap.add_argument("--diff-timeout", type=int, default=60)
    ap.add_argument("--ssh-port", type=int)
    ap.add_argument("--ssh-identity")
    ap.add_argument("--ssh-extra")
    ap.add_argument("--source-ssh-port", type=int)
    ap.add_argument("--source-ssh-identity")
    ap.add_argument("--source-ssh-extra")
    ap.add_argument("--target-ssh-port", type=int)
    ap.add_argument("--target-ssh-identity")
    ap.add_argument("--target-ssh-extra")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--apply-dry-run", action="store_true")
    ap.add_argument("--apply-backup", default="auto", choices=["auto", "none"])
    ap.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero if any differences remain after filtering.",
    )
    ap.add_argument(
        "--format",
        default="text",
        choices=["text", "json"],
        help="Output format. JSON includes summary and exit decision.",
    )
    args = ap.parse_args()

    case_sensitive = args.case_sensitive.lower() == "true"
    stype = detect_type(args.source, args.source_type)
    ttype = detect_type(args.target, args.target_type)
    global_extra = comma_split(args.ssh_extra)
    src_extra = comma_split(args.source_ssh_extra) or global_extra
    tgt_extra = comma_split(args.target_ssh_extra) or global_extra
    src_port = args.source_ssh_port if args.source_ssh_port is not None else args.ssh_port
    tgt_port = args.target_ssh_port if args.target_ssh_port is not None else args.ssh_port
    src_id = args.source_ssh_identity if args.source_ssh_identity else args.ssh_identity
    tgt_id = args.target_ssh_identity if args.target_ssh_identity else args.ssh_identity

    s = load_kv_any(args.source, stype, src_port, src_id, src_extra)
    t = load_kv_any(args.target, ttype, tgt_port, tgt_id, tgt_extra)

    if args.only_prefix:
        s = {k: v for k, v in s.items() if any(k.startswith(p) for p in args.only_prefix)}
        t = {k: v for k, v in t.items() if any(k.startswith(p) for p in args.only_prefix)}

    s = apply_ignores(s, args.ignore_prefix)
    t = apply_ignores(t, args.ignore_prefix)

    include_res = [re.compile(p) for p in (args.include or [])]
    exclude_res = [re.compile(p) for p in (args.exclude or [])]

    def _keep(k: str) -> bool:
        if include_res and not any(r.search(k) for r in include_res):
            return False
        if exclude_res and any(r.search(k) for r in exclude_res):
            return False
        return True

    s = {k: v for k, v in s.items() if _keep(k)}
    t = {k: v for k, v in t.items() if _keep(k)}

    missing, extra, different, per_key = compute_diff(s, t, case_sensitive)
    same = sorted([k for k in per_key if k not in different])

    # Build result dictionary for JSON output mode
    # This structure is used when --format json is specified
    result = {
        "source": args.source,
        "target": args.target,
        "filters": {
            "only_prefix": args.only_prefix or [],
            "ignore_prefix": args.ignore_prefix or [],
            "include": args.include or [],
            "exclude": args.exclude or [],
        },
        "summary": {
            "missing": len(missing),
            "extra": len(extra),
            "different": len(different),
            "same": (len(same) if args.show_same else None),
        },
        "keys": {
            "missing": missing,
            "extra": extra,
            "different": different,
            "same": (same if args.show_same else None),
        },
        "patch": None,
        "apply": None,
        "check": None,
    }

    # Handle JSON-only output modes (keys-json or json-only)
    if args.keys_json or args.json_only:
        # Output lightweight JSON with just the key lists
        print(
            json.dumps(
                {
                    "missing": missing,
                    "extra": extra,
                    "different": different,
                    "same": (same if args.show_same else None),
                },
                indent=2,
                sort_keys=True,
            )
        )
        if args.json_only:
            # Exit with code 5 if differences exist and --check is enabled
            if args.check and (missing or extra or different):
                sys.exit(5)
            return

    # Human-readable text output format
    if args.format == "text":

        def section(title: str, keys: List[str]):
            print(f"\n{title} ({len(keys)}):")
            if not keys:
                print("  (none)")
            else:
                for k in keys:
                    print(f"  - {k}")

        section("Missing on target", missing)
        section("Extra on target", extra)
        section("Different values", different)
        if args.show_same:
            section("Same values", same)
        if different:
            print("\nDetails of different values:")
            for k in different:
                sv, tv = per_key[k]
                print(f"  {k}:\n    source:  {sv}\n    target:  {tv}")

    # Generate patch if requested
    # Patches contain commands to add/update missing or different keys
    if args.patch_format:
        to_set = missing + different
        if to_set:
            lines = generate_patch(s, to_set, args.patch_format)
            result["patch"] = {"format": args.patch_format, "lines": lines}
            if args.format == "text":
                header = f"# Patch ({args.patch_format}) — apply on target to add/update keys"
                if args.output_patch_file:
                    with open(args.output_patch_file, "w", encoding="utf-8") as f:
                        f.write(header + "\n" + "\n".join(lines) + "\n")
                    print(f"\nWrote patch to {args.output_patch_file}")
                else:
                    print("\n" + header)
                    for line in lines:
                        print(line)
        else:
            result["patch"] = {"format": args.patch_format, "lines": []}
            if args.format == "text":
                print("\n# Patch: target already matches source (no changes needed)")

    # Apply changes directly to target file (only for .env files)
    if args.apply:
        ttype = detect_type(args.target, args.target_type)
        if ttype != "env":
            print(
                "\nERROR: --apply supports only target-type env (.env). Refusing to modify Python files.",
                file=sys.stderr,
            )
            sys.exit(3)

        # Merge target with source changes (add missing, update different)
        merged = dict(t)
        for k in missing + different:
            merged[k] = s[k]
        new_text = generate_dotenv_content(merged)

        if args.apply_dry_run:
            # Preview mode: show what would be written without actually writing
            result["apply"] = {"mode": "dry-run", "bytes": len(new_text)}
            if args.format == "text":
                print("\n# --apply-dry-run: would write the following .env content:\n")
                print(new_text)
        else:
            # Actually apply changes: create backup and write new content
            backup_suffix = (
                datetime.now(timezone.utc).strftime("bak-%Y%m%d%H%M%S")
                if args.apply_backup == "auto"
                else None
            )
            write_text_maybe_remote(
                args.target, new_text, backup_suffix, tgt_port, tgt_id, tgt_extra
            )
            result["apply"] = {
                "mode": "applied",
                "backup_suffix": backup_suffix,
                "bytes": len(new_text),
            }
            if args.format == "text":
                print("\nApplying changes to target .env...")
                print(f"Done.{(' Backup: .' + backup_suffix) if backup_suffix else ''}")

    # CI/CD check mode: exit with non-zero code if differences exist
    if args.check:
        status_fail = bool(missing or extra or different)
        result["check"] = {
            "enabled": True,
            "status": ("fail" if status_fail else "ok"),
            "exit_code": (5 if status_fail else 0),
        }
        if args.format == "text":
            if status_fail:
                print(
                    f"\nCHECK FAILED: missing={len(missing)} extra={len(extra)} different={len(different)}",
                    file=sys.stderr,
                )
                sys.exit(5)
            else:
                print("\nCHECK OK: no differences after filtering.")
    else:
        result["check"] = {"enabled": False, "status": None, "exit_code": 0}

    # Output structured JSON result (if --format json)
    if args.format == "json":
        print(json.dumps(result, indent=2, sort_keys=False))
        # Exit with appropriate code if --check was used
        if args.check and result["check"]["exit_code"]:
            sys.exit(result["check"]["exit_code"])


if __name__ == "__main__":
    main()
