#!/usr/bin/env python3
"""
envset - Single key editor for environment configurations across multiple files.

This module provides functionality to:
- Edit a single key across multiple files simultaneously
- Support multiple file formats (.env, YAML, Python config.py)
- Handle nested keys in YAML and Python dicts using dot notation
- Support remote file editing via SSH/SCP
- Create automatic backups before modifications
- Support in-place rewriting of existing constants and dict assignments
- Handle JSON values for typed data (numbers, booleans, arrays, objects)

Supported file formats:
- .env files (standard KEY=VALUE format)
- YAML files (with nested key support via dot notation)
- Python config.py files (CONFIG/ENV dicts and UPPERCASE constants)
"""

import argparse
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


def is_remote(path: str) -> bool:
    """
    Check if a path is a remote path (SSH/SCP format).

    Args:
        path: Path string to check

    Returns:
        True if path matches remote format (host:/path), False otherwise

    Examples:
        >>> is_remote("user@server:/etc/config.yml")
        True
        >>> is_remote("/local/path/.env")
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


def _ssh_base(
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
        >>> _ssh_base("server", 2222, "/path/to/key", ["StrictHostKeyChecking=no"])
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


def ssh_read(
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
    base = _ssh_base(host, port, identity, extra)
    out = subprocess.check_output(
        base + [f"cat {shlex.quote(rpath)}"], stderr=subprocess.STDOUT, timeout=timeout
    )
    return out.decode("utf-8", errors="replace")


def ssh_run(
    host: str,
    cmd_str: str,
    port: Optional[int],
    identity: Optional[str],
    extra: Optional[List[str]],
    timeout: int = 30,
):
    """
    Execute a command on remote host via SSH (no return value).

    Args:
        host: SSH hostname
        cmd_str: Command string to execute remotely
        port: Optional SSH port
        identity: Optional SSH identity file path
        extra: Optional SSH options
        timeout: Command timeout in seconds (default: 30)

    Raises:
        subprocess.CalledProcessError: If command fails
        subprocess.TimeoutExpired: If command times out

    Note:
        Used for commands that don't need output (e.g., backup creation)
    """
    base = _ssh_base(host, port, identity, extra)
    subprocess.check_call(
        base + [cmd_str], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, timeout=timeout
    )


def scp_upload(
    local: str,
    remote: str,
    port: Optional[int],
    identity: Optional[str],
    extra: Optional[List[str]],
    timeout: int = 60,
):
    """
    Upload local file to remote location via SCP.

    Args:
        local: Local file path
        remote: Remote destination (host:/path format)
        port: Optional SSH port
        identity: Optional SSH identity file path
        extra: Optional SSH options
        timeout: Command timeout in seconds (default: 60)

    Raises:
        subprocess.CalledProcessError: If upload fails
    """
    cmd = _scp_cmd(local, remote, port, identity, extra)
    subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, timeout=timeout)


# --- .env file parser and generator ---

# Regex pattern for matching .env file lines: KEY=VALUE format
# Simpler than envdiff's pattern - matches key and value separately
ENV_LINE_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_\.]*)\s*=\s*(.*)$")


def parse_env(text: str) -> Dict[str, str]:
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
        >>> parse_env("APP_NAME=myapp\\nDATABASE_URL='postgres://...'")
        {'APP_NAME': 'myapp', 'DATABASE_URL': 'postgres://...'}
    """
    out: Dict[str, str] = {}
    for raw in text.splitlines():
        # Skip empty lines and comments
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        m = ENV_LINE_RE.match(raw)
        if not m:
            continue
        key, val = m.group(1), m.group(2).strip()
        # Remove surrounding quotes if present
        if (val.startswith('"') and val.endswith('"')) or (
            val.startswith("'") and val.endswith("'")
        ):
            val = val[1:-1]
        # Unescape common escape sequences
        val = val.replace("\\n", "\n").replace("\\r", "\r").replace("\\t", "\t")
        out[key] = val
    return out


def dump_env(kv: Dict[str, Any]) -> str:
    """
    Generate .env file content from key-value dictionary.

    Args:
        kv: Dictionary of key-value pairs (sorted by key)

    Returns:
        Complete .env file content as string (with trailing newline)

    Notes:
        - Keys are sorted alphabetically
        - Values are quoted if they contain spaces, #, quotes, or are empty
        - None values become empty strings
        - Special characters in values are escaped

    Example:
        >>> dump_env({"APP": "myapp", "DEBUG": True})
        'APP=myapp\\nDEBUG=true\\n'
    """
    lines = []
    for k in sorted(kv.keys()):
        v = "" if kv[k] is None else str(kv[k])
        # Quote if value contains special characters or is empty
        if re.search(r"\s|#|['\"]", v) or v == "":
            dq = v.replace("\\", "\\\\").replace('"', '\\"')
            lines.append(f'{k}="{dq}"')
        else:
            lines.append(f"{k}={v}")
    return "\n".join(lines) + "\n"


# --- YAML file parser and generator ---


def parse_yaml(text: str) -> Dict[str, Any]:
    """
    Parse YAML file content into a dictionary.

    Args:
        text: YAML file content as string

    Returns:
        Dictionary representation of YAML structure

    Raises:
        RuntimeError: If top-level YAML is not a dictionary/mapping

    Note:
        Unlike envdiff, this preserves the nested structure (doesn't flatten)
    """
    import yaml

    data = yaml.safe_load(text) or {}
    if not isinstance(data, dict):
        raise RuntimeError("Top-level YAML must be a mapping")
    return data


def dump_yaml(data: Dict[str, Any]) -> str:
    """
    Convert dictionary to YAML string representation.

    Args:
        data: Dictionary to convert

    Returns:
        YAML-formatted string

    Note:
        Keys are not sorted to preserve original order
    """
    import yaml

    return yaml.safe_dump(data, sort_keys=False)


def ensure_yaml_path(d: Dict[str, Any], path: List[str]) -> Dict[str, Any]:
    """
    Ensure nested dictionary path exists, creating intermediate dicts as needed.

    Args:
        d: Root dictionary
        path: List of keys representing the path (e.g., ["app", "database"])

    Returns:
        Dictionary at the parent level (ready for setting the final key)

    Example:
        >>> d = {}
        >>> ensure_yaml_path(d, ["app", "database", "host"])
        {}  # Returns the "database" dict
        >>> d
        {'app': {'database': {}}}
    """
    cur = d
    # Create intermediate dictionaries for all but the last key
    for p in path[:-1]:
        if p not in cur or not isinstance(cur[p], dict):
            cur[p] = {}
        cur = cur[p]
    return cur


def set_yaml_key(d: Dict[str, Any], dotkey: str, value: Any):
    """
    Set a nested key in YAML dictionary using dot notation.

    Args:
        d: Root dictionary
        dotkey: Dot-separated key path (e.g., "app.database.host")
        value: Value to set

    Raises:
        ValueError: If key is empty after splitting

    Example:
        >>> d = {}
        >>> set_yaml_key(d, "app.database.host", "localhost")
        >>> d
        {'app': {'database': {'host': 'localhost'}}}
    """
    parts = [p for p in dotkey.split(".") if p]
    if not parts:
        raise ValueError("Empty key")
    # Ensure parent path exists
    parent = ensure_yaml_path(d, parts)
    # Set the final key
    parent[parts[-1]] = value


# --- Python config.py file handler ---


def set_configpy_assign_block(existing_text: str, dotkey: str, value: Any) -> str:
    """
    Generate Python code block to set a key in config.py file.

    This function appends a code block that sets either:
    1. A nested CONFIG/ENV dict key via dot notation (e.g., "database.host")
    2. An UPPERCASE constant if no dict exists or key is a simple ALL_CAPS token

    Args:
        existing_text: Current content of config.py file
        dotkey: Key to set (dot notation for nested, or UPPERCASE for constant)
        value: Value to assign (will be Python-repr'd)

    Returns:
        Updated file content with appended assignment block

    Notes:
        - Detects if CONFIG or ENV dict exists in file
        - Creates CONFIG dict if neither exists and key is not a constant
        - Uses try/except blocks for safe execution
        - Adds comment markers for easy identification

    Example:
        >>> set_configpy_assign_block("CONFIG = {}\\n", "database.host", "localhost")
        'CONFIG = {}\\n# --- envset update (dict) ---\\ntry:\\n    _t = CONFIG\\n    _t = _t.setdefault(\\'database\\', {})\\nexcept Exception:\\n    pass\\nCONFIG[\\'database\\'][\\'host\\'] = \\'localhost\\'\\n'
    """
    # Check if key is a simple UPPERCASE constant (e.g., "API_KEY")
    is_constant = bool(re.fullmatch(r"[A-Z][A-Z0-9_]*", dotkey))
    # Check if CONFIG or ENV dictionaries exist in file
    has_config = re.search(r"^\s*CONFIG\s*=", existing_text, re.M) is not None
    has_env = re.search(r"^\s*ENV\s*=", existing_text, re.M) is not None
    # Determine target dict (CONFIG takes precedence over ENV)
    target = "CONFIG" if has_config else ("ENV" if has_env else None)
    # Convert value to Python representation
    vsrc = repr(value)

    # Case 1: UPPERCASE constant and no CONFIG/ENV dict exists
    if is_constant and not target:
        block = f"# --- envset update (constant) ---\n{dotkey} = {vsrc}\n"
        return existing_text + ("" if existing_text.endswith("\n") else "\n") + block

    # Case 2: CONFIG or ENV dict exists - set nested key
    if target:
        parts = [p for p in dotkey.split(".") if p]
        if not parts:
            raise ValueError("Empty key")
        # Build Python code to safely set nested dict key
        py_lines = ["# --- envset update (dict) ---", "try:", f"    _t = {target}"]
        # Create intermediate dicts if they don't exist
        for p in parts[:-1]:
            py_lines.append(f"    _t = _t.setdefault({repr(p)}, {{}})")
        py_lines += ["except Exception:", "    pass"]
        # Build index chain for nested access (e.g., ['database']['host'])
        index_chain = "".join([f"[{repr(p)}]" for p in parts[:-1]])
        # Final assignment
        py_lines.append(f"{target}{index_chain}[{repr(parts[-1])}] = {vsrc}")
        block = "\n".join(py_lines) + "\n"
        return existing_text + ("" if existing_text.endswith("\n") else "\n") + block

    # Case 3: No CONFIG/ENV dict exists and key is not a constant - create CONFIG
    parts = [p for p in dotkey.split(".") if p]
    py_lines = [
        "# --- envset update (create CONFIG) ---",
        "try:",
        "    CONFIG",  # Check if CONFIG exists
        "except NameError:",
        "    CONFIG = {}",  # Create CONFIG if it doesn't exist
        "try:",
        "    _t = CONFIG",
    ]
    # Create intermediate dicts
    for p in parts[:-1]:
        py_lines.append(f"    _t = _t.setdefault({repr(p)}, {{}})")
    py_lines += ["except Exception:", "    pass"]
    # Build index chain and final assignment
    index_chain = "".join([f"[{repr(p)}]" for p in parts[:-1]])
    py_lines.append(f"CONFIG{index_chain}[{repr(parts[-1])}] = {vsrc}")
    block = "\n".join(py_lines) + "\n"
    return existing_text + ("" if existing_text.endswith("\n") else "\n") + block


# --- File I/O helpers ---


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
    local = parse_remote(path)[1] if is_remote(path) else path
    ext = os.path.splitext(local)[1].lower()
    if ext in (".yml", ".yaml"):
        return "yaml"
    if ext == ".py":
        return "py"
    return "env"


def read_text(
    path: str, ssh_port: Optional[int], ssh_identity: Optional[str], ssh_extra: Optional[List[str]]
) -> str:
    """
    Read text content from local file or remote file via SSH.

    Args:
        path: File path (local, remote "host:/path", or "-" for stdin)
        ssh_port: Optional SSH port for remote paths
        ssh_identity: Optional SSH identity file for remote paths
        ssh_extra: Optional SSH options for remote paths

    Returns:
        File content as string

    Note:
        Remote paths are read via SSH cat command
    """
    if is_remote(path):
        host, rp = parse_remote(path)
        return ssh_read(host, rp, ssh_port, ssh_identity, ssh_extra)
    with open(path, encoding="utf-8") as f:
        return f.read()


def write_text(
    path: str,
    text: str,
    backup: Optional[str],
    ssh_port: Optional[int],
    ssh_identity: Optional[str],
    ssh_extra: Optional[List[str]],
):
    """
    Write text content to local file or remote file, optionally creating backup.

    Args:
        path: Destination path (local or remote "host:/path")
        text: Content to write
        backup: Optional backup suffix (e.g., "bak-20240101120000")
        ssh_port: Optional SSH port for remote paths
        ssh_identity: Optional SSH identity file for remote paths
        ssh_extra: Optional SSH options for remote paths

    Notes:
        - Remote files: backup created via SSH cp command, then upload via SCP
        - Local files: backup created via shutil.copy2, then write new content
        - Backup is skipped if backup is None
        - Directory is created if it doesn't exist (for local paths)
    """
    if is_remote(path):
        host, rp = parse_remote(path)
        # Create backup on remote server if requested
        if backup:
            ssh_run(
                host,
                f"cp {shlex.quote(rp)} {shlex.quote(rp + '.' + backup)} 2>/dev/null || true",
                ssh_port,
                ssh_identity,
                ssh_extra,
            )
        # Write to temp file, then upload
        tmp = tempfile.NamedTemporaryFile(prefix="envset_", delete=False)
        tmp.write(text.encode("utf-8"))
        tmp.flush()
        tmp.close()
        try:
            scp_upload(tmp.name, f"{host}:{rp}", ssh_port, ssh_identity, ssh_extra)
        finally:
            try:
                os.unlink(tmp.name)
            except Exception:
                pass
    else:
        # Local file: create backup if requested and file exists
        if backup and os.path.exists(path):
            import shutil

            shutil.copy2(path, path + "." + backup)
        # Ensure directory exists
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)


def main():
    """
    Main entry point for envset CLI tool.

    Edits a single key across multiple files in different formats.
    Supports local and remote files via SSH/SCP.

    Exit codes:
        - 0: Success
        - 2: Invalid JSON value when --json is used
    """
    ap = argparse.ArgumentParser(
        description="Add/edit a key across multiple files (.env, YAML, config.py dicts or constants)."
    )
    ap.add_argument("--files", nargs="+", required=True)
    ap.add_argument("--key", required=True, help="dot.path for dicts; ALL_CAPS for constants.")
    ap.add_argument("--value", required=True, help="String value; add --json for typed.")
    ap.add_argument("--type", choices=["env", "yaml", "py"])
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--backup", default="auto", choices=["auto", "none"])
    ap.add_argument(
        "--rewrite",
        action="store_true",
        help="In-place rewrite for existing constants or dotted CONFIG/ENV assignments in config.py.",
    )
    ap.add_argument("--ssh-port", type=int)
    ap.add_argument("--ssh-identity")
    ap.add_argument("--ssh-extra")
    args = ap.parse_args()

    # Parse value (JSON if --json flag, otherwise string)
    if args.json:
        try:
            new_value = json.loads(args.value)
        except Exception as e:
            print(f"ERROR: --json value not valid JSON: {e}", file=sys.stderr)
            sys.exit(2)
    else:
        new_value = args.value

    # Parse SSH extra options (comma-separated)
    extra = [x.strip() for x in (args.ssh_extra.split(",") if args.ssh_extra else []) if x.strip()]
    # Generate backup suffix if backups are enabled
    backup_suffix = (
        None if args.backup == "none" else datetime.now(timezone.utc).strftime("bak-%Y%m%d%H%M%S")
    )

    # Process each file in the list
    for path in args.files:
        # Detect file type (or use explicit type if provided)
        ftype = detect_type(path, args.type)

        # Read file content
        try:
            original = read_text(path, args.ssh_port, args.ssh_identity, extra)
        except Exception as e:
            print(f"[{path}] ERROR reading: {e}", file=sys.stderr)
            continue

        # Update file based on type
        if ftype == "env":
            # .env file: parse, update key, regenerate
            kv = parse_env(original)
            kv[args.key] = new_value
            updated = dump_env(kv)

        elif ftype == "yaml":
            # YAML file: parse, set nested key, regenerate
            data = parse_yaml(original)
            set_yaml_key(data, args.key, new_value)
            updated = dump_yaml(data)

        elif ftype == "py":
            # Python config.py: handle rewrite or append
            try:
                if args.rewrite:
                    # In-place rewrite mode: try to find and replace existing assignment
                    if re.fullmatch(r"[A-Z][A-Z0-9_]*", args.key or ""):
                        # UPPERCASE constant: find and replace existing constant assignment
                        const_re = re.compile(rf"^(\s*){re.escape(args.key)}\s*=\s*.*?$", re.M)
                        if const_re.search(original):
                            # Replace existing constant
                            new_line = rf"\1{args.key} = {repr(new_value)}"
                            updated = const_re.sub(new_line, original, count=1)
                        else:
                            # Constant doesn't exist, append it
                            updated = set_configpy_assign_block(original, args.key, new_value)
                    else:
                        # Dot notation key: try to find and replace dict assignment
                        parts = [p for p in (args.key or "").split(".") if p]
                        if parts:
                            # Build index chain (e.g., ['database']['host'])
                            idx = "".join([f"[{repr(p)}]" for p in parts])
                            # Regex to match CONFIG['key'] or ENV['key'] assignments
                            dict_re = re.compile(
                                rf"^(\s*)(CONFIG|ENV){re.escape(idx)}\s*=\s*.*?$", re.M
                            )
                            if dict_re.search(original):
                                # Replace existing dict assignment
                                new_line = rf"\1\2{idx} = {repr(new_value)}"
                                updated = dict_re.sub(new_line, original, count=1)
                            else:
                                # Dict assignment doesn't exist, append it
                                updated = set_configpy_assign_block(original, args.key, new_value)
                        else:
                            # Empty key after splitting
                            updated = set_configpy_assign_block(original, args.key, new_value)
                else:
                    # Append mode: always append new assignment block
                    updated = set_configpy_assign_block(original, args.key, new_value)
            except Exception as e:
                print(f"[{path}] ERROR updating config.py: {e}", file=sys.stderr)
                continue
        else:
            print(f"[{path}] Unsupported type: {ftype}", file=sys.stderr)
            continue

        # Output or write updated content
        if args.dry_run:
            # Dry-run mode: show what would be written (truncated to 600 chars)
            print(f"\n[{path}] DRY-RUN: set {args.key} = {new_value!r}")
            print(updated[:600] + ("...\n" if len(updated) > 600 else ""))
        else:
            # Actually write the file
            try:
                write_text(path, updated, backup_suffix, args.ssh_port, args.ssh_identity, extra)
                print(
                    f"[{path}] updated{(' (backup .' + backup_suffix + ')' if backup_suffix else '')}"
                )
            except Exception as e:
                print(f"[{path}] ERROR writing: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
