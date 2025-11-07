# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive test suite with 100% code coverage
- Ruff linting integration for code quality
- Support for dict/list values in patch generation
- Enhanced error handling for edge cases

### Changed
- Refactored code to comply with Ruff style guidelines (E701/E702)
- Fixed deprecation warnings (replaced `datetime.utcnow()` with `datetime.now(timezone.utc)`)
- Improved code readability by splitting one-line statements

### Fixed
- Fixed ambiguous variable names in test files
- Fixed unused imports across test suite
- Fixed coverage gaps in edge case handling

## [0.1.0] - 2025-11-07

### Added

#### envdiff - Compare & Patch Tool
- **Remote Operations**: Support for SSH/SCP to access remote files
  - `--source-ssh-port`, `--source-ssh-identity`, `--source-ssh-extra` options
  - `--target-ssh-port`, `--target-ssh-identity`, `--target-ssh-extra` options
  - Global SSH options: `--ssh-port`, `--ssh-identity`, `--ssh-extra`
- **File Format Support**:
  - `.env` files (standard environment variable format)
  - YAML files (with nested key flattening)
  - Python `config.py` files (CONFIG/ENV dicts and UPPERCASE constants)
- **Comparison Features**:
  - Detect missing, extra, and different keys between source and target
  - Case-sensitive and case-insensitive comparison modes
  - Prefix filtering (`--only-prefix`, `--ignore-prefix`)
  - Regex-based filtering (`--include`, `--exclude`)
- **Patch Generation**:
  - Multiple output formats: `export`, `dotenv`, `powershell`
  - Generate patches for missing and different keys
  - Output to file or stdout
- **Apply Changes**:
  - `--apply` flag to directly modify target `.env` files
  - `--apply-dry-run` to preview changes without applying
  - Automatic backup creation with timestamp suffix
  - Backup control via `--apply-backup` (auto/none)
- **CI/CD Integration**:
  - `--check` flag exits with code 5 when differences exist
  - JSON output format for machine-readable reports
  - `--json-only` mode for automation scripts
  - `--keys-json` for lightweight key-only output
- **Output Formats**:
  - Human-readable text format (default)
  - Structured JSON format with full diff details
  - `--show-same` to include matching keys in output

#### envset - Single Key Editor
- **Multi-Format Support**:
  - Edit keys in `.env` files
  - Edit nested keys in YAML files (dot notation: `app.database.host`)
  - Edit Python `config.py` files (CONFIG/ENV dicts and constants)
- **Remote Operations**: SSH/SCP support for remote file editing
- **In-Place Rewriting**:
  - `--rewrite` flag for updating existing constants and dict assignments
  - Preserves file structure and formatting
- **Value Types**:
  - String values (default)
  - JSON values with `--json` flag for typed data (numbers, booleans, arrays, objects)
- **Safety Features**:
  - `--dry-run` to preview changes without modifying files
  - Automatic backup creation before modifications
  - Backup control via `--backup` (auto/none)
- **Batch Operations**: Update the same key across multiple files simultaneously

### Technical Details

#### Code Quality
- 100% test coverage across all modules
- Comprehensive test suite with 112+ tests
- Ruff linting with zero errors
- Type hints throughout codebase
- Python 3.8+ compatibility

#### Architecture
- Single-file modules (`envdiff.py`, `envset.py`)
- Minimal dependencies (PyYAML only)
- No external runtime dependencies for core functionality
- Clean separation of concerns

### Documentation
- Comprehensive README with examples
- Usage examples for all features
- CI/CD integration guide
- Windows PowerShell support guide
- FAQ section

### Examples
- Sample files in `examples/` directory
- Test files demonstrate all use cases
- CLI integration tests cover edge cases


