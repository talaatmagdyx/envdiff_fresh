# Contributing to envdiff-tool

Thank you for your interest in contributing to envdiff-tool! This document provides guidelines and instructions for contributing.

## Development Setup

### Prerequisites

- Python 3.8 or higher
- pip
- git

### Setup Steps

1. **Fork and clone the repository:**
   ```bash
   git clone https://github.com/talaatmagdyx/envdiff_fresh.git
   cd envdiff_fresh
   ```

2. **Create a virtual environment:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install in development mode:**
   ```bash
   pip install -e ".[dev]"
   ```

   Or use the Makefile:
   ```bash
   make install-dev
   ```

4. **Install pre-commit hooks (optional but recommended):**
   ```bash
   make pre-commit-install
   # or manually:
   pip install pre-commit
   pre-commit install
   ```

## Development Workflow

### Running Tests

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run with coverage report
pytest --cov=envdiff --cov=envset --cov-report=html
```

### Code Quality

```bash
# Check linting
ruff check .

# Format code
ruff format .

# Check formatting without changes
ruff format --check .

# Run all checks (lint + format check + tests)
make check
```

### Making Changes

1. **Create a feature branch:**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes:**
   - Follow the existing code style
   - Add tests for new functionality
   - Update documentation as needed
   - Ensure 100% test coverage is maintained

3. **Run checks before committing:**
   ```bash
   make check
   ```

4. **Commit your changes:**
   ```bash
   git add .
   git commit -m "feat: add new feature"
   ```

   Use conventional commit messages:
   - `feat:` for new features
   - `fix:` for bug fixes
   - `docs:` for documentation changes
   - `test:` for test additions/changes
   - `refactor:` for code refactoring
   - `style:` for formatting changes

5. **Push and create a Pull Request:**
   ```bash
   git push origin feature/your-feature-name
   ```

## Code Style Guidelines

### Python Style

- Follow PEP 8 style guide
- Use type hints for function parameters and return values
- Maximum line length: 100 characters
- Use 4 spaces for indentation
- Use double quotes for strings (enforced by ruff formatter)

### Documentation

- Add docstrings to all public functions and classes
- Use Google-style docstrings
- Include examples in docstrings where helpful
- Update README.md for user-facing changes
- Update CHANGELOG.md for significant changes

### Testing

- Maintain 100% test coverage
- Write tests for all new functionality
- Include edge cases and error conditions
- Use descriptive test function names: `test_<function>_<scenario>`

### File Organization

- Keep functions focused and single-purpose
- Group related functions with section comments
- Place imports at the top, grouped by standard library, third-party, local

## Pull Request Process

1. **Ensure all checks pass:**
   - All tests pass
   - Code coverage remains at 100%
   - Linting passes (`ruff check .`)
   - Formatting is correct (`ruff format --check .`)

2. **Update documentation:**
   - Update README.md if adding new features
   - Update CHANGELOG.md with your changes
   - Ensure docstrings are complete

3. **Write a clear PR description:**
   - Describe what changes you made
   - Explain why you made them
   - Reference any related issues
   - Include examples if applicable

4. **Respond to feedback:**
   - Be open to suggestions and improvements
   - Make requested changes promptly
   - Ask questions if something is unclear

## Reporting Issues

When reporting bugs or requesting features:

1. **Check existing issues** to avoid duplicates
2. **Use clear, descriptive titles**
3. **Provide context:**
   - Python version
   - Operating system
   - Steps to reproduce (for bugs)
   - Expected vs actual behavior
   - Error messages or logs

## Code Review Guidelines

### For Contributors

- Keep PRs focused and reasonably sized
- Respond to review comments promptly
- Be open to feedback and suggestions

### For Reviewers

- Be constructive and respectful
- Explain the reasoning behind suggestions
- Approve when changes meet standards

## Release Process

Releases are handled by maintainers:

1. Update version in `pyproject.toml`
2. Update `CHANGELOG.md` with release date
3. Create git tag: `git tag v0.1.0`
4. Push tag: `git push --tags`
5. GitHub Actions will build and publish to PyPI (if configured)

## Questions?

If you have questions or need help:

- Open an issue for discussion
- Check existing documentation
- Review test files for usage examples

Thank you for contributing! 🎉

