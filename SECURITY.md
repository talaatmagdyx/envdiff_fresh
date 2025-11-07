# Security Policy

## Supported Versions

We release patches for security vulnerabilities. Which versions are eligible for receiving such patches depends on the CVSS v3.0 Rating:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

Please report (suspected) security vulnerabilities by creating a [private security advisory on GitHub](https://github.com/talaatmagdyx/envdiff_fresh/security/advisories/new). You will receive a response within 48 hours. If the issue is confirmed, we will release a patch as soon as possible depending on complexity but historically within a few days.

**Please do not report security vulnerabilities through public GitHub issues.**

## Security Best Practices

When using `envdiff` and `envset`:

1. **SSH Credentials**: Never commit SSH keys or credentials to version control
2. **Remote Access**: Use SSH key-based authentication instead of passwords
3. **File Permissions**: Ensure configuration files have appropriate permissions (e.g., `chmod 600` for sensitive `.env` files)
4. **Backups**: Always review backups created by the tools before deletion
5. **Network Security**: When accessing remote files, ensure you're connecting over secure networks
6. **Input Validation**: Be cautious when processing untrusted configuration files

## Known Security Considerations

- **Remote File Access**: The tools use SSH/SCP for remote file access. Ensure your SSH configuration is secure.
- **Temporary Files**: Temporary files created during remote operations are cleaned up, but ensure your system's temp directory is secure.
- **Command Injection**: The tools use `shlex.quote()` to safely escape paths in shell commands, but always validate inputs from untrusted sources.

## Disclosure Policy

When we receive a security bug report, we will:

1. Confirm the problem and determine affected versions
2. Audit code to find any potential similar problems
3. Prepare fixes for all releases still under maintenance
4. Publish a security advisory with details and credits

