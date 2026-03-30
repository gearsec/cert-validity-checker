# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email security@gearsec.dev with:

1. A description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Suggested fix (if any)

We will acknowledge receipt within 48 hours and aim to provide a fix within 7 days for critical issues.

## Security Practices

- All dependencies are scanned weekly via automated security pipelines
- Static analysis is performed on every pull request using gosec
- Vulnerability database checks are run using govulncheck
- Supply chain integrity is verified via SafeDep
- Release artifacts are signed using Sigstore cosign (keyless)
