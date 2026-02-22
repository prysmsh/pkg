# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in prysmsh/pkg, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, email **security@prysm.sh** with:

- A description of the vulnerability
- Steps to reproduce
- Affected package(s) and version(s)
- Any potential impact

We will acknowledge your report within 48 hours and aim to provide a fix or mitigation within 7 days for critical issues.

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest  | Yes       |

## Scope

This policy covers the Go packages in this repository:

- `pqc` -- Hybrid KEM and AEAD
- `pqc/sign` -- Hybrid signatures
- `kdf` -- Key derivation
- `secret` -- Shamir's Secret Sharing
- `encfile` -- Encrypted storage
- `secure` -- Security primitives
- `tlsutil` -- TLS configuration

## Disclosure

We follow coordinated disclosure. We will credit reporters in the release notes unless they prefer to remain anonymous.
