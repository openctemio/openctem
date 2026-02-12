# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take security seriously at OpenCTEM. If you discover a security vulnerability, please follow these steps:

### DO NOT

- Open a public GitHub issue for security vulnerabilities
- Disclose the vulnerability publicly before it's fixed
- Exploit the vulnerability beyond what's necessary to demonstrate it

### DO

1. **Email us directly** at security@openctem.io with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

2. **Use our bug bounty program** (if available) through:
   - [HackerOne](https://hackerone.com.openctemio) (coming soon)

### What to expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 5 business days
- **Resolution Timeline**: Depends on severity
  - Critical: 24-72 hours
  - High: 1-2 weeks
  - Medium: 2-4 weeks
  - Low: Next release cycle

### Security Measures

This repository uses:

- **CodeQL** - Static Application Security Testing (SAST)
- **Gosec** - Go security checker
- **Govulncheck** - Go vulnerability database scanning
- **Trivy** - Container and dependency vulnerability scanning
- **Gitleaks** - Secret detection
- **Dependabot** - Automated dependency updates

## Security Best Practices for Contributors

1. **Never commit secrets** - Use environment variables
2. **Validate all inputs** - Especially user-provided data
3. **Use parameterized queries** - Prevent SQL injection
4. **Follow the principle of least privilege**
5. **Keep dependencies updated** - Review Dependabot PRs promptly
6. **Enable 2FA** on your GitHub account

## Secure Development Guidelines

### Authentication & Authorization
- Use JWT with proper expiration
- Implement refresh token rotation
- Validate tokens on every request
- Use secure password hashing (bcrypt/argon2)

### Data Protection
- Encrypt sensitive data at rest
- Use TLS for all communications
- Sanitize logs (no PII/secrets)
- Implement proper CORS policies

### Input Validation
- Validate and sanitize all user inputs
- Use strong typing
- Implement rate limiting
- Validate file uploads

## Compliance

We aim to comply with:
- OWASP Top 10
- CWE/SANS Top 25
- SOC 2 Type II (planned)
- ISO 27001 (planned)

## Contact

- Security Team: security@openctem.io
- General Issues: https://github.com/openctemio/api/issues
