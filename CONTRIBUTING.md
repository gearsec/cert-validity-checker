# Contributing to cert-validity-checker

Thank you for your interest in contributing! This document provides guidelines
for contributing to the project.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/<your-username>/cert-validity-checker.git`
3. Create a feature branch: `git checkout -b feat/your-feature`
4. Make your changes
5. Run tests: `make test`
6. Run linter: `make lint`
7. Commit your changes following our commit message conventions
8. Push and open a pull request

## Development Prerequisites

- Go 1.25.8 or later
- [golangci-lint](https://golangci-lint.run/welcome/install/)
- [Terraform](https://developer.hashicorp.com/terraform/install) (for infrastructure changes)
- AWS credentials configured (for integration testing)

## Commit Message Format

We follow conventional commits:

```
<type>: <description>

[optional body]
```

Types: `feat`, `fix`, `docs`, `test`, `ci`, `refactor`, `sec`

## Code Standards

- All exported functions must have doc comments
- All packages must have unit tests
- Use `go vet` and `golangci-lint` before submitting
- AWS SDK interactions must be behind interfaces for testability
- No hardcoded credentials or secrets

## Pull Request Process

1. Ensure all CI checks pass
2. Update documentation if your change affects configuration or behavior
3. Add tests for new functionality
4. Request review from a maintainer

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
