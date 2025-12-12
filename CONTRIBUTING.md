# Contributing to Sibna

Thank you for your interest in contributing to Sibna! This document provides guidelines for contributing to the project.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for all contributors.

## How to Contribute

### Reporting Bugs

If you find a bug, please create an issue with:
- Clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- Your environment (OS, Python version, etc.)
- Relevant logs or error messages

### Suggesting Features

Feature suggestions are welcome! Please:
- Check if the feature has already been requested
- Clearly describe the feature and its use case
- Explain why it would be valuable to the project

### Pull Requests

1. **Fork the repository** and create a new branch from `main`
2. **Make your changes** following our coding standards
3. **Add tests** for new functionality
4. **Update documentation** as needed
5. **Run the test suite** to ensure everything passes
6. **Submit a pull request** with a clear description

## Development Setup

```bash
# Clone your fork
git clone https://github.com/yourusername/sibna.git
cd sibna

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest
```

## Coding Standards

### Python Style

- Follow [PEP 8](https://pep8.org/) style guide
- Use [Black](https://black.readthedocs.io/) for code formatting
- Use type hints where appropriate
- Write docstrings for all public functions and classes

### Code Formatting

```bash
# Format code with Black
black sibna/ tests/

# Check types with mypy
mypy sibna/

# Run security checks
bandit -r sibna/
```

### Testing

- Write tests for all new features
- Maintain or improve code coverage
- Run the full test suite before submitting PR

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=sibna tests/

# Run specific test file
pytest tests/test_security.py -v
```

## Security

### Reporting Security Issues

**DO NOT** create public issues for security vulnerabilities. Instead:
- Email security concerns to [security email]
- Provide detailed information about the vulnerability
- Allow time for the issue to be addressed before public disclosure

### Security Best Practices

When contributing:
- Never commit sensitive data (keys, credentials, etc.)
- Use secure coding practices
- Be mindful of timing attacks and side channels
- Follow cryptographic best practices

## Documentation

- Update README.md for user-facing changes
- Add docstrings to new functions/classes
- Update EXAMPLES.md with usage examples
- Keep documentation clear and concise

## Commit Messages

Write clear, descriptive commit messages:

```
Short summary (50 chars or less)

More detailed explanation if needed. Wrap at 72 characters.
Explain what changed and why, not how.

- Bullet points are okay
- Use present tense ("Add feature" not "Added feature")
- Reference issues: "Fixes #123"
```

## Pull Request Process

1. **Update your branch** with the latest `main`
2. **Ensure all tests pass** and code is formatted
3. **Update documentation** as needed
4. **Fill out the PR template** completely
5. **Wait for review** - maintainers will review your PR
6. **Address feedback** if requested
7. **Merge** - once approved, your PR will be merged

## Review Process

- All PRs require at least one review from a maintainer
- Reviews focus on:
  - Code quality and style
  - Test coverage
  - Security implications
  - Documentation completeness
  - Performance impact

## Areas for Contribution

We especially welcome contributions in:

- 🐛 **Bug Fixes**: Fix reported issues
- 🔒 **Security**: Improve security features
- 📝 **Documentation**: Improve clarity and examples
- ✨ **Features**: Add new functionality (discuss first!)
- 🧪 **Tests**: Improve test coverage
- ⚡ **Performance**: Optimize critical paths
- 🌍 **Translations**: Translate documentation

## Questions?

- Open a [Discussion](https://github.com/yourusername/sibna/discussions)
- Check existing [Issues](https://github.com/yourusername/sibna/issues)
- Read the [Documentation](docs/)

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.

---

Thank you for contributing to Sibna! 🙏
