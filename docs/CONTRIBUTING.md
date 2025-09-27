# 🤝 Contributing to ZyraCrypt

Thank you for your interest in contributing to ZyraCrypt! This document provides guidelines and information for contributors.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Contributing Guidelines](#contributing-guidelines)
- [Testing Requirements](#testing-requirements)
- [Security Guidelines](#security-guidelines)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Documentation](#documentation)
- [Community](#community)

## 🤲 Code of Conduct

By participating in this project, you are expected to uphold our Code of Conduct:

- **Be respectful**: Treat all contributors with respect and kindness
- **Be inclusive**: Welcome newcomers and encourage diverse perspectives
- **Be collaborative**: Work together constructively and help others learn
- **Be professional**: Keep discussions focused and constructive
- **Be patient**: Remember that everyone has different experience levels

## 🚀 Getting Started

### Prerequisites

- **Python 3.11 or higher**
- **Git** for version control
- **Basic cryptography knowledge** (recommended)
- **Familiarity with Python testing frameworks**

### Setting Up Your Development Environment

1. **Fork the repository** on GitHub
2. **Clone your fork**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/ZyraCrypt.git
   cd ZyraCrypt
   ```
3. **Set up upstream remote**:
   ```bash
   git remote add upstream https://github.com/Alqudimi/ZyraCrypt.git
   ```
4. **Install development dependencies**:
   ```bash
   pip install -e ".[dev]"
   ```

## 🛠️ Development Setup

### Virtual Environment (Recommended)

```bash
# Create virtual environment
python -m venv zyracrypt-dev
source zyracrypt-dev/bin/activate  # On Windows: zyracrypt-dev\Scripts\activate

# Install package in editable mode
pip install -e .

# Install development dependencies
pip install pytest black ruff mypy cython
```

### Development Dependencies

```bash
# Core development tools
pip install black>=22.0.0        # Code formatting
pip install ruff>=0.1.0          # Linting
pip install mypy>=1.0.0          # Type checking
pip install pytest>=7.0.0        # Testing framework
pip install pytest-cov>=4.0.0    # Coverage reporting
pip install cython>=3.0.0        # Compilation support
```

### Verify Installation

```bash
# Run comprehensive tests
python corrected_comprehensive_test.py

# Expected output: 100% success rate
```

## 📝 Contributing Guidelines

### Types of Contributions

We welcome various types of contributions:

- 🐛 **Bug fixes**
- ✨ **New features**
- 📚 **Documentation improvements**
- 🧪 **Test enhancements**
- ⚡ **Performance optimizations**
- 🔒 **Security improvements**
- 🎨 **Code quality improvements**

### Before You Start

1. **Check existing issues** to avoid duplicates
2. **Create an issue** for new features or major changes
3. **Discuss your approach** before implementing large changes
4. **Follow security best practices** for cryptographic code

### Workflow

1. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```
2. **Make your changes** following our coding standards
3. **Add or update tests** for your changes
4. **Update documentation** if needed
5. **Commit your changes** with clear messages
6. **Push to your fork** and create a pull request

## 🧪 Testing Requirements

### Comprehensive Testing

All contributions must maintain our **100% test success rate**.

#### Running Tests

```bash
# Run comprehensive test suite
python corrected_comprehensive_test.py

# Run specific module tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=zyracrypt --cov-report=html
```

#### Test Requirements

- ✅ **All existing tests must pass**
- ✅ **New features require comprehensive tests**
- ✅ **Bug fixes must include regression tests**
- ✅ **Cryptographic functions require security tests**
- ✅ **Performance tests for optimization changes**

#### Test Categories

1. **Unit Tests**: Individual function/method testing
2. **Integration Tests**: Module interaction testing
3. **Security Tests**: Cryptographic correctness verification
4. **Performance Tests**: Benchmark validation
5. **API Tests**: REST API endpoint testing

### Writing Tests

```python
# Example test structure
import pytest
from zyracrypt.encryption_system.src.core_cryptography.symmetric_encryption import SymmetricEncryption

class TestSymmetricEncryption:
    def setup_method(self):
        self.symmetric = SymmetricEncryption()
        self.key = os.urandom(32)
    
    def test_aes_gcm_encryption_decryption(self):
        """Test AES-GCM encryption and decryption"""
        plaintext = b"Test message"
        
        # Encrypt
        iv, ciphertext, tag = self.symmetric.encrypt_aes_gcm(self.key, plaintext)
        
        # Verify encryption produced output
        assert iv is not None
        assert ciphertext is not None
        assert tag is not None
        assert ciphertext != plaintext
        
        # Decrypt
        decrypted = self.symmetric.decrypt_aes_gcm(self.key, iv, ciphertext, tag)
        assert decrypted == plaintext
    
    def test_invalid_key_raises_exception(self):
        """Test that invalid keys raise appropriate exceptions"""
        with pytest.raises(ValueError):
            self.symmetric.encrypt_aes_gcm(b"short_key", b"test")
```

## 🔒 Security Guidelines

### Cryptographic Code Standards

- **Use established libraries**: Never implement crypto primitives from scratch
- **Constant-time operations**: Avoid timing attacks
- **Secure random generation**: Use cryptographically secure randomness
- **Key management**: Proper key lifecycle handling
- **Input validation**: Validate all cryptographic inputs
- **Error handling**: Secure error messages (no information leakage)

### Security Review Process

1. **Self-review**: Check for common security issues
2. **Peer review**: Have another developer review security-critical code
3. **Testing**: Include security-specific tests
4. **Documentation**: Update security documentation

### Common Security Issues to Avoid

❌ **Timing attacks in comparisons**
```python
# Bad: Variable-time comparison
if computed_hash == provided_hash:
    return True

# Good: Constant-time comparison
return constant_time.bytes_eq(computed_hash, provided_hash)
```

❌ **Weak random number generation**
```python
# Bad: Predictable randomness
import random
key = random.randint(0, 2**256)

# Good: Cryptographically secure
import os
key = os.urandom(32)
```

❌ **Information leakage in errors**
```python
# Bad: Reveals internal state
raise ValueError(f"Invalid key: {key}")

# Good: Generic error message
raise ValueError("Invalid key format")
```

## 📋 Pull Request Process

### Before Submitting

- [ ] Code follows PEP 8 style guidelines
- [ ] All tests pass (100% success rate maintained)
- [ ] Documentation updated for new features
- [ ] Security review completed for crypto code
- [ ] Commit messages are clear and descriptive
- [ ] No sensitive information in commits

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Security enhancement

## Testing
- [ ] All existing tests pass
- [ ] New tests added for changes
- [ ] Manual testing completed

## Security Review
- [ ] No new security vulnerabilities introduced
- [ ] Cryptographic code follows best practices
- [ ] Input validation implemented

## Documentation
- [ ] Code comments updated
- [ ] Documentation files updated
- [ ] API documentation updated (if applicable)

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Assignee added for review
```

### Review Process

1. **Automated checks**: CI/CD pipeline validation
2. **Code review**: Manual review by maintainers
3. **Security review**: Additional review for cryptographic changes
4. **Testing**: Comprehensive test execution
5. **Documentation review**: Documentation accuracy check

## 📏 Coding Standards

### Python Style Guide

- **Follow PEP 8**: Use black for auto-formatting
- **Type hints**: Add type hints for all functions
- **Docstrings**: Use Google-style docstrings
- **Line length**: Maximum 88 characters (black default)
- **Import order**: Use isort for import organization

### Code Formatting

```bash
# Format code with black
black zyracrypt/

# Sort imports
isort zyracrypt/

# Lint with ruff
ruff check zyracrypt/

# Type check with mypy
mypy zyracrypt/
```

### Documentation Style

```python
def encrypt_data(plaintext: bytes, key: bytes, algorithm: str = "aes_gcm") -> tuple[bytes, bytes, bytes]:
    """
    Encrypt data using specified algorithm.
    
    Args:
        plaintext: Data to encrypt
        key: Encryption key (32 bytes for AES-256)
        algorithm: Encryption algorithm to use
    
    Returns:
        Tuple of (iv, ciphertext, tag)
    
    Raises:
        ValueError: If key length is invalid
        CryptographyError: If encryption fails
    
    Example:
        >>> key = os.urandom(32)
        >>> iv, ciphertext, tag = encrypt_data(b"secret", key)
    """
```

### Commit Message Format

```
type(scope): Brief description

Optional longer description with more details.

- Change 1
- Change 2

Fixes #123
```

**Types**: feat, fix, docs, style, refactor, test, chore, security

## 📚 Documentation

### Documentation Requirements

- **Code comments**: Explain complex algorithms and security considerations
- **API documentation**: Document all public functions and classes
- **User guides**: Update user-facing documentation
- **Developer docs**: Maintain technical documentation
- **Examples**: Provide working code examples

### Documentation Structure

```
docs/
├── user_guide.md           # User documentation
├── developer_guide.md      # Developer documentation
├── api.md                  # API reference
├── security.md             # Security guidelines
├── examples/               # Code examples
│   ├── basic_usage.py
│   ├── advanced_features.py
│   └── enterprise_setup.py
├── tutorials/              # Step-by-step guides
└── troubleshooting.md      # Common issues
```

## 🌐 Community

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and discussions
- **Pull Requests**: Code contributions and reviews
- **Security Issues**: security@alqudimi.tech (private)

### Getting Help

- **Documentation**: Check existing documentation first
- **Search Issues**: Look for similar issues or questions
- **Ask Questions**: Create a discussion for general questions
- **Report Bugs**: Use issue templates for bug reports

### Code Review Expectations

- **Be constructive**: Provide helpful feedback
- **Be specific**: Point out exact issues and suggest improvements
- **Be respectful**: Maintain professional tone
- **Be thorough**: Review both functionality and security aspects

## 🎯 Development Priorities

### Current Focus Areas

1. **Performance Optimization**: Improve encryption throughput
2. **Post-Quantum Features**: Expand quantum-resistant algorithms
3. **Documentation**: Enhance user and developer guides
4. **Testing**: Increase test coverage and add fuzzing
5. **Security Auditing**: Regular security reviews and updates

### Roadmap Contributions

See our [development roadmap](ROADMAP.md) for planned features and improvements.

## 📞 Contact

For questions about contributing:

- **General Questions**: GitHub Discussions
- **Security Issues**: security@alqudimi.tech
- **Maintainer Contact**: contact@alqudimi.tech

---

Thank you for contributing to ZyraCrypt! Your efforts help make cryptography more accessible and secure for everyone.

## ✨ Recognition

Contributors are recognized in:
- **README.md**: Major contributors listed
- **CHANGELOG.md**: Contributions noted in releases
- **GitHub**: Contributor stats and recognition

*Every contribution, no matter how small, makes a difference!*