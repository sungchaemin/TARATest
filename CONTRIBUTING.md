# Contributing to TARA Pipeline

Thank you for your interest in contributing to the TARA Pipeline! 🚗

## Code of Conduct

This project is dedicated to providing a harassment-free experience for everyone. We expect all contributors to adhere to our Code of Conduct.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/yourusername/tara-pipeline.git
   cd tara-pipeline
   ```
3. **Create a branch** for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Setup

1. **Install dependencies** (optional):
   ```bash
   pip install -r requirements.txt
   ```

2. **Run tests** to ensure everything works:
   ```bash
   python test_setup.py
   python example_run.py
   ```

## Making Changes

### Types of Contributions

- 🐛 **Bug fixes**
- ✨ **New features** 
- 📚 **Documentation improvements**
- 🔧 **Performance optimizations**
- 🧪 **Test coverage improvements**
- 🚗 **New automotive protocol support**

### Guidelines

- **Security First**: Never introduce vulnerabilities
- **Clean Code**: Follow Python best practices
- **Documentation**: Update README and comments as needed
- **Testing**: Ensure your changes don't break existing functionality
- **Ethical Use**: Maintain focus on authorized security testing

### Commit Messages

Use clear, descriptive commit messages:

```bash
# Good
git commit -m "Add DoIP protocol timeout handling"
git commit -m "Fix NIST control binding for CAN scenarios"
git commit -m "Update README with new installation steps"

# Not so good
git commit -m "fix bug"
git commit -m "update stuff"
```

## Pull Request Process

1. **Update documentation** if needed
2. **Run the test suite**:
   ```bash
   python test_setup.py
   ```
3. **Ensure your PR includes**:
   - Clear description of changes
   - Reasoning for the changes
   - Any breaking changes noted
   - Testing instructions if applicable

4. **Submit your PR** with a clear title and description

### PR Template

```markdown
## Description
Brief description of your changes

## Motivation and Context
Why is this change required? What problem does it solve?

## Testing
- [ ] Ran test_setup.py successfully
- [ ] Tested with example scenarios
- [ ] Tested both LLM and stub modes (if applicable)

## Types of Changes
- [ ] Bug fix (non-breaking change)
- [ ] New feature (non-breaking change)  
- [ ] Breaking change (fix/feature that would cause existing functionality to change)
- [ ] Documentation update

## Checklist
- [ ] My code follows the code style of this project
- [ ] My change requires a change to the documentation
- [ ] I have updated the documentation accordingly
- [ ] I have added tests to cover my changes
- [ ] All new and existing tests passed
```

## Automotive Security Guidelines

When contributing automotive security features:

- **Always prioritize safety** - never introduce code that could affect vehicle safety systems without proper safeguards
- **Follow industry standards** - align with ISO/SAE 21434, NIST guidelines
- **Responsible disclosure** - report security vulnerabilities privately first
- **Test responsibly** - only on authorized systems or simulators

## Questions or Need Help?

- 💬 **General questions**: [GitHub Discussions](https://github.com/yourusername/tara-pipeline/discussions)
- 🐛 **Bug reports**: [GitHub Issues](https://github.com/yourusername/tara-pipeline/issues)
- 📧 **Security concerns**: security@yourorganization.com

Thank you for helping make automotive security testing more accessible! 🙏