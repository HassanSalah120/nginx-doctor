# Contributing to Nginx Doctor

Thank you for your interest in contributing to Nginx Doctor! We welcome all contributions, from bug reports and feature requests to code changes and documentation improvements.

## Code of Conduct

By participating in this project, you agree to abide by the [Code of Conduct](CODE_OF_CONDUCT.md).

## How to Contribute

### Reporting Bugs

If you find a bug, please [open an issue](https://github.com/HassanSalah120/nginx-doctor/issues/new?template=bug_report.md) and include:

- A clear description of the issue.
- Steps to reproduce the bug.
- Any relevant logs or screenshots.
- Details about your environment (OS, Nginx version, PHP version).

### Suggesting Features

We welcome feature requests! Please [open an issue](https://github.com/HassanSalah120/nginx-doctor/issues/new?template=feature_request.md) and explain:

- What feature you'd like to see.
- Why it would be useful.
- How you imagine it working.

### Submitted Pull Requests

1. Fork the repository and create your branch from `master`.
2. Install dependencies: `pip install -e .[dev]`
3. Ensure your code follows the project's style and passes all existing tests:
   ```bash
   python -m pytest
   ```
4. If you've added new features, please add corresponding tests.
5. Submit your pull request with a clear description of the changes.

## Development Setup

Nginx Doctor is built with Python and uses `pytest` for testing.

```bash
# Clone your fork
git clone https://github.com/YOUR-USERNAME/nginx-doctor.git
cd nginx-doctor

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in editable mode with dev dependencies
pip install -e .
```

## Questions?

If you have any questions, feel free to open an issue or reach out to the maintainers.
