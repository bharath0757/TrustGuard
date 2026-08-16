# Development & Contribution Guide

## Branch Strategy & Workflow

1. Clone the repository:
   ```bash
   git clone https://github.com/bharath0757/TrustGuard.git
   cd TrustGuard
   ```
2. Keep synchronized with `develop`:
   ```bash
   git checkout develop
   git pull origin develop
   ```
3. Create your feature branch:
   ```bash
   git checkout -b feature/<module_name>
   ```
4. Verify local integration before committing:
   ```bash
   python scripts/verify_setup.py
   pytest tests
   pytest backend/tests
   ```
5. Commit with descriptive messages:
   ```bash
   git commit -m "feat(module): descriptive explanation"
   ```
6. Push and open pull request targeting `develop`.
