# Test Data Fixtures

This directory contains synthetic fixtures used exclusively for automated unit and integration testing of Hammerhead's audit engine and rule checkers.

### Repository Fixtures

- `testdata/repos/clean`: Benign repository with proper hygiene and no security exposures.
- `testdata/repos/dirty`: Repository containing mock credentials, secrets, and private keys for detection testing.
- `testdata/repos/hygiene`: Repository containing hygiene-only issues (e.g. missing documentation/license). Large-file fixtures (>50 MB) are generated dynamically at test runtime to avoid repository bloat.

> [!NOTE]
> All credentials, private keys, API tokens, and secrets within `testdata/` are **synthetic, dummy fixtures** created solely for automated security test verification. None of these files contain live credentials or sensitive material. Large test files (>1 MB / 50 MB) are generated dynamically during test execution via temporary directories and sparse filesystem operations rather than committed as stored repository fixtures.
