APP := env("FLOW_APP", "/Applications/Flow.app")

# Patch Flow.app → installs to ~/Applications/
patch:
    uv run flow-patcher patch {{ APP }}

# Remove the patched copy from ~/Applications/
restore:
    uv run flow-patcher restore {{ APP }}

# Run tests with coverage
test:
    uv run --group dev pytest tests/ -qq --cov=flow_patcher -m "not integration"

# Run integration tests (requires installed Flow.app)
test-integration:
    uv run --group dev pytest tests/ -qq -m integration

# Check app compatibility
probe *ARGS:
    uv run flow-patcher probe {{ APP }} {{ ARGS }}

# Lint with ruff
lint:
    uv run --group dev ruff check flow_patcher/ tests/
    uv run --group dev ruff format --check flow_patcher/ tests/

# Auto-fix lint issues and format
fix:
    uv run --group dev ruff check --fix flow_patcher/ tests/
    uv run --group dev ruff format flow_patcher/ tests/

# Type-check with mypy
typecheck:
    uv run --group dev mypy flow_patcher/

# Run all checks (lint + typecheck + test)
check: lint typecheck test
