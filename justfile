_default:
  @just --list --unsorted


# To create a development environment
dev:
  uv venv
  uv pip install -r admin/requirements-dev.txt
  uv run scripts/create-keys.py
