_default:
  @just --list --unsorted


# To create a development environment
dev:
  uv venv
  uv pip install -r admin/requirements-dev.txt
  ./scripts/create-keys.py
