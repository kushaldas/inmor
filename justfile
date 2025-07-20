_default:
  @just --list --unsorted


venv_command := if path_exists(".venv") == "false" { "uv venv && uv pip install -r admin/requirements-dev.txt" } else { "" }

# To create the virtual environment for development
venv:
  {{ venv_command }}

# To create a development environment
dev: venv
  uv run scripts/create-keys.py

# To check for formatting and typing erors
lint: venv
  # The Python code is not packaged, so imports are currently
  # relative to the admin/ directory
  . .venv/bin/activate && \
  ty check . --extra-search-path=admin/ && \
  ruff format --check && \
  ruff check .
  cargo clippy
  cargo fmt --check

# To format the Rust and Python code
reformat: venv
  ruff format
  cargo fmt

# To remove the files of the dev environment
clean:
  rm -rf .venv
  rm -f public.json private.json admin/private.json
