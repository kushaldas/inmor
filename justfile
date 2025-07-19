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
  source .venv/bin/activate && \
  mypy . && \
  ruff check .

# To remove the files of the dev environment
clean:
  rm -rf .venv
  rm -f public.json private.json admin/private.json
