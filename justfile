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

# Building rust binary to be able to be mounted
# inside other linux containers.
build-rs:
  docker run --rm -it \
  -v "$(pwd)":/code \
  -w /code \
  rust:1.88 \
  cargo build

build:
  docker compose build ta
  docker compose build admin

rebuild-ta:
  @cargo build
  docker compose restart ta

up:
  docker compose up -d

down:
  docker compose down

debug-ta:
  docker compose run --rm ta /bin/bash

debug-admin:
  docker compose run --rm admin /bin/bash

# To remove the files of the dev environment
clean:
  rm -rf .venv
  rm -f public.json private.json admin/private.json
