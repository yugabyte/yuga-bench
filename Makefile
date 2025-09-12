RELEASE_VER := 1.0.0
BASE_DIR    := $(shell git rev-parse --show-toplevel)
GIT_SHA     := $(shell git rev-parse --short HEAD)
VERSION     := $(RELEASE_VER)-$(GIT_SHA)
PYTHON 		:= python3

all: run

run:
	$(PYTHON) yuga_bench.py --host localhost --port 5433 --user yugabyte --output-format html

pipenv-lock:
	pipenv lock 

dev-install:
	pipenv install --dev --verbose

pre-commit-hook: dev-install
	pipenv run pre-commit install

format:
	pipenv run autopep8  --in-place --recursive core/ sections/ reports/ yuga_bench.py

lint:
	pipenv run flake8 core/ sections/ reports/ yuga_bench.py

sort-imports:
	pipenv run isort core/ sections/ reports/ yuga_bench.py --gitignore

commit-check: sort-imports format lint

run-pre-commit: dev-install pre-commit-hook
	pipenv run pre-commit run --all-files

