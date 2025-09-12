DOCKER_HUB_REPO?=yugabytedb
DOCKER_HUB_REGISTRY_IMAGE?=yugabyte-bench
DOCKER_HUB_REGISTRY_TAG?=latest

YUGA_BENCH_REGISTRY_IMG=$(DOCKER_HUB_REPO)/$(DOCKER_HUB_REGISTRY_IMAGE):$(DOCKER_HUB_REGISTRY_TAG)

RELEASE_VER := v1.0.0
BASE_DIR    := $(shell git rev-parse --show-toplevel)
GIT_SHA     := $(shell git rev-parse --short HEAD)
VERSION     := $(RELEASE_VER)-$(GIT_SHA)

ifneq ($(NO_CACHE),)
DOCKER_NO_CACHE = --no-cache
endif

export DOCKER_BUILDKIT?=1

all: image-build

image-build:
	@echo "Building container: docker build --progress=plain --tag $(YUGA_BENCH_REGISTRY_IMG) -f Dockerfile ."
	docker build --progress=plain --tag $(YUGA_BENCH_REGISTRY_IMG) --build-arg build_version=$(VERSION) --build-arg DOCKER_HUB_IMAGE_TAG=$(DOCKER_HUB_REGISTRY_TAG) -f Dockerfile .
	@echo "Build successfully completed"
	docker rm $(DOCKER_HUB_REGISTRY_IMAGE)-pipenv; \

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

push-image: image-build
	docker push $(YUGA_BENCH_REGISTRY_IMG)
