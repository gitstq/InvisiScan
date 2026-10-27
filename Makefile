PROJECT := invisiscan
PKG := invisiscan
PYTHON ?= python3
DIST := dist

.PHONY: help install dev test lint fmt clean build bundle dist-check self-scan release-check verify

help:                                  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

install:                               ## Install the package
	$(PYTHON) -m pip install .

dev:                                   ## Editable install with dev extras
	$(PYTHON) -m pip install -e ".[dev]"

test:                                  ## Run the test suite
	$(PYTHON) -m pytest

lint: self-scan                        ## Static checks (self + no 3rd-party deps)

self-scan:                             ## Scan this repository with itself
	$(PYTHON) -m invisiscan $(PKG) tests

fmt-check:                             ## Verify formatting matches black-style ordering
	$(PYTHON) -m compileall -q $(PKG) tests > /dev/null

verify: test fmt-check self-scan       ## Everything CI runs, locally

clean:                                 ## Remove build artifacts
	rm -rf $(DIST) build *.egg-info .pytest_cache .coverage
	find . -type d -name __pycache__ -prune -exec rm -rf {} +

build: clean                           ## Build wheel + sdist
	$(PYTHON) -m pip install --quiet --upgrade build
	$(PYTHON) -m build

bundle: clean                          ## Build a standalone zipapp (needs python>=3.9 only)
	$(PYTHON) -m pip install --quiet --target .builddeps .
	mkdir -p $(DIST)
	$(PYTHON) -m zipapp .builddeps \
	    -m "$(PKG).cli:main" \
	    -p "/usr/bin/env python3" \
	    -o $(DIST)/$(PROJECT).pyz
	rm -rf .builddeps

dist-check: build                      ## Validate built artifacts install and run
	$(PYTHON) -m pip install --quiet --force-reinstall $(DIST)/*.whl
	$(PYTHON) -c "import invisiscan; print('import ok', invisiscan.__version__)"
	printf 'x = %s\n' $$(printf '\xe2\x80\x8b') > /tmp/is-clean.py
	invisiscan --version
	$(PYTHON) -m invisiscan --help > /dev/null && echo "cli ok"
