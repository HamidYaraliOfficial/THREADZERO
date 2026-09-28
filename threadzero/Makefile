# THREADZERO — build and test entry points (Linux / macOS / WSL / MSYS2).  Windows users: see install.ps1
GHC      ?= ghc
PYTHON   ?= python3
CORE_DIR := haskell/build
CORE     := $(CORE_DIR)/threadzero-core

.PHONY: all install core web test test-haskell test-python test-web serve doctor clean golden cabal

all: install core web

install:                        ## Python dependencies + editable install
	$(PYTHON) -m pip install -r requirements.txt
	$(PYTHON) -m pip install -e .

core:                           ## Haskell core (only GHC boot libraries — no Hackage download needed)
	mkdir -p $(CORE_DIR)
	$(GHC) -O1 -ihaskell/src -ihaskell/app -outputdir $(CORE_DIR) -o $(CORE) haskell/app/Main.hs

cabal:                          ## alternative build through cabal
	cabal build exe:threadzero-core && cp "$$(cabal list-bin exe:threadzero-core)" $(CORE)

web:                            ## Web studio (static export served by `threadzero serve`)
	cd web && npm install && npm run build

test: test-haskell test-python  ## everything except the optional web smoke tests

test-haskell:                   ## property-based + parser + type-system + solver + graph + refactoring + fuzz tests
	mkdir -p $(CORE_DIR)/test
	$(GHC) -O0 -ihaskell/src -ihaskell/test -outputdir $(CORE_DIR)/test -o $(CORE_DIR)/spec haskell/test/Spec.hs
	$(CORE_DIR)/spec

test-python:                    ## compiler, WASM runtime, golden, security-ops, API and CLI tests
	$(PYTHON) -m pytest -q

test-web:                       ## renders all 20 views (EN/FA/ZH) against a live backend
	cd web && THREADZERO_HOME=$(CURDIR) $(PYTHON) -m threadzero serve --port 8799 & sleep 4; \
	cd web && NEXT_PUBLIC_API=http://127.0.0.1:8799 npm test; pkill -f "threadzero serve" || true

golden:                         ## regenerate golden artifacts after an intentional compiler change
	PYTHONPATH=python $(PYTHON) python/tests/update_golden.py

serve:                          ## API + web studio on http://127.0.0.1:8737
	$(PYTHON) -m threadzero serve

doctor:
	$(PYTHON) -m threadzero doctor

clean:
	rm -rf $(CORE_DIR) web/.next web/out .threadzero
