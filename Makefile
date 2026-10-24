# sbomlens — every gate in one place. `make check` is what CI runs.
CARGO ?= cargo
COVERAGE_MIN ?= 80

.PHONY: check fmt fmt-check lint test coverage verify-data demo bench eval data clean

check: fmt-check lint test coverage verify-data ## format + lint + tests + coverage gate + data checksums
	@echo "make check: all gates passed"

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

lint:
	$(CARGO) clippy --all-targets --locked -- -D warnings

test:
	$(CARGO) test --locked

# Line coverage of the library (src/main.rs is a thin wrapper and excluded).
coverage:
	$(CARGO) llvm-cov --locked --ignore-filename-regex 'src/main\.rs' --fail-under-lines $(COVERAGE_MIN) --summary-only

verify-data:
	python3 scripts/verify-osv-manifest.py

demo:
	./scripts/demo.sh

bench:
	$(CARGO) bench --locked --bench matching

eval:
	$(CARGO) run --locked --release --example agreement
	$(CARGO) run --locked --release --example agreement -- --ranges-only
	$(CARGO) run --locked --release --example version_sweep

# Network required: regenerate real SBOM fixtures and the pinned OSV subset.
data:
	./scripts/gen-real-sboms.sh
	python3 scripts/fetch-osv-subset.py

clean:
	$(CARGO) clean
	rm -rf out
