CARGO ?= cargo
RUSTUP ?= rustup

WASM_TARGET ?= wasm32-unknown-unknown
CORE_PACKAGE ?= zk-citadel
WALLET_PACKAGE ?= zk-citadel-wallet

BENCH_ARGS ?=
WALLET_ARGS ?=

.PHONY: help require-bls-backend contract test-contract test-core test-wallet bench run-wallet

help:
	@printf '%s\n' \
		'Available targets:' \
		'  make contract       Build release contract artifacts with BLST' \
		'  make test-contract  Build contract artifacts and run contract tests' \
		'  make test-core      Run release core tests with zk enabled' \
		'  make test-wallet    Run release wallet tests' \
		'  make bench          Run core benchmarks with zk enabled' \
		'  make run-wallet     Build and run the Citadel wallet with BLST' \
		'' \
		'Contract builds and wallet runs default to BLS_BACKEND=bls-backend-blst.' \
		'Tests and benchmarks always use bls-backend-blst.'

require-bls-backend:
	@if [ "$(BLS_BACKEND)" != "bls-backend-blst" ] && \
		[ "$(BLS_BACKEND)" != "bls-backend-dusk" ]; then \
		printf '%s\n' \
			'Set BLS_BACKEND to bls-backend-blst or bls-backend-dusk.'; \
		exit 2; \
	fi

contract: BLS_BACKEND ?= bls-backend-blst
contract: require-bls-backend
	$(CARGO) build -p license-contract --release --features $(BLS_BACKEND)
	$(RUSTUP) target add $(WASM_TARGET)
	$(CARGO) build --manifest-path contract/Cargo.toml --target $(WASM_TARGET) --release --features $(BLS_BACKEND)

test-contract:
	$(MAKE) contract BLS_BACKEND=bls-backend-blst
	$(CARGO) test --manifest-path contract/Cargo.toml --release --features bls-backend-blst --test license_contract

test-core:
	$(CARGO) test -p $(CORE_PACKAGE) --release --features zk,bls-backend-blst

test-wallet:
	$(CARGO) test -p $(WALLET_PACKAGE) --release --features bls-backend-blst

bench:
	$(CARGO) bench -p $(CORE_PACKAGE) --profile release --features zk,bls-backend-blst $(BENCH_ARGS)

run-wallet: BLS_BACKEND ?= bls-backend-blst
run-wallet: require-bls-backend
	$(CARGO) run -p $(WALLET_PACKAGE) --release --features $(BLS_BACKEND) -- $(WALLET_ARGS)
