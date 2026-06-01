CARGO ?= cargo
RUSTUP ?= rustup

WASM_TARGET ?= wasm32-unknown-unknown
CORE_PACKAGE ?= zk-citadel
WALLET_PACKAGE ?= zk-citadel-wallet

BENCH_ARGS ?=
WALLET_ARGS ?=

.PHONY: help contract test-contract test-core test-wallet bench run-wallet

help:
	@printf '%s\n' \
		'Available targets:' \
		'  make contract       Build release contract artifacts and wasm' \
		'  make test-contract  Build contract artifacts and run contract tests' \
		'  make test-core      Run release core tests with zk enabled' \
		'  make test-wallet    Run release wallet tests' \
		'  make bench          Run core benchmarks with zk enabled' \
		'  make run-wallet     Build and run the Citadel wallet in release mode'

contract:
	$(CARGO) build --release --features zk
	$(RUSTUP) target add $(WASM_TARGET)
	$(CARGO) build --manifest-path contract/Cargo.toml --target $(WASM_TARGET) --release

test-contract: contract
	$(CARGO) test --manifest-path contract/Cargo.toml --release --test license_contract

test-core:
	$(CARGO) test -p $(CORE_PACKAGE) --release --features zk

test-wallet:
	$(CARGO) test -p $(WALLET_PACKAGE) --release

bench:
	$(CARGO) bench -p $(CORE_PACKAGE) --profile release --features zk $(BENCH_ARGS)

run-wallet:
	$(CARGO) run -p $(WALLET_PACKAGE) --release -- $(WALLET_ARGS)
