CARGO ?= cargo
RUSTUP ?= rustup

WASM_TARGET ?= wasm32-unknown-unknown
CORE_PACKAGE ?= zk-citadel
WALLET_PACKAGE ?= zk-citadel-wallet

BENCH_ARGS ?=
WALLET_ARGS ?=
BLS_BACKEND ?= bls-backend-blst
override TEST_BLS_BACKEND := bls-backend-blst

.PHONY: help contract test-contract test-core test-wallet bench run-wallet

help:
	@printf '%s\n' \
		'Available targets:' \
		'  make contract       Build release contract artifacts and wasm' \
		'  make test-contract  Build contract artifacts and run contract tests' \
		'  make test-core      Run release core tests with zk enabled' \
		'  make test-wallet    Run release wallet tests' \
		'  make bench          Run core benchmarks with zk enabled' \
		'  make run-wallet     Build and run the Citadel wallet in release mode' \
		'' \
		'Build and run targets default to BLS_BACKEND=bls-backend-blst.' \
		'Tests and benchmarks always use bls-backend-blst.'

contract:
	$(CARGO) build -p license-contract --release --no-default-features --features contract,$(BLS_BACKEND)
	$(RUSTUP) target add $(WASM_TARGET)
	$(CARGO) build --manifest-path contract/Cargo.toml --target $(WASM_TARGET) --release --no-default-features --features contract,$(BLS_BACKEND)

test-contract:
	$(MAKE) contract BLS_BACKEND=$(TEST_BLS_BACKEND)
	$(CARGO) test --manifest-path contract/Cargo.toml --release --no-default-features --features contract,$(TEST_BLS_BACKEND) --test license_contract

test-core:
	$(CARGO) test -p $(CORE_PACKAGE) --release --no-default-features --features rkyv-impl,std,zk,$(TEST_BLS_BACKEND)

test-wallet:
	$(CARGO) test -p $(WALLET_PACKAGE) --release --no-default-features --features $(TEST_BLS_BACKEND)

bench:
	$(CARGO) bench -p $(CORE_PACKAGE) --profile release --no-default-features --features rkyv-impl,std,zk,$(TEST_BLS_BACKEND) $(BENCH_ARGS)

run-wallet:
	$(CARGO) run -p $(WALLET_PACKAGE) --release --no-default-features --features $(BLS_BACKEND) -- $(WALLET_ARGS)
