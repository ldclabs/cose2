.PHONY: lint fix test

lint:
	@cargo fmt --all --check
	@cargo clippy --workspace --all-targets --all-features -- -D warnings

fix:
	@cargo clippy --fix --workspace --all-targets --all-features
	@cargo fmt --all

test:
	@cargo test --workspace --all-targets --all-features -- --nocapture
	@cargo test --workspace --doc --all-features -- --nocapture
	@python3 -m unittest discover -s scripts -p 'test_*.py'
