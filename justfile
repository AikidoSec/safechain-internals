set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

export RUSTFLAGS := "-D warnings"
export RUSTDOCFLAGS := "-D rustdoc::broken-intra-doc-links"

rust-qa:
    cargo fmt
    @cargo install cargo-sort
    cargo sort --grouped
    cargo doc --all-features --workspace --no-deps
    cargo check --all-features --workspace --all-targets
    cargo clippy --all-features --workspace --all-targets
    @cargo install cargo-nextest --locked
    cargo nextest run --all-features --workspace
    just rust-fuzz-check

rust-test-ignored:
    @cargo install cargo-nextest --locked
    cargo nextest run --workspace --all-features --run-ignored=only

rust-fuzz-check:
    @cargo install cargo-fuzz
    cargo +nightly fuzz check --fuzz-dir ./proxy_fuzz

rust-fuzz *ARGS:
    @cargo install cargo-fuzz
    cargo +nightly fuzz run --fuzz-dir ./proxy_fuzz -j 8 parse_pragmatic_semver_version -- -max_total_time=60

rust-qa-full: rust-qa rust-test-ignored rust-fuzz

run-proxy *ARGS:
    mkdir -p .aikido/safechain-proxy
    RUST_LOG=info,safechain_proxy=debug \
    cargo run \
        --bin safechain-proxy \
        --features har \
        -- \
        --bind '127.0.0.1:8080' \
        --meta '127.0.0.1:8088' \
        --secrets .aikido/safechain-proxy \
        --pretty \
        {{ARGS}}

run-netbench-cli *ARGS:
    cargo run \
        --bin netbench \
        {{ARGS}}

run-netbench *ARGS:
    ./proxy_netbench/run.py {{ARGS}}

proxy-har-toggle:
    curl -v -XPOST http://127.0.0.1:8088/har/toggle

rust-update-deps:
    cargo upgrades
    cargo update

rust-detect-unused-deps:
    @cargo install cargo-machete
    cargo machete --skip-target-dir
