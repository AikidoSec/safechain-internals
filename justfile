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

rust-qa-full: rust-qa
    cargo nextest run --workspace --all-features --run-ignored=only

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

proxy-har-toggle:
    curl -v -XPOST http://127.0.0.1:8088/har/toggle

rust-update-deps:
    cargo upgrades
    cargo update

rust-detect-unused-deps:
    @cargo install cargo-machete
    cargo machete --skip-target-dir
