set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

export RUSTFLAGS := "-D warnings"
export RUSTDOCFLAGS := "-D rustdoc::broken-intra-doc-links"

rust-qa:
    cargo fmt
    @cargo install cargo-sort
    cargo sort --grouped
    cargo check --workspace --all-targets
    cargo clippy --workspace --all-targets
    cargo test --workspace

rust-qa-full: rust-qa
    cargo test --workspace -- --ignored

run-proxy *ARGS:
    mkdir -p target/.safechain-proxy
    RUST_LOG=info,safechain_proxy=debug \
    cargo run -- \
        --bind '127.0.0.1:8080' \
        --meta '127.0.0.1:8088' \
        --secrets target/.safechain-proxy \
        {{ARGS}}

rust-update-deps:
    cargo upgrades
    cargo update

rust-detect-unused-deps:
    @cargo install cargo-machete
    cargo machete --skip-target-dir
