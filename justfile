set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

export RUSTFLAGS := "-D warnings"
export RUSTDOCFLAGS := "-D rustdoc::broken-intra-doc-links"

l7_team_id := "7VPF8GD6J4"
l7_bundle_id := "com.aikido.endpoint.proxy.l7"
l7_access_group := l7_team_id + "." + l7_bundle_id
xcode_l7_project_dir := "packaging/macos/xcode/l7-proxy"
xcode_l7_project_file := xcode_l7_project_dir + "/AikidoEndpointL7Proxy.xcodeproj"
xcode_l7_scheme := "AikidoEndpointL7Proxy"
xcode_l7_derived_data := ".aikido/xcode/safechain-l7-proxy-wrapper"
xcode_l7_app_exe := xcode_l7_derived_data + "/Build/Products/Debug/" + xcode_l7_scheme + ".app/Contents/MacOS/safechain-l7-proxy-bin"

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

rust-fuzz-check:
    @cargo install cargo-fuzz
    CARGO_PROFILE_RELEASE_LTO=false \
        cargo +nightly fuzz check --fuzz-dir ./proxy-fuzz

rust-fuzz *ARGS:
    @cargo install cargo-fuzz
    CARGO_PROFILE_RELEASE_LTO=false \
        cargo +nightly fuzz run --fuzz-dir ./proxy-fuzz -j 8 parse_pragmatic_semver_version -- -max_total_time=60

rust-qa-full: rust-qa rust-fuzz
    cargo nextest run --workspace --all-features --run-ignored=only

run-l4-proxy *ARGS:
    mkdir -p .aikido/safechain-l4-proxy
    RUST_LOG=info,endpoint_protection_l4_proxy=debug,endpoint_protection_proxy_lib=debug \
    cargo run \
        --bin safechain-l4-proxy \
        --features har \
        -- \
        --secrets .aikido/safechain-l4-proxy \
        {{ARGS}}

run-l7-proxy *ARGS:
    mkdir -p .aikido/safechain-l7-proxy
    RUST_LOG=info,endpoint_protection_l7_proxy=debug,endpoint_protection_proxy_lib=debug \
    cargo run \
        --bin safechain-l7-proxy \
        --features har \
        -- \
        --bind '127.0.0.1:8080' \
        --meta '127.0.0.1:8088' \
        --secrets .aikido/safechain-l7-proxy \
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

macos-l7-xcodegen-generate:
    xcodegen generate --spec "{{xcode_l7_project_dir}}/project.yml"

macos-l7-xcodegen-build-debug: macos-l7-xcodegen-generate
    xcodebuild \
        -project "{{xcode_l7_project_file}}" \
        -scheme "{{xcode_l7_scheme}}" \
        -configuration Debug \
        -derivedDataPath "{{xcode_l7_derived_data}}" \
        -allowProvisioningUpdates \
        build

macos-l7-xcode-verify-signing: macos-l7-xcodegen-build-debug
    @codesign -dvv "{{xcode_l7_app_exe}}" 2>&1 | rg "Identifier=|TeamIdentifier="
    @codesign -dv --verbose=4 "{{xcode_l7_derived_data}}/Build/Products/Debug/{{xcode_l7_scheme}}.app/Contents/MacOS/safechain-l7-proxy-bin" 2>&1 | rg "Identifier=|TeamIdentifier="

run-macos-l7-proxy-protected-xcode *ARGS: macos-l7-xcode-verify-signing
    "{{xcode_l7_app_exe}}" \
        --bind '127.0.0.1:8080' \
        --meta '127.0.0.1:8088' \
        --secrets "protected:access-group={{l7_access_group}}" \
        --pretty \
        {{ARGS}}
