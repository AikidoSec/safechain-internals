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
l4_team_id := "7VPF8GD6J4"
l4_host_bundle_id := "com.aikido.endpoint.proxy.l4"
xcode_l4_project_dir := "packaging/macos/xcode/l4-proxy"
xcode_l4_project_file := xcode_l4_project_dir + "/AikidoEndpointL4Proxy.xcodeproj"
xcode_l4_host_scheme := "AikidoEndpointL4ProxyHost"
xcode_l4_derived_data := ".aikido/xcode/safechain-l4-proxy-wrapper"
xcode_l4_app_name := "AikidoEndpointL4ProxyHost.app"
xcode_l4_app := xcode_l4_derived_data + "/Build/Products/Debug/" + xcode_l4_app_name
xcode_l4_app_exe := xcode_l4_app + "/Contents/MacOS/AikidoEndpointL4ProxyHost"
xcode_l4_installed_app := "/Applications/" + xcode_l4_app_name
xcode_l4_installed_app_exe := xcode_l4_installed_app + "/Contents/MacOS/AikidoEndpointL4ProxyHost"
xcode_l4_installed_appex := xcode_l4_installed_app + "/Contents/PlugIns/AikidoEndpointL4ProxyExtension.appex"

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
    RUST_LOG=info,safechain_l4_proxy=debug,safechain_proxy_lib=debug \
    cargo run \
        --bin safechain-l4-proxy \
        --features har \
        -- \
        --secrets .aikido/safechain-l4-proxy \
        {{ARGS}}

run-l7-proxy *ARGS:
    mkdir -p .aikido/safechain-l7-proxy
    RUST_LOG=info,safechain_l7_proxy=debug,safechain_proxy_lib=debug \
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

macos-l4-build-rust:
    MACOSX_DEPLOYMENT_TARGET=13.0 \
    CMAKE_OSX_DEPLOYMENT_TARGET=13.0 \
    CFLAGS_aarch64_apple_darwin="-mmacosx-version-min=13.0" \
    CXXFLAGS_aarch64_apple_darwin="-mmacosx-version-min=13.0" \
    cargo build --target aarch64-apple-darwin -p safechain-lib-l4-proxy-macos
    MACOSX_DEPLOYMENT_TARGET=13.0 \
    CMAKE_OSX_DEPLOYMENT_TARGET=13.0 \
    CFLAGS_x86_64_apple_darwin="-mmacosx-version-min=13.0" \
    CXXFLAGS_x86_64_apple_darwin="-mmacosx-version-min=13.0" \
    cargo build --target x86_64-apple-darwin -p safechain-lib-l4-proxy-macos
    mkdir -p target/universal
    lipo -create \
        -output target/universal/libsafechain_lib_l4_proxy_macos.a \
        target/aarch64-apple-darwin/debug/libsafechain_lib_l4_proxy_macos.a \
        target/x86_64-apple-darwin/debug/libsafechain_lib_l4_proxy_macos.a

macos-l4-xcodegen-generate:
    xcodegen generate --spec "{{xcode_l4_project_dir}}/Project.yml"

macos-l4-xcodegen-build-debug: macos-l4-build-rust macos-l4-xcodegen-generate
    xcodebuild \
        -project "{{xcode_l4_project_file}}" \
        -scheme "{{xcode_l4_host_scheme}}" \
        -configuration Debug \
        -derivedDataPath "{{xcode_l4_derived_data}}" \
        CODE_SIGNING_ALLOWED=NO \
        CODE_SIGNING_REQUIRED=NO \
        CODE_SIGN_IDENTITY="" \
        build

macos-l4-xcodegen-build-debug-signed: macos-l4-build-rust macos-l4-xcodegen-generate
    xcodebuild \
        -project "{{xcode_l4_project_file}}" \
        -scheme "{{xcode_l4_host_scheme}}" \
        -configuration Debug \
        -derivedDataPath "{{xcode_l4_derived_data}}" \
        -allowProvisioningUpdates \
        clean \
        build

macos-l4-install-signed: macos-l4-xcodegen-build-debug-signed
    pkill -f "{{l4_host_bundle_id}}" || true
    sleep 1
    rm -rf "{{xcode_l4_installed_app}}"
    ditto "{{xcode_l4_app}}" "{{xcode_l4_installed_app}}"
    /System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f "{{xcode_l4_installed_app}}"
    pluginkit -a "{{xcode_l4_installed_appex}}" || true

macos-l4-status:
    "{{xcode_l4_installed_app_exe}}" status

macos-l4-log-stream:
    log stream --style compact --level debug \
        --predicate 'subsystem == "com.aikido.endpoint.proxy.l4" \
        OR process == "AikidoEndpointL4ProxyExtension" \
        OR process == "AikidoEndpointL4ProxyHost"'

macos-l4-start *ARGS:
    "{{xcode_l4_installed_app_exe}}" start {{ARGS}}

macos-l4-stop:
    "{{xcode_l4_installed_app_exe}}" stop

run-macos-l4-proxy *ARGS: macos-l4-install-signed
    just macos-l4-start {{ARGS}}
