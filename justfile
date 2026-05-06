set windows-shell := ["powershell.exe", "-NoLogo", "-ExecutionPolicy", "Bypass", "-Command"]

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
l4_dev_host_bundle_id := "com.aikido.endpoint.proxy.l4.dev"
l4_dev_extension_bundle_id := "com.aikido.endpoint.proxy.l4.dev.extension"
l4_dist_host_bundle_id := "com.aikido.endpoint.proxy.l4.dist"
l4_dist_extension_bundle_id := "com.aikido.endpoint.proxy.l4.dist.extension"
xcode_l4_project_dir := "packaging/macos/xcode/l4-proxy"
xcode_l4_project_spec_dev := xcode_l4_project_dir + "/Project.dev.yml"
xcode_l4_project_file := xcode_l4_project_dir + "/AikidoNetworkExtension.xcodeproj"
xcode_l4_host_scheme := "AikidoNetworkExtensionHost"
xcode_l4_derived_data := ".aikido/xcode/safechain-l4-proxy-wrapper"
xcode_l4_app_name := "Aikido Network Extension.app"
xcode_l4_app := xcode_l4_derived_data + "/Build/Products/Debug/" + xcode_l4_app_name
xcode_l4_app_exe := xcode_l4_app + "/Contents/MacOS/Aikido Network Extension"
xcode_l4_installed_app := "/Applications/" + xcode_l4_app_name
xcode_l4_installed_app_exe := xcode_l4_installed_app + "/Contents/MacOS/Aikido Network Extension"
xcode_l4_installed_sysext := xcode_l4_installed_app + "/Contents/Library/SystemExtensions/" + l4_dev_extension_bundle_id + ".systemextension"

rust-quick-qa:
    @just _rust-quick-qa-{{ os() }}

_rust-quick-qa-windows: rust-quick-qa-crossplatform windows-driver-quick-qa

_rust-quick-qa-linux: rust-quick-qa-crossplatform

_rust-quick-qa-macos: rust-quick-qa-crossplatform

rust-fmt:
    cargo fmt
    @cargo install cargo-sort
    cargo sort --grouped --workspace

rust-quick-qa-crossplatform:
    cargo fmt --all --check
    @cargo install cargo-sort
    cargo sort --workspace --grouped --check
    cargo doc --all-features --workspace --no-deps \
        --exclude safechain-lib-l4-proxy-windows-driver \
        --exclude safechain-l4-proxy-windows-driver-object
    cargo check --all-features --workspace --all-targets \
        --exclude safechain-lib-l4-proxy-windows-driver \
        --exclude safechain-l4-proxy-windows-driver-object
    cargo clippy \
        --all-features --workspace --all-targets \
        --exclude safechain-lib-l4-proxy-windows-driver \
        --exclude safechain-l4-proxy-windows-driver-object \
        -- -D warnings

rust-test *ARGS:
    cargo test --all-features --workspace \
        --exclude safechain-lib-l4-proxy-windows-driver \
        --exclude safechain-l4-proxy-windows-driver-object \
        {{ARGS}}

rust-qa: rust-quick-qa rust-test rust-fuzz-check
    @just _rust-qa-{{ os() }}

_rust-qa-windows: windows-driver-build
    cargo test --all-features \
        -p safechain-l4-proxy-windows-driver-object

_rust-qa-linux:

_rust-qa-macos:

rust-fuzz-check:
    @just _rust-fuzz-check-{{os_family()}}

_rust-fuzz-check-unix $CARGO_PROFILE_RELEASE_LTO="false":
    @cargo install cargo-fuzz
    cargo +nightly fuzz check --fuzz-dir ./proxy-fuzz

_rust-fuzz-check-windows:

rust-fuzz:
    @just _rust-fuzz-{{os_family()}}

_rust-fuzz-unix $CARGO_PROFILE_RELEASE_LTO="false" *ARGS:
    @cargo install cargo-fuzz
    cargo +nightly fuzz run --fuzz-dir ./proxy-fuzz -j 8 parse_pragmatic_semver_version -- -max_total_time=60

_rust-fuzz-windows:

rust-qa-full: rust-qa
    cargo test --all-features --workspace \
        --exclude safechain-lib-l4-proxy-windows-driver \
        --exclude safechain-l4-proxy-windows-driver-object \
        -- --ignored

run-l4-proxy $RUST_LOG="debug" *ARGS:
    cargo run \
        --bin safechain-l4-proxy \
        -- \
        --bind-ipv4 '127.0.0.1:0' \
        --bind-ipv6 '[::1]:0' \
        --secrets .aikido/safechain-l4-proxy \
        --output .aikido/safechain-l4-proxy.log \
        {{ARGS}}

run-l7-proxy $RUST_LOG="info,safechain_l4_proxy=debug,safechain_proxy_lib=debug" *ARGS:
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

clean-rust:
    cargo clean

clean-xcode:
    rm -rf .aikido/xcode 2> /dev/null

clean-packaging:
    rm -rf bin 2> /dev/null
    rm -rf dist 2> /dev/null

clean: clean-rust clean-xcode clean-packaging

rust-update-deps:
    @cargo install cargo-edit
    cargo upgrade
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
        -allowProvisioningDeviceRegistration \
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
    xcodegen generate --spec "{{xcode_l4_project_spec_dev}}"

macos-l4-xcodegen-build-debug-signed: macos-l4-build-rust macos-l4-xcodegen-generate
    xcodebuild \
        -project "{{xcode_l4_project_file}}" \
        -scheme "{{xcode_l4_host_scheme}}" \
        -configuration Debug \
        -derivedDataPath "{{xcode_l4_derived_data}}" \
        -allowProvisioningUpdates \
        -allowProvisioningDeviceRegistration \
        clean \
        build

macos-l4-install-signed: macos-l4-xcodegen-build-debug-signed
    rm -rf "{{xcode_l4_installed_app}}"
    ditto "{{xcode_l4_app}}" "{{xcode_l4_installed_app}}"
    /System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -u "{{xcode_l4_app}}" || true
    /System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f "{{xcode_l4_installed_app}}"
    echo "Installed Development system extension bundle at {{xcode_l4_installed_sysext}}"

macos-l4-status:
    "{{xcode_l4_installed_app_exe}}" status

macos-l4-log-stream:
    log stream --style compact --level debug \
        --predicate 'subsystem == "com.aikido.endpoint.proxy.l4" \
        OR process == "com.aikido.endpoint.proxy.l4.dev.extension" \
        OR process == "Aikido Network Extension"'

macos-l4-start *ARGS:
    "{{xcode_l4_installed_app_exe}}" start {{ARGS}}
    @for i in $(seq 1 120); do \
        status="$("{{xcode_l4_installed_app_exe}}" status | sed -n 's/^status: //p')"; \
        echo "$i) status: $status"; \
        case "$status" in \
            connected) \
                echo "Dev proxy enabled, have fun!"; \
                exit 0; \
                ;; \
        esac; \
        sleep 0.5; \
    done; \
    echo "timed out waiting for macOS L4 proxy to become active" >&2; \
    "{{xcode_l4_installed_app_exe}}" status; \
    exit 1

macos-l4-stop:
    "{{xcode_l4_installed_app_exe}}" stop
    @for i in $(seq 1 120); do \
        status="$("{{xcode_l4_installed_app_exe}}" status | sed -n 's/^status: //p')"; \
        echo "$i) status: $status"; \
        case "$status" in \
            disconnected) \
                echo "Dev proxy disabled, bye!"; \
                exit 0; \
                ;; \
        esac; \
        sleep 0.5; \
    done; \
    echo "timed out waiting for macOS L4 proxy to stop" >&2; \
    "{{xcode_l4_installed_app_exe}}" status; \
    exit 1

run-macos-l4-proxy *ARGS: macos-l4-install-signed
    just macos-l4-start {{ARGS}}

windows-driver-quick-qa: windows-driver-check windows-driver-clippy windows-driver-test
    cargo doc --all-features --no-deps \
        -p safechain-l4-proxy-windows-driver-object
    cargo check --all-features --all-targets \
        -p safechain-l4-proxy-windows-driver-object
    cargo clippy --all-features --all-targets \
        -p safechain-l4-proxy-windows-driver-object \
        -- -D warnings

windows-driver-qa: windows-driver-quick-qa windows-driver-build
    cargo test --all-features \
        -p safechain-l4-proxy-windows-driver-object

windows-driver-package-stage profile="debug" *ARGS:
    ./packaging/windows/stage-driver-package.ps1 -Profile {{profile}} {{ARGS}}

windows-driver-package-install package_dir="dist/windows-driver-package/debug":
    ./packaging/windows/install-driver-package.ps1 -PackageDir {{package_dir}}

windows-driver-package-install-fresh-debug:
    just rust-quick-qa
    just windows-driver-test
    just windows-driver-disable
    just windows-driver-package-remove
    just windows-driver-build
    just windows-driver-package-stage
    just windows-driver-package-install
    @Write-Host ""
    @Write-Host "Reboot Windows to activate the new driver package." -ForegroundColor Yellow
    @Write-Host "After reboot, start safechain-l4-proxy; it will automatically synchronize its IPv4/IPv6 listener addresses into the Windows driver runtime config." -ForegroundColor Yellow

windows-driver-package-verify *ARGS:
    ./packaging/windows/verify-driver-install.ps1 {{ARGS}}

windows-driver-package-remove:
    ./packaging/windows/remove-driver-package.ps1

windows-install-root-crt *ARGS:
    ./packaging/windows/install-root-crt.ps1 {{ARGS}}

[working-directory: './proxy-lib-l4-windows-driver']
windows-driver-check:
    cargo check

[working-directory: './proxy-lib-l4-windows-driver']
windows-driver-clippy:
    cargo clippy \
        -- -D warnings

[working-directory: './proxy-lib-l4-windows-driver']
windows-driver-test *ARGS:
    cargo test {{ARGS}}

[working-directory: './proxy-lib-l4-windows-driver']
windows-driver-build profile="dev" target_arch="amd64" *ARGS:
   @cargo install cargo-wdk
   @cargo install cargo-make
   $env:STAMPINF_VERSION=((Get-Content '..\Cargo.toml' | Select-String '^version = "([^"]+)"').Matches[0].Groups[1].Value + '.0'); cargo wdk build --profile {{profile}} --target-arch {{target_arch}} {{ARGS}}

[working-directory: './proxy-lib-l4-windows-driver']
windows-driver-build-verify profile="dev" target_arch="amd64" *ARGS:
    just windows-driver-build {{profile}} {{target_arch}} --verify-signature {{ARGS}}

run-windows-driver-cli *ARGS:
    cargo run \
        --bin safechain-l4-proxy-windows-driver-object \
        -- \
        {{ARGS}}

windows-driver-enable IPV4_PROXY *ARGS:
    just run-windows-driver-cli enable \
        --ipv4-proxy {{IPV4_PROXY}} \
        --ipv4-proxy-pid "$(& ./packaging/windows/resolve-proxy-pid.ps1 -BindAddress '{{IPV4_PROXY}}')" \
        {{ARGS}}

windows-driver-enable-dual-stack IPV4_PROXY IPV6_PROXY *ARGS:
    just run-windows-driver-cli enable \
        --ipv4-proxy {{IPV4_PROXY}} \
        --ipv4-proxy-pid "$(& ./packaging/windows/resolve-proxy-pid.ps1 -BindAddress '{{IPV4_PROXY}}')" \
        --ipv6-proxy {{IPV6_PROXY}} \
        --ipv6-proxy-pid "$(& ./packaging/windows/resolve-proxy-pid.ps1 -BindAddress '{{IPV6_PROXY}}')" \
        {{ARGS}}

windows-driver-disable *ARGS:
    just run-windows-driver-cli disable \
        --force-remove-on-veto \
        {{ARGS}}

windows-driver-update-ipv4 IPV4_PROXY *ARGS:
    just run-windows-driver-cli update \
        --ipv4-proxy {{IPV4_PROXY}} \
        --ipv4-proxy-pid "$(& ./packaging/windows/resolve-proxy-pid.ps1 -BindAddress '{{IPV4_PROXY}}')" \
        {{ARGS}}

windows-driver-update-ipv6 IPV6_PROXY *ARGS:
    just run-windows-driver-cli update \
        --ipv6-proxy {{IPV6_PROXY}} \
        --ipv6-proxy-pid "$(& ./packaging/windows/resolve-proxy-pid.ps1 -BindAddress '{{IPV6_PROXY}}')" \
        {{ARGS}}

windows-driver-update-dual-stack IPV4_PROXY IPV6_PROXY *ARGS:
    just run-windows-driver-cli update \
        --ipv4-proxy {{IPV4_PROXY}} \
        --ipv4-proxy-pid "$(& ./packaging/windows/resolve-proxy-pid.ps1 -BindAddress '{{IPV4_PROXY}}')" \
        --ipv6-proxy {{IPV6_PROXY}} \
        --ipv6-proxy-pid "$(& ./packaging/windows/resolve-proxy-pid.ps1 -BindAddress '{{IPV6_PROXY}}')" \
        {{ARGS}}

windows-driver-enable-dev *ARGS:
    just windows-driver-enable-dual-stack \
        "$([System.IO.File]::ReadAllText('.aikido/safechain-l4-proxy/l4_proxy.addr.v4.txt').Trim())" \
        "$([System.IO.File]::ReadAllText('.aikido/safechain-l4-proxy/l4_proxy.addr.v6.txt').Trim())" \
        {{ARGS}}

windows-driver-update-dev *ARGS:
    just windows-driver-update-dual-stack \
        "$([System.IO.File]::ReadAllText('.aikido/safechain-l4-proxy/l4_proxy.addr.v4.txt').Trim())" \
        "$([System.IO.File]::ReadAllText('.aikido/safechain-l4-proxy/l4_proxy.addr.v6.txt').Trim())" \
        {{ARGS}}

windows-driver-clear-ipv6 *ARGS:
    just run-windows-driver-cli update \
        --clear-ipv6 \
        {{ARGS}}
