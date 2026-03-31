# Contributing to Aikido Endpoint Protection

Thank you for your interest in contributing to Aikido Endpoint Protection! This guide will help you get started with setting up your development environment, running tests, and building the project.

## Prerequisites

Before you begin, ensure you have the following installed:

- **Go**: Version 1.25 or higher. You can download it from [golang.org](https://golang.org/).
- **Rust**: Version 1.93 or higher. You can install it using [rustup](https://rustup.rs/).
- **Make**: Typically pre-installed on Unix-like systems, used for building.
- **Just**: You can install it via a package manager of choice: <https://just.systems/man/en/packages.html>

Requirements to build the (Rust) proxy:

- **CMake**: Required for certain builds and dependencies. You can install it via your package manager or download it from the [CMake website](https://cmake.org/download/).
- Unix-only dependencies:
  - **Clang**: Already installed on MacOS, for Linux you might still need to install it.
    - This is not used for Windows, there we use the default MVSC (2015) tooling
      which most likely is already installed on a developer machine.

These (Rust) proxy dependencies are used to compile
rust dependencies which have C/C++ bindings.

## Instructions

The rest of the instructions are split in Agent vs Proxy for now,
as these are two different projects within the same monorepo.

### Instructions: Agent

The agent is written in Go.

#### Agent: build

Using `make`:

```sh
make build
```

The resulting binaries are available in `bin/`.

#### Agent: format Code

To format the Go code, run:

```sh
gofmt -w .
```

### Instructions: Proxy

The proxy is written in Rust.

Learn more about the Proxy, what it is and how to use it,
in the Proxy README: [../docs/proxy.md](../docs/proxy.md).

With `just` you can use a single command: format code,
sort `Cargo.toml` dependencies, lint (`clippy`), check code can compile
and run all tests as follows:

```sh
just rust-qa
```

It's recommended to run the `rust-qa` target locally prior to comitting to GitHub,
as it will catch 99% of the reasons why your CI might fail otherwise.

If you also wish to _also_ run the ignored tests (which include slower tests,
or tests which on platforms such as MacOS might require you to unlock keychain):

```sh
just rust-qa-full
```

These ignored tests are on top of all other `rust-qa` checks all run
in the GitHub CI as well.

#### Proxy: run

Using `just`:

```sh
just run-proxy
```

You can use the same `justfile` to also toggle the [HAR](https://en.wikipedia.org/wiki/HAR_(file_format))
recording on and off:

```sh
just proxy-har-toggle
```

### Instructions: UI

The desktop tray application is built with [Wails v3](https://v3.wails.io/) (Go + React/TypeScript). See [`ui/README.md`](../ui/README.md) for architecture details and full setup instructions.

**Extra prerequisites:** [Wails v3 CLI](https://v3.wails.io/getting-started/installation/), Node.js, [Task](https://taskfile.dev/)

```sh
brew install go-task
go install github.com/wailsapp/wails/v3/cmd/wails3@latest
```

#### UI: development

```sh
cd ui
task dev
```

This generates Wails bindings, builds the frontend, and starts the app with hot-reload.

To develop without running the full agent stack, start the mock daemon first:

```sh
task mock   # serves seed data on :7878
# then in another terminal:
task dev
```

> **Note:** The frontend cannot be run standalone with `npm run dev` — the Vite config depends on Wails-generated bindings. Always use `task dev` for development.

#### UI: build

```sh
cd ui
task build       # compile binary
task package     # platform-specific distributable (.app, .exe)
```

## Local testing against a non-production backend

To point the agent and proxy at a local or staging backend instead of `https://app.aikido.dev`, add a `base_url` field to the config file 
and restart the service. Also update the `token` field — the token can be found on the **Endpoint Protection** page of the webapp.

**macOS** — config file: `/Library/Application Support/AikidoSecurity/EndpointProtection/run/config.json`

```json
{
  "token": "<new token>",
  "device_id": "...",
  "base_url": "http://app.local.aikido.io"
}
```

Restart the service:

```sh
sudo launchctl bootout system/com.aikidosecurity.endpointprotection
sudo launchctl bootstrap system /Library/LaunchDaemons/com.aikidosecurity.endpointprotection.plist
```

**Windows** — config file: `%ProgramData%\AikidoSecurity\EndpointProtection\run\config.json`

Restart the service:

```sh
sc stop EndpointProtection
sc start EndpointProtection
```

Remove the `base_url` field (or leave it empty) and restore the production `token` to revert to the production backend.

#### Proxy: dependency management

Update all dependencies (or get error in case there is a breaking update available):

```sh
just rust-update-deps
```

Detect unused dependencies (that can be removed from `Cargo.toml` manually):

```sh
just rust-detect-unused-deps
```
