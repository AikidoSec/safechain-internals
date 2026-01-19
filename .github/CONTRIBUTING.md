# Contributing to SafeChain Agent

Thank you for your interest in contributing to SafeChain Agent! This guide will help you get started with setting up your development environment, running tests, and building the project.

## Prerequisites

Before you begin, ensure you have the following installed:

- **Go**: Version 1.25 or higher. You can download it from [golang.org](https://golang.org/).
- **Rust**: Version 1.91 or higher. You can install it using [rustup](https://rustup.rs/).
- **Make**: Typically pre-installed on Unix-like systems, used for building.
- **Just**: You can install it via a package manager of choice: <https://just.systems/man/en/packages.html>

Requirements to build the (Rust) proxy:

- **CMake**: Required for certain builds and dependencies. You can install it via your package manager or download it from the [CMake website](https://cmake.org/download/).
- Unix-only dependencies:
  - **Clang**: Already installed on MacOS, for Linux you might still need to install it.
    - This is not used for Windows, there we use the default MVSC (2015) tooling
      which most likely is already installed on a developer machine.

These (Rust) proxy dependencies are used to compile and link `rama-boring`, a `boringssl` fork.

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

#### Proxy: dependency management

Update all dependencies (or get error in case there is a breaking update available):

```sh
just rust-update-deps
```

Detect unused dependencies (that can be removed from `Cargo.toml` manually):

```sh
just rust-detect-unused-deps
```
