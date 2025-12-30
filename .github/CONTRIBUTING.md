# Contributing to SafeChain Agent

Thank you for your interest in contributing to SafeChain Agent! This guide will help you get started with setting up your development environment, running tests, and building the project.

## Prerequisites

Before you begin, ensure you have the following installed:

- **Go**: Version 1.25 or higher. You can download it from [golang.org](https://golang.org/).
- **Rust**: Version 1.91 or higher. You can install it using [rustup](https://rustup.rs/).
- **Make**: Typically pre-installed on Unix-like systems, used for building.
- **CMake**: Required for certain builds and dependencies. You can install it via your package manager or download it from the [CMake website](https://cmake.org/download/).

## Installing Dependencies


To install the dependencies, run:

```sh
go mod download # We currently don't have any go dependencies
cargo build # Download rust packages
```

## Running Tests

### Rust Tests
To run Rust tests, navigate to the `proxy` directory and run:

```sh
cd proxy
cargo test
```

This will run all the tests in the Rust packages.

## Building the Project

Using `make`:

```sh
make build
```

## Additional Commands

### Formatting Code

To format the Go code, run:

```sh
gofmt -w .
```

To format the Rust code, navigate to the `proxy` directory and run:

```sh
cd proxy
cargo fmt
```

### Linting Code

To lint the Rust code, navigate to the `proxy` directory and run:

```sh
cd proxy
cargo clippy
```
