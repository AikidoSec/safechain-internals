# Aikido Endpoint Protection UI

Desktop tray application for Aikido Endpoint Protection. Built with [Wails v3](https://v3.wails.io/) (Go backend + web frontend).

The app runs as a **system-tray icon** (no dock icon). It receives proxy-status updates and blocked-event notifications from the Endpoint Protection daemon, displays them in a dashboard window, and pushes native OS notifications.

## Architecture

```
┌──────────┐  POST /v1/proxy-status  ┌───────────┐
│  Daemon  │  POST /v1/blocked       │  UI App   │
│          │ ──────────────────────► |(appserver)│
│          │ ◄────────────────────── │           │
│          │  GET  /v1/events        │ (daemon   │
│          │  POST /v1/events/:id/   │  client)  │
│          │       request-access    └───────────┘
└──────────┘
```

| Package | Purpose |
|---------|---------|
| `main` | Entry point, CLI flags, Wails app, window management, system tray, notifications |
| `appserver` | HTTP server that receives status and block callbacks from the daemon |
| `daemon` | HTTP client for the daemon API (`ListEvents`, `GetEvent`, `RequestAccess`) |
| `frontend/` | Web frontend (Vite + TypeScript) embedded into the binary |

## Prerequisites

- Go 1.25+
- [Wails v3 CLI](https://v3.wails.io/getting-started/installation/)
- Node.js (for the frontend build)
- [Task](https://taskfile.dev/) (task runner)

Install Task and the Wails CLI (macOS):

```sh
brew install go-task
go install github.com/wailsapp/wails/v3/cmd/wails3@latest
```

## Development

```sh
task dev
```

This starts the Wails dev server with hot-reload for both Go and frontend changes. It automatically generates bindings, installs npm dependencies, builds the frontend, and launches the app.

> **Note:** The frontend cannot be run standalone with `npm run dev` — the Vite config uses the Wails plugin, which requires generated bindings that are only produced by the full `task dev` or `task build` pipeline.

### Mock daemon

The UI connects to the daemon API at `127.0.0.1:7878` by default. If you don't have the real daemon running, start the mock server in a separate terminal first:

```sh
task mock
```

This serves seed data (block events, TLS failures) and returns version `v1.2.3`. Then run `task dev` in another terminal to start the UI.

### Build without running

```sh
# Verify the frontend compiles (includes bindings generation)
task common:build:frontend

# Full build
task build

# Platform-specific distributable (.app, .exe, etc.)
task package
```

### Server mode (no GUI)

Runs the app as a plain HTTP server, useful for testing on headless machines:

```sh
task build:server
task run:server
```

### Available tasks

Run `task --list` from the `ui/` directory to see all available tasks.

## CLI Flags

The daemon typically launches the UI with these flags:

| Flag | Default | Description |
|------|---------|-------------|
| `-daemon_url` | `http://127.0.0.1:7878` | Daemon API base URL |
| `-token` | `devtoken` | Bearer token for daemon API auth |
| `-ui_url` | `127.0.0.1:9876` | Address the UI's HTTP server listens on |
| `-log_file` | _(stdout only)_ | Path to a log file (tee'd with stdout) |
