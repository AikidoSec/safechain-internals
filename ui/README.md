# Aikido Safechain UI

Desktop tray application for Aikido Safechain endpoint protection. Built with [Wails v3](https://v3.wails.io/) (Go backend + web frontend).

The app runs as a **system-tray icon** (no dock icon). It receives proxy-status updates and blocked-event notifications from the Safechain daemon, displays them in a dashboard window, and pushes native OS notifications.

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

## Development

```sh
task dev
```

This starts the app with hot-reload for both Go and frontend changes.

## Build

```sh
task build       # compile binary
task package     # platform-specific distributable (.app, .exe, etc.)
```

## CLI Flags

The daemon typically launches the UI with these flags:

| Flag | Default | Description |
|------|---------|-------------|
| `-daemon_url` | `http://127.0.0.1:7878` | Daemon API base URL |
| `-token` | `devtoken` | Bearer token for daemon API auth |
| `-ui_url` | `127.0.0.1:9876` | Address the UI's HTTP server listens on |
| `-log_file` | _(stdout only)_ | Path to a log file (tee'd with stdout) |
