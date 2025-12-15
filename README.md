# Aikido Agent

A lightweight background agent that provides real-time security scanning for your development environment. The Aikido Agent runs as a daemon, integrates and manages the following security tooling seamlessly into your workflow:
- Aikido SafeChain
- Aikido GitHook (WIP)
- Aikido VsCode extension (WIP)
- ...

## Installation

### macOS (Homebrew)

```bash
brew tap AikidoSec/AikidoAgent
brew install AikidoAgent
```

To start the agent as a background service:

```bash
brew services start AikidoAgent
```

To stop the service:

```bash
brew services stop AikidoAgent
```
