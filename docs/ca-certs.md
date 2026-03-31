# CA Certificates

Aikido Endpoint installs a proxy CA certificate into the OS trust store (macOS System Keychain / Windows Certificate Store) and configures per-application trust for tools that maintain their own certificate stores.

## Node.js

Node.js does not use the OS trust store. Aikido Endpoint sets the `NODE_EXTRA_CA_CERTS` environment variable in shell startup files (`.zshrc`, `.bash_profile`, `.bashrc`, `.zprofile`, `.profile`, `config.fish`), pointing to a combined PEM bundle containing the SafeChain CA and any previously configured extra CA certificates.

On Windows, the environment variable is set at the User level via PowerShell.

## Python / pip

pip and the Python `requests`/`ssl` libraries do not use the OS trust store by default. Aikido Endpoint sets the `PIP_CERT` environment variable in shell startup files, pointing to a combined PEM bundle containing the SafeChain CA and the system's existing CA bundle (resolved from `certifi` or Python's `ssl` module defaults).

On Windows, the environment variable is set at the User level via PowerShell.

## Firefox

Firefox maintains its own certificate store and does not trust the OS trust store by default. Aikido Endpoint enables the `security.enterprise_roots.enabled` preference in each detected Firefox profile's `user.js` file, which tells Firefox to also trust certificates in the OS trust store.

## Docker

Aikido Endpoint automatically installs the CA into running Docker containers for supported Linux distributions (Debian/Ubuntu, Alpine, RHEL/CentOS/Fedora/Amazon Linux). Containers that start after the agent is active are also reconciled automatically.

### Docker troubleshooting

`docker build` runs before runtime reconciliation can help. If your build downloads packages (`npm install`, `pip install`, etc.), you need to install the CA in the Dockerfile manually. See [Proxy Troubleshooting: Docker builds](proxy/troubleshooting.md#docker-builds-with-the-l4-proxy) for per-distro Dockerfile instructions.

## JetBrains IDEs

JetBrains IDEs (IntelliJ IDEA, PyCharm, WebStorm, GoLand, CLion, PhpStorm, Rider, RubyMine, DataGrip, RustRover) read from the OS trust store by default. No additional certificate configuration is needed.

**The IDE must be restarted** after Aikido Endpoint is installed (or after the CA is updated). JetBrains IDEs load certificates at startup and do not watch for changes to the OS trust store at runtime.

> **Note:** Maven and Gradle running inside JetBrains use the project JDK's `cacerts` keystore, not the IDE's trust manager. If Maven/Gradle builds fail with certificate errors while the IDE itself works fine, the CA may need to be added to the JDK's trust store separately via `keytool`.
