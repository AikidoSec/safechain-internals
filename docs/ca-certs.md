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

## Java

Maven, Gradle, and other Java build tools read trust roots from the JDK's `cacerts` keystore rather than the OS trust store. Aikido Endpoint imports its CA into the `cacerts` of every JDK it can discover on the system.

On macOS, discovery covers:

- JDKs reported by `/usr/libexec/java_home -V`
- JetBrains-managed JDKs and the bundled JBR inside IDE app bundles
- Eclipse-bundled JustJ JDKs
- Homebrew `openjdk` (Apple Silicon and Intel prefixes)
- Version managers: sdkman, asdf, jenv

JDKs installed in non-standard locations are not auto-configured and must be handled manually.

If a build still fails with a TLS error, confirm which JDK is actually being used (`mvn --version`, or in JetBrains via `Settings → Build Tools → Gradle → Gradle JVM`) and verify the `aikido-safechain-proxy-ca` alias is present in its `cacerts`:

```bash
keytool -list -keystore <jdk>/lib/security/cacerts -storepass changeit | grep aikido-safechain-proxy-ca
```

If the alias is missing, the JDK was outside Aikido's discovery — import the CA manually with `keytool -importcert`.

## Docker

Aikido Endpoint automatically installs the CA into running Docker containers for supported Linux distributions (Debian/Ubuntu, Alpine, RHEL/CentOS/Fedora/Amazon Linux). Containers that start after the agent is active are also reconciled automatically.

### Docker build troubleshooting

`docker build` runs before runtime reconciliation can help. If your build downloads packages (`npm install`, `pip install`, etc.), you need to install the CA in the Dockerfile manually.

Add the following before the first networked package-manager step (`RUN npm install`, `RUN pip install`, etc.) in every build stage that downloads dependencies.

**Debian / Ubuntu:**

```dockerfile
RUN apt-get update && apt-get install -y ca-certificates curl && \
    curl -fsSL http://mitm.ramaproxy.org/data/root.ca.pem \
      -o /usr/local/share/ca-certificates/aikido-safechain-proxy-ca.crt && \
    update-ca-certificates

ENV NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/aikido-safechain-proxy-ca.crt
ENV PIP_CERT=/usr/local/share/ca-certificates/aikido-safechain-proxy-ca.crt
ENV REQUESTS_CA_BUNDLE=/usr/local/share/ca-certificates/aikido-safechain-proxy-ca.crt
ENV SSL_CERT_FILE=/usr/local/share/ca-certificates/aikido-safechain-proxy-ca.crt
```

**Alpine:**

```dockerfile
RUN apk add --no-cache ca-certificates curl && \
    curl -fsSL http://mitm.ramaproxy.org/data/root.ca.pem \
      -o /usr/local/share/ca-certificates/aikido-safechain-proxy-ca.crt && \
    update-ca-certificates

ENV NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/aikido-safechain-proxy-ca.crt
ENV PIP_CERT=/usr/local/share/ca-certificates/aikido-safechain-proxy-ca.crt
ENV REQUESTS_CA_BUNDLE=/usr/local/share/ca-certificates/aikido-safechain-proxy-ca.crt
ENV SSL_CERT_FILE=/usr/local/share/ca-certificates/aikido-safechain-proxy-ca.crt
```

**RHEL / CentOS / Fedora / Amazon Linux / Rocky / AlmaLinux / Oracle Linux:**

```dockerfile
RUN mkdir -p /etc/pki/ca-trust/source/anchors && \
    (command -v dnf >/dev/null && dnf install -y ca-certificates curl || yum install -y ca-certificates curl) && \
    curl -fsSL http://mitm.ramaproxy.org/data/root.ca.pem \
      -o /etc/pki/ca-trust/source/anchors/aikido-safechain-proxy-ca.crt && \
    update-ca-trust

ENV NODE_EXTRA_CA_CERTS=/etc/pki/ca-trust/source/anchors/aikido-safechain-proxy-ca.crt
ENV PIP_CERT=/etc/pki/ca-trust/source/anchors/aikido-safechain-proxy-ca.crt
ENV REQUESTS_CA_BUNDLE=/etc/pki/ca-trust/source/anchors/aikido-safechain-proxy-ca.crt
ENV SSL_CERT_FILE=/etc/pki/ca-trust/source/anchors/aikido-safechain-proxy-ca.crt
```

Notes:

- Repeat in every stage that performs package downloads (multi-stage builds often need it in both the builder and runtime stages).
- For Node-based images, `NODE_EXTRA_CA_CERTS` is often required even after the OS trust store has been updated.
- For Python-based images, `PIP_CERT` is the primary setting; `REQUESTS_CA_BUNDLE` and `SSL_CERT_FILE` help other Python and OpenSSL-based tooling trust the same CA.
- If the build still fails after the CA is trusted, the proxy may be blocking a package by policy. Check the package-manager output for details.

## JetBrains IDEs

JetBrains IDEs (IntelliJ IDEA, PyCharm, WebStorm, GoLand, CLion, PhpStorm, Rider, RubyMine, DataGrip, RustRover) read from the OS trust store by default. No additional certificate configuration is needed.

**The IDE must be restarted** after Aikido Endpoint is installed (or after the CA is updated). JetBrains IDEs load certificates at startup and do not watch for changes to the OS trust store at runtime.

For Maven and Gradle builds run from inside JetBrains IDEs, see [Java](#java) — those tools use the JDK's `cacerts` keystore, not the IDE's trust manager.

## Custom / other software

If you use software that maintains its own certificate store or does not read from the OS trust store, you can retrieve the Aikido Endpoint CA certificate and install it manually.

While the proxy is running, the CA certificate is available at:

```
http://mitm.ramaproxy.org/data/root.ca.pem
```

Download it with curl:

```bash
curl -fsSL http://mitm.ramaproxy.org/data/root.ca.pem -o aikido-safechain-proxy-ca.pem
```
