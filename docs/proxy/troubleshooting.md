# Proxy Troubleshooting

## Problems

### Port Already in Use

If you get a "port already in use" error:
- Try running without `--port` to let the OS assign an available port
- Or choose a different port: `./safechain-l7-proxy --port 8080`

### Proxy Not Working

1. Verify the proxy is running and note the port from the console output
2. Check your client is configured with the correct port
3. Ensure firewall settings allow connections to the proxy

To verify that the proxy is correctly configured via system settings,
a PAC file, or a client specific configuration,
try accessing the hijack domain `mitm.ramaproxy.org`.

- If you can reach it over the `http://` scheme, the proxy is correctly configured and running.
- If you can also reach it over the `https://` scheme, the proxy root CA is trusted.

For any HTTPS traffic that is MITM’d by the proxy, you should also observe that the server certificate
is signed by the proxy root CA rather than the original CA for that server
(for example Let’s Encrypt).

### Proxied traffic fails

If proxied traffic is not working as expected, try the following steps.

- Check the logs if possible
  stderr by default, or the configured output file when using the `--output` argument.
  - [Verbose logging](#verbose-logging) can help narrow down the issue further,
    especially when well defined directives are in use.
- Ensure that [HAR support](#har-support) is enabled and inspect the output
  to see whether anything looks incorrect.

If none of the above provides useful insight, you may need to escalate to more advanced tooling,
such as [Wireshark](https://www.wireshark.org/).

The proxy supports SSL key logging to a file, which is required for Wireshark
to decrypt encrypted traffic on both the ingress and egress side.
Set the environment variable `SSLKEYLOGFILE=<path>` to enable this.

On macOS, there is an additional trick that can make it easier to identify
which traffic belongs to which process.

```bash
sudo tcpdump -i pktap,all -k -w - \
  | /Applications/Wireshark.app/Contents/MacOS/Wireshark -k -i -
```

Using the special `pktap` interface on macOS, you can add the following columns
in Wireshark to display process information.

```
frame.darwin.process_info.pname
frame.darwin.process_info.pid
```

All traffic that passes through the proxy can then be identified with the filter.

```
frame.darwin.process_info.pname = safechain_proxy
```

This approach is not the simplest, but it is usually sufficient to determine
why traffic fails when routed through the proxy while succeeding when connecting
directly to the target services.

### Docker builds with the L4 proxy

> See also: [CA Certificates](../ca-certs.md) for a full overview of how Aikido Endpoint configures certificate trust across all supported tools.

Aikido Endpoint attempts to install its CA automatically into supported
Docker containers that are already running or that start after the agent is active.

> In most runtime scenarios, you do not need to modify the image yourself.

`docker build` is different. If the build runs package-manager commands such as
`npm install`, `pnpm install`, `yarn install`, or `pip install`, you may need
to install the L4 proxy CA in the Dockerfile yourself. Build-time package
downloads happen before that runtime reconciliation can help.

Add the CA before the first networked package-manager step in every build stage
that downloads dependencies. The exact command depends on the base image family.

Debian or Ubuntu based images:

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

Alpine based images:

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

RHEL, CentOS, Fedora, Amazon Linux, Rocky, AlmaLinux, or Oracle Linux based images:

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

- Add this before the first `RUN npm install`, `RUN pnpm install`, `RUN yarn install`,
  `RUN pip install`, or similar command.
- Repeat it in every stage that performs package downloads. Multi-stage builds
  often need the same setup in both the builder stage and the runtime stage.
- For Node-based images, `NODE_EXTRA_CA_CERTS` is often required even after the
  OS trust store has been updated.
- For Python-based images, `PIP_CERT` is the primary setting; `REQUESTS_CA_BUNDLE`
  and `SSL_CERT_FILE` help other Python and OpenSSL-based tooling trust the same CA.

If the build still fails after the CA is trusted, inspect the package-manager
output carefully. The proxy can still block packages that are flagged by policy,
including packages that require approval. In that case, the failure is expected
proxy behavior rather than a certificate trust problem.

### JetBrains IDEs

JetBrains IDEs read from the OS trust store but only load certificates at startup. If you see certificate errors after installing Aikido Endpoint, restart the IDE. See [CA Certificates: JetBrains IDEs](../ca-certs.md#jetbrains-ides) for more details.

### Verbose Logging

Enable debug (or trace even) logging to troubleshoot issues:

```bash
# macOS/Linux
RUST_LOG=debug ./safechain-l7-proxy

# Windows (Command Prompt)
set RUST_LOG=trace
SafeChainL7Proxy.exe

# Windows (PowerShell)
$env:RUST_LOG = "debug,safechain_proxy=trace"
.\SafeChainL7Proxy.exe
```

'debug,safechain_proxy=trace' might as well be the default trace directive.

### Malware request is not blocked

In case your request is not blocked and you are certain that it should, you can:

- look into the logs
- and/or use tools such as wireshark.

> In the near future we will also have tooling
> to replay traffic (e.g. via HAR files) to help
> reproduce issues.
