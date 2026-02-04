# Proxy Troubleshooting

## Problems

### Port Already in Use

If you get a "port already in use" error:
- Try running without `--port` to let the OS assign an available port
- Or choose a different port: `./safechain-proxy --port 8080`

### Proxy Not Working

1. Verify the proxy is running and note the port from the console output
2. Check your client is configured with the correct port
3. Ensure firewall settings allow connections to the proxy

To verify that the proxy is correctly configured via system settings, a PAC file, or a client specific configuration,
try accessing the pseudo domain `proxy.safechain.internal`.

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

### Verbose Logging

Enable debug (or trace even) logging to troubleshoot issues:

```bash
# macOS/Linux
RUST_LOG=debug ./safechain-proxy

# Windows (Command Prompt)
set RUST_LOG=trace
safechain-proxy.exe

# Windows (PowerShell)
$env:RUST_LOG = "debug,safechain_proxy=trace"
.\safechain-proxy.exe
```

'debug,safechain_proxy=trace' might as well be the default trace directive.

### Malware request is not blocked

In case your request is not blocked and you are certain that it should, you can:

- look into the logs
- and/or use tools such as wireshark.

> In the near future we will also have tooling
> to replay traffic (e.g. via HAR files) to help
> reproduce issues.
