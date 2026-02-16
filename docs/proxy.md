# Safe-chain Proxy

A security-focused SOCKS5/HTTP(S) system proxy
built with <https://ramaproxy.org/>.

> Edge Rama Rust docs:
> <https://ramaproxy.org/docs/rama/>

Other proxy docs:

- [./proxy/auth-flow.md](./proxy/auth-flow.md): learn more about the proxy authentication flow,
  and specifically how to pass a user config when connecting to the safechain proxy.
- [./proxy/pac.md](./proxy/pac.md): learn more about Proxy Auto Configuration
  and how the safechain proxy project supports this flow.
- [`./proxy/troubleshooting.md](./proxy/troubleshooting.md): proxy troubleshooting doc.

## Quick Start

### Running the Proxy

Run the executable:

```bash
# Unix
./safechain-l7-proxy

# Windows
SafeChainL7Proxy.exe
```

The proxy will automatically find an available port and display it:

```
local HTTP(S)/SOCKS5 proxy ready proxy.address=127.0.0.1:8080
```

Or you can get the address from the local data file where it is stored as wel.

### Custom interface

By default the safechain-l7-proxy will run on the local Ipv4 interface (127.0.0.1),
on an available port. You can specify a specific (network) "interface" to bind to:

Use the `--bind` or `-b` flag:

```bash
# Long form
./safechain-l7-proxy --bind 127.0.0.1:3128

# Short form
./safechain-l7-proxy -b '[::]:3128'
```

The meta server's interface can be chosen the same using the `--meta` / `-m` flag.
Note in case you need advanced socket options it will need to be programmed
that a config is accepted.

### Usage Command

```bash
./safechain-l7-proxy --help
```

## Using the Proxy

Configure your package manager or HTTP client to route traffic through the proxy.

### npm / Node.js

```bash
npm config set proxy http://127.0.0.1:3128
npm config set https-proxy http://127.0.0.1:3128

# Now npm install will route through the proxy
npm install
```

You can also use username labels to configure
the proxy connection behavior, e.g.:

```bash
npm config set proxy http://-min_package_age-48h:@127.0.0.1:3128
```

To revert:
```bash
npm config delete proxy
npm config delete https-proxy
```

### Yarn

```bash
yarn config set httpProxy http://127.0.0.1:3128
yarn config set httpsProxy http://127.0.0.1:3128
```

### pnpm

```bash
pnpm config set proxy http://127.0.0.1:3128
pnpm config set https-proxy http://127.0.0.1:3128
```

### Bun

```bash
export http_proxy=http://127.0.0.1:3128
export https_proxy=http://127.0.0.1:3128
bun install
```

### curl

```bash
curl -x http://127.0.0.1:3128 https://example.com
```

For the HTTP(S) proxy we also support username labels, example:

```bash
curl \
    -x http://127.0.0.1:3128 \
    --proxy-user 'system-min_pkg_age-48h:' \  # no password is required
    https://example.com
```

The username labels allow one to configure the firewall behaviour,
such as in the example above where the minimum package is 48 hours,
instead of whatever the global default is.

Read more about this in [./proxy/auth-flow.md](./proxy/auth-flow.md).

### Environment Variables (any tool)

Set these environment variables to make any HTTP client use the proxy:

```bash
# macOS/Linux
export http_proxy=http://127.0.0.1:3128
export https_proxy=http://127.0.0.1:3128

# Windows (Command Prompt)
set http_proxy=http://127.0.0.1:3128
set https_proxy=http://127.0.0.1:3128

# Windows (PowerShell)
$env:http_proxy = "http://127.0.0.1:3128"
$env:https_proxy = "http://127.0.0.1:3128"
```

## Developer instructions

For ease of use we provide a justfile which
does require `just` to be insalled: <https://just.systems/man/en/>

Once that is installed you can run all normal tests:

```
just rust-qa
```

In case clippy fails you often can fix it automatically using `cargo clippy --fix --allow-dirty`,

To run the proxy for local dev purposes you can just:

```
just run-proxy
```

### Har support

Safechain Proxy supports HAR exports,
but it does require that you compile the `safechain-l7-proxy` binary
using `--features har`, which is for you done when running (locally) `just run-proxy`.

> In case it is the first time that you run the proxy
> make sure to trust the root certificate.
>
> 1. download the root CA (pem) crt
>
> ```bash
> curl -s http://127.0.0.1:8088/ca -o /tmp/safechain-proxy-ca-crt.pem
> # will store the PEM data of that (root) CA crt in a tmp location
> ```
>
> 2. install and trust the root CA crt as a system CA,
>    (see the Slack canvas in `#aikido-rama` for more info on how to
>     do this for your platform)

In case you want to run HAR exports because you wish to support
a new target it could be handy to use the `--all` flag when running the proxy
so that you MITM all traffic, as you might not yet know what domains it uses:

```bash
just run-proxy -v --all
````

Once that is done you can start (HAR) recording (in another tab):

```bash
just proxy-har-toggle
# should return true
```

Now download an extension on the app that you wish to support (e.g. google chrome store).
Once that is done you can stop the HAR recording by using the same cmd:

```bash
just proxy-har-toggle
# should return false
```

The HAR recording file is in your data folder (by default `.aikido/safechain-proxy`)
in a sub folder named `diagnostics`. Within there you'll find your HAR file
with a timestamp + seq id in the name.

Using your browser dev tools or a site like <https://toolbox.googleapps.com/apps/har_analyzer/>
you can inspect the desired target in peace and figure out how to get the info
from the desired requests and know when to block and when not.

#### Har as Developer aid

The beauty of Har is that they are not only good for diagnostics,
but can also aid the developer in finding relevant requests,
and adding them to their own test suite of requests to replay
with attached expected behaviour (e.g. whether to block or not).

Example request of chrome store which requests the download link for an extension:

```json
{
    "method": "GET",
    "url": "https://clients2.google.com/service/update2/crx?response=redirect&os=mac&arch=arm64&os_arch=arm64&prod=chromecrx&prodchannel=&prodversion=143.0.7499.111&lang=en-US&acceptformat=crx3,puff&x=id%3Dlajondecmobodlejlcjllhojikagldgd%26installsource%3Dondemand%26uc&authuser=0",
    "httpVersion": "2",
    "cookies": [ "..." ],
    "headers": [ "..." ],
    "queryString": [],
    "postData": null,
    "headersSize": 4075,
    "bodySize": 0,
    "comment": "http(s) MITM egress client"
}
```

> The cookies and headers are left out of this snippet for the purpose brevity.

Using <https://ramaproxy.org/docs/rama/http/layer/har/spec/struct.Request.html#impl-TryFrom%3CRequest%3E-for-Request> you can easily
turn this request (deserialized from the json format) into a regular rama http request,
that you can replay through your service and test if indeed your
request is correct blocked or not.

This makes it trivial to:

- initially develop a new firewall rule;
- ensure that rules keep working despite updates in this codebase or the service API.

## Troubleshooting

See [`./proxy/troubleshooting.md`](./proxy/troubleshooting.md).

## Stopping the Proxy

Press `Ctrl+C` to stop the proxy. It will gracefully shut down, waiting up to 30 seconds for active connections to complete.

## What Does It Do?

The Safe-chain proxy intercepts HTTP/HTTPS traffic
from package managers and other tools, allowing Safe-chain to:
- Scan packages for malware before installation
- Monitor registry requests
- Block malicious packages
- Provide visibility into dependency downloads

## Security

- The proxy and meta servers should only listens on `127.0.0.1` (localhost) -
  this way it cannot be accessed from other machines
- Body size limits prevent memory exhaustion attacks
