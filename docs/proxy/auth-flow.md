# Proxy Auth Flow

The safechain proxy does not require authentication.
However, for both HTTP(S) and SOCKS5(H) proxy connect support,
it is possible to use BASIC authentication using a username and password.

When authentication is used, the username may be any value,
and the password may be omitted entirely.

Given this, why support optional authentication at all?

The reason is that it is the only universal mechanism that allows users
to pass per connection configuration to the proxy.
This configuration applies only to the connection that is being established
for the current user and nowhere else.

For HTTP proxy CONNECT requests, it is also possible to pass configuration
using HTTP headers. This approach works only for HTTP proxies and only for TLS secured targets
such as `https://`.

As a result, insecure requests such as `http://`, as well as SOCKS5 users,
cannot rely on proxy CONNECT request headers.

## User Connection Config

| label | example values | description |
|-------|----------------|-------------|
| `min_pkg_age` | `2d`, `48h`, `12h_30m`, `2y` | the minimum allowed package age, with no minimum by default |

### Curl Examples

In the following examples, `example.com` is used for documentation purposes only.
We assume that the proxy is running at `127.0.0.1:8080`.

#### Config via Username Labels

```sh
curl \
    http://example.com \
    -x http://127.0.0.1:8080 \
    --proxy-user 'test-min_pkg_age-24h:'
```

In this example, the proxy user is defined as follows:

- username: `test-min_pkg_age-24h`
- password: omitted

The username is parsed into:

- username: `test`  
  This value can be anything and serves a role similar to a User Agent
  in regular HTTP requests.
- config:
  - `min_pkg_age`: `Some(24h)`

The advantage of using username labels is that they also work for:

- secure targets such as `https://example.com`
- SOCKS5 proxies, for example:

```sh
curl \
    https://example.com \
    -x socks5h://127.0.0.1:8080 \
    --proxy-user 'test-min_pkg_age-1d:'
```

Unknown labels such as `foo` are ignored.
This means that `test-min_pkg_age-1d:` and `test-foo-min_pkg_age-1d`
result in the exact same username and configuration.

If an error occurs while parsing the username labels,
for example due to an invalid duration like `test-min_pkg_age-what`
or a missing value such as `test-min_pkg_age`,
the error is logged at debug level.
The request is still allowed to proceed, but no user configuration is applied.

#### Config via Proxy CONNECT Request Header

Proxy CONNECT request headers are only supported when:

- using the proxy as an HTTP proxy
- making a request to a secure target such as `https://`

Example:

```sh
curl \
    https://example.com \
    -x http://127.0.0.1:8080 \
    --proxy-header 'x-aikido-safe-chain-config: min_pkg_age=24h'
```

Explanation:

- the custom header name is `x-aikido-safe-chain-config`
- the value is encoded in the same way as an HTML form POST payload
- this works only when:
  - connecting to the proxy using the `http://` scheme
  - targeting secure servers  
    Plain text targets such as `http://example.com` do not use HTTP CONNECT
    and therefore cannot include proxy headers

If both a username label and a custom HTTP proxy CONNECT header are provided,
the header value takes precedence.

Finally, note that most clients do not support custom HTTP proxy CONNECT
request headers. As a result, the username label approach is expected to be used
in almost all cases.
