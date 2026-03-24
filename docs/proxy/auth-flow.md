# Proxy Auth Flow

The `safechain` proxy does not require authentication.
However, for both HTTP(S) and SOCKS5(H) proxy connect support,
it is possible to use BASIC authentication using a username and password.

When authentication is used, the username may be any value,
and the password may be omitted entirely.

Given this, why support optional authentication at all?

Well it can be used to let the proxy user use an identifier,
that can used to identify the source or purpose of the traffic,
by making use of the inserted `UserId` extension value.
