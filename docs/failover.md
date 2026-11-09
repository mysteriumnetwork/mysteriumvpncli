# Domain discovery and failover

API and authentication requests normally start with the configured API URL;
cached availability can select a working alternative during a failure cooldown. Requests
have a default overall timeout of 30 seconds and a 5-second dial limit for
connecting (DNS/TCP). TLS handshakes, waiting for an API response, and reading its
body share the overall request budget; TLS has no separate timeout. With discovery enabled, transport failures
move directly to the next domain without retrying the failed domain. HTTP 5xx
responses retain normal retries. After a transport or response-read failure, HTTP
5xx, 403, or 451,
the CLI tries alternative domains in discovery mapping order. It replaces only
the hostname, preserving the scheme, port, path, query, headers, and request body.
HTTP 401 continues to use the existing token-refresh flow; other API errors do
not trigger domain discovery.

Discovery loads `https://static-resources-hub.github.io/config.json`, falling back
to `https://raw.githubusercontent.com/static-resources-hub/static-resources-hub.github.io/main/config.json`
if fetching or validation fails, with a 3-second timeout per discovery source.
The loader accepts schema version 1 and validates
required metadata and domain mappings. Signatures are ignored for now.

The last valid configuration is stored atomically in `mystvpn/discovery.json`
inside the user's configuration directory. Discovery refreshes on demand during
failover, at most once an hour per process; successful primary requests never
fetch discovery. A fresh disk cache is reused across CLI invocations. An expired
cache remains usable for initial selection and refreshes only after an endpoint fails.
Invalid responses never replace the last valid configuration. If no configuration
is available, the original request error is returned. Sources and refresh intervals
can be extended through `internal/discovery.Loader`.

Domain availability is remembered across CLI invocations in
`mystvpn/domain-state.json` inside the user configuration directory. API and
browser app origins have separate preferences. Failed hosts are deprioritized
for 30 minutes, and the last working alternative is tried first during that
cooldown. After the cooldown, the primary is checked again. If other endpoints
fail, cooling-down hosts are still tried as a recovery path. This does not
require a public-IP lookup and adapts when the network changes.
Delete this file to reset availability preferences. Corrupt or unwritable state
does not prevent requests; cached hosts are only used if still present in discovery.
