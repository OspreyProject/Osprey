# Remote configuration

> Managing a fleet? The [Osprey Management Console](https://console.osprey.ac) builds and hosts this configuration
> per client and updates every enrolled device automatically. Plans are on the
> [pricing page](https://osprey.ac/pricing/). The rest of this document describes the underlying extension behavior
> for administrators who host their own configuration.

The `ManagedConfigUrl` managed policy points the extension at a signed JSON document that the administrator hosts and
controls. Set `ManagedConfigPublicKey` in managed storage to the JSON-encoded P-256 public JWK corresponding to the
private key used to sign the document. Without both settings, no remote policy is applied. The extension fetches this
document on startup and on a recurring schedule, then applies it, so enrolled endpoints pick up changes on their next
refresh without a Group Policy or Intune re-push.

## How values are applied

Fetched values are merged **under** managed storage. Anything an administrator sets locally through Group Policy,
Intune, or a plist always wins, and the fetched document fills in the rest. This lets a client keep a few locally pinned
settings while everything else is driven from the hosted file.

On a fetch failure the extension keeps the last document it successfully fetched. A network outage or a bad deploy never
drops settings or protection. The last-known-good document is stored on the endpoint and is reloaded on the next startup
only after its signature is verified again against the current managed key. Removing `ManagedConfigUrl` or
`ManagedConfigPublicKey` deactivates remote policy immediately and removes the stored document. Replacing the key
invalidates documents signed with the old key.

`ManagedConfigUrl` and `ManagedConfigPublicKey` can only be set through managed storage. A fetched document cannot
change its own source or verification key.

## Refresh timing

The extension fetches the document once at startup and then every 60 minutes through a browser alarm. Fetches use a
15-second timeout, and documents larger than 512 KB are rejected. The URL and its final redirect must use `https`. Proxy
and reporting endpoints also require HTTPS.

## Host permission

The extension only holds host permission for `https://api.osprey.ac`. Every other origin it calls (the managed config
URL, a self-hosted proxy, the reporting endpoint, and custom provider endpoints) is reached as an ordinary cross-origin
request, so that server must answer with CORS headers that allow the extension's origin
(`chrome-extension://<id>` or `moz-extension://<id>`, or `*`). The Osprey console and OspreyProxy already do. The config
fetch is a simple `GET`, so it needs only `Access-Control-Allow-Origin`; the proxy and reporting calls send JSON and an
auth header, so their servers must also answer the `OPTIONS` preflight.

## Document shape

The fetched JSON is an envelope with a `payload` string containing the serialized configuration document and a
base64-encoded `signature`. Sign the UTF-8 bytes of the **exact payload string** using ECDSA P-256 with SHA-256. The
signature must use the Web Crypto (IEEE P1363) format: 32-byte `r` followed by 32-byte `s`. Keep the private key on the
signing server; deploy only its public JWK via managed storage. Unsigned documents and previously cached unsigned
documents are rejected.

The signed payload must also carry two binding fields, and documents without them are rejected:

- `audience` is the exact `ManagedConfigUrl` the document is served at. A document signed for one client's URL is
  rejected at any other URL, so one signing key can safely serve many clients.
- `sequence` is a non-negative integer that must never decrease. The extension rejects a document whose sequence is
  lower than the last one it accepted, so an older signed document cannot be replayed to roll policy back. Re-serving
  the current sequence is fine. An optional `issuedAt` (epoch milliseconds) is ignored by the extension but useful for
  auditing.

The inner document also has two content sections:

```json
{
  "payload": "{\"version\":1,\"audience\":\"https://config.msp.example/acme.json\",\"sequence\":42,\"policies\":{\"DisableUserAllowlist\":true},\"customProviders\":[]}",
  "signature": "<base64-encoded 64-byte signature>"
}
```

For example, the decoded `payload` may contain:

```json
{
  "version": 1,
  "audience": "https://config.msp.example/acme.json",
  "sequence": 42,
  "issuedAt": 1700000000000,
  "policies": {
    "ManagedAllowlist": [
      "intranet.example.com",
      "*.corp.example.com"
    ],
    "ManagedBlocklist": [
      "*.malware.example"
    ],
    "ProxyBaseUrl": "https://osprey.msp.example",
    "BrandName": "Acme Secure Browsing",
    "SupportEmail": "help@msp.example",
    "DisableUserAllowlist": true,
    "DisableUninstallSurvey": true,
    "DisableWelcomePage": true,
    "ManagedProviderSettings": {
      "phishunt-io": {
        "enabled": true,
        "bypassBlockingThreshold": false
      },
      "alphamountain": {
        "enabled": true,
        "blockCategories": {
          "adult_content": true,
          "gambling": true
        }
      }
    }
  },
  "customProviders": []
}
```

The `policies` object accepts the same keys as managed storage, with two exceptions:

- `ManagedConfigUrl` and `ManagedConfigPublicKey` are ignored if present, because a document cannot change its own
  source or verification key.
- Prototype keys such as `__proto__` are ignored.

Set `DisableUninstallSurvey` to `true` to stop the extension from opening its uninstall feedback page when a user
removes the extension. It defaults to `false`, so a consumer install still shows the survey; a managed MSP deployment
normally sets it to `true`.

Set `DisableWelcomePage` to `true` to stop the extension from opening its welcome page in a new tab the first time it is
installed. It defaults to `false`, so a consumer install sees the page; a managed MSP deployment normally sets it to
`true`. The policy is read when the install event fires, so it must already be present in managed storage at install
time.

The warning page's support link opens `SupportUrl` as configured and does not transmit the user's email or the blocked
URL as query parameters; users provide any details needed for an unblock request on the support site. (The former
`UserEmail` policy only fed that prefill and has been removed.)

`ManagedNotificationProtection` (`""` or `"on"`) blocks the browser notification permission for any origin Osprey flags,
so a scam page the user proceeds past can never weaponize the notification prompt. Osprey records every origin it sets
and only ever reverts its own entries (on allowlist addition); the user's notification choices on other sites are never
touched. Chrome and Edge only: Firefox has no contentSettings API, and the device records the degraded state in its
local event log once. Defaults off; the managed baseline in the console enables it.

`ManagedDomainIntelMode` (`""`, `"warn"`, or `"block"`) turns on fully local lookalike and domain-shape analysis:
homograph and typo lookalikes of the domains listed in `ManagedProtectedDomains` (an array of the client's own real
domains), mixed-script labels, and DGA-shaped hostnames. Everything computes on the device; nothing new leaves the
browser. In `warn` mode findings are recorded to the on-device event log only and are never reported, because the
outbound event schema has no non-blocking signal type; use `warn` to trial protected domains before switching to
`block`. In `block` mode a lookalike of a protected
domain blocks with a Lookalike Domain warning; the other signals stay log-only. Both keys default off.

`blockCategories` inside a `ManagedProviderSettings` entry force-sets that provider's block-category toggles. For
AlphaMountain this covers the security-adjacent toggles (`suspicious`, `newly_registered`, `dynamic_dns`).

`CommercialDisabledProviders` is an array of provider ids that are force-disabled on the endpoint. It is honored only
when it arrives through this remote document; the same key in managed storage (Group Policy, Intune, or a plist) is
ignored, so self-managed non-commercial deployments are never affected. Providers on the list are disabled after every
other policy is applied, including `ManagedProviderSettings` entries that set
`enabled: true`, and their cards render greyed out and locked in the settings page. The hosted console injects this key
into every document it serves when a threat feed's license does not permit commercial use; documents served from other
sources normally omit it.

A flat object of policy keys is also accepted. When the top-level object has no
`policies` field, every key other than `version` and `customProviders` is treated as a policy value. The nested form is
recommended for clarity.

Unknown or wrongly typed policy values are ignored by the runtime, so a malformed entry never breaks the rest of the
document.

## Custom providers

The `customProviders` array lets the document define an MSP's own threat feed or another custom provider. Each entry is
validated with the same catalog validator that checks the built-in providers before it is applied. Entries that fail
validation are dropped individually and logged, so one malformed entry does not discard the rest.

Rules enforced during validation:

- `id` must match `^[a-z0-9-]+$` and must not collide with a built-in provider id or alias.
- `group` must be one of `official_partners`, `security_filters`, `feeds`, or
  `direct_integrations` (retained for existing custom-provider configurations).
- `kind` must be `proxy_builtin` or `direct_static`.

A custom `proxy_builtin` provider keeps its own `proxyBaseUrl` even when the global
`ProxyBaseUrl` policy is set, so pointing the built-in providers at a self-hosted backend does not reroute a separate
custom feed.

### `proxy_builtin` example

Use this when the feed speaks the Osprey proxy protocol, for example a feed served by a self-hosted `OspreyProxy`.

```json
{
  "kind": "proxy_builtin",
  "id": "acme-feed",
  "displayName": "Acme Threat Feed",
  "group": "feeds",
  "icon": "https://cdn.msp.example/acme.png",
  "enabledByDefault": true,
  "lookupTarget": "url",
  "tags": [
    "proxy"
  ],
  "aliases": [],
  "proxyBaseUrl": "https://osprey.msp.example",
  "endpoint": "acmefeed",
  "report": {
    "type": "none"
  }
}
```

### `direct_static` example

Use this when the feed is a plain HTTP endpoint. The `request` templates and
`responseRules` specify how the response is interpreted. For `regex` rules, patterns are limited to 512 characters, may
have at most one quantifier, and cannot contain groups, alternation, counted repetitions, or backreferences. Regex
matching skips response values over 1024 characters to prevent untrusted provider data from stalling URL checks.

```json
{
  "kind": "direct_static",
  "id": "acme-lookup",
  "displayName": "Acme Lookup",
  "group": "security_filters",
  "icon": "https://cdn.msp.example/acme.png",
  "enabledByDefault": true,
  "lookupTarget": "hostname",
  "tags": [],
  "request": {
    "urlTemplate": "https://feed.msp.example/lookup?host={hostname}",
    "method": "GET",
    "headers": []
  },
  "responseRules": [
    {
      "path": "listed",
      "operator": "truthy",
      "result": "MALICIOUS"
    }
  ],
  "report": {
    "type": "none"
  }
}
```
