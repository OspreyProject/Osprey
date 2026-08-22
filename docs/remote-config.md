# Remote configuration

The `ManagedConfigUrl` managed policy points the extension at a JSON document that it hosts and controls. The extension
fetches this document on startup and on a recurring schedule, then applies it. An MSP edits one hosted file per client
and every enrolled endpoint picks up the change on its next refresh, with no Group Policy or Intune re-push.

## How values are applied

Fetched values are merged **under** managed storage. Anything an administrator sets locally through Group Policy,
Intune, or a plist always wins, and the fetched document fills in the rest. This lets a client keep a few locally pinned
settings while everything else is driven from the hosted file.

On a fetch failure the extension keeps the last document it successfully fetched. A network outage or a bad deploy never
drops settings or protection. The last-known-good document is stored on the endpoint and is reloaded on the next
startup.

`ManagedConfigUrl` itself can only be set through managed storage. A fetched document cannot change it, so the document
can never redirect its own source.

## Refresh timing

The extension fetches the document once at startup and then every 60 minutes through a browser alarm. Fetches use a 15
second timeout, and documents larger than 512 KB are rejected.

## Host permission

The config origin must be reachable by the extension. In a managed deployment, grant the origin through the browser's
extension policy the same way you grant the proxy origin for `ProxyBaseUrl`. The extension declares broad optional host
access for this purpose.

## Document shape

The document is a JSON object. The canonical form has two sections:

```json
{
  "version": 1,
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
    "ManagedProviderSettings": {
      "phishunt-io": {
        "enabled": true,
        "bypassBlockingThreshold": false
      }
    }
  },
  "customProviders": []
}
```

The `policies` object accepts the same keys as managed storage, with two exceptions:

- `ManagedConfigUrl` is ignored if present, because a document cannot change its own source.
- Prototype keys such as `__proto__` are ignored.

Set `DisableUninstallSurvey` to `true` to stop the extension from opening its uninstall feedback page when a user
removes the extension. It defaults to `false`, so a consumer install still shows the survey; a managed MSP deployment
normally sets it to `true`.

`UserEmail` holds the signed-in user's email address and is intended to be set per user through Group Policy, Intune, or
a plist rather than through this shared document, since the document is the same for every user of a client. When set,
the warning page's contact link carries the user's email and the blocked URL as query parameters, so a console-hosted
unblock request page opens with both fields already filled in.

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
  `direct_integrations`.
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
`responseRules` follow the same format as the built-in direct integrations.

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
