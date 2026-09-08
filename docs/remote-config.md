# Remote configuration

> Managing a fleet? The [Osprey Management Console](https://console.osprey.ac) builds and hosts this configuration
> per client and updates every enrolled device automatically. Plans are on the
> [pricing page](https://osprey.ac/pricing/). The rest of this document describes the underlying extension behavior
> for administrators who host their own configuration.

The `ManagedConfigUrl` managed policy points the extension at a JSON document that the administrator hosts and controls.
The extension fetches this document on startup and on a recurring schedule, then applies it, so enrolled endpoints pick
up changes on their next refresh without a Group Policy or Intune re-push.

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

The extension fetches the document once at startup and then every 60 minutes through a browser alarm. Fetches use a
15-second timeout, and documents larger than 512 KB are rejected. The URL must use `https`; plain `http` is accepted
only for loopback and private-network hosts, and a fetch that is redirected off approved transport is rejected.

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

- `ManagedConfigUrl` is ignored if present, because a document cannot change its own source.
- Prototype keys such as `__proto__` are ignored.

Set `DisableUninstallSurvey` to `true` to stop the extension from opening its uninstall feedback page when a user
removes the extension. It defaults to `false`, so a consumer install still shows the survey; a managed MSP deployment
normally sets it to `true`.

Set `DisableWelcomePage` to `true` to stop the extension from opening its welcome page in a new tab the first time it is
installed. It defaults to `false`, so a consumer install sees the page; a managed MSP deployment normally sets it to
`true`. The policy is read when the install event fires, so it must already be present in managed storage at install
time.

`UserEmail` holds the signed-in user's email address and is intended to be set per user through Group Policy, Intune, or
a plist rather than through this shared document, since the document is the same for every user of a client. When set,
the warning page's contact link carries the user's email and the blocked URL as query parameters, so a console-hosted
unblock request page opens with both fields already filled in.

`ManagedDomainIntelMode` (`""`, `"warn"`, or `"block"`) turns on fully local lookalike and domain-shape analysis:
homograph and typo lookalikes of the domains listed in `ManagedProtectedDomains` (an array of the client's own real
domains), mixed-script labels, and DGA-shaped hostnames. Everything computes on the device; nothing new leaves the
browser. In `warn` mode findings are recorded to the local event log only. In `block` mode a lookalike of a protected
domain blocks with a Lookalike Domain warning; the other signals stay log-only. Both keys default off.

`ManagedSafeSearch` (`""` or `"strict"`) forces SafeSearch on Google, Bing, and DuckDuckGo through request rules on the
device, and `ManagedYouTubeRestrict` (`""`, `"moderate"`, or `"strict"`) forces YouTube Restricted Mode through the
`YouTube-Restrict` request header. Both default off. They require host access to the search and YouTube domains, which
the extension declares as optional permissions; managed deployments grant them through the browser's
`ExtensionSettings` policy (`runtime_allowed_hosts`) delivered by GPO, Intune, or the Google Admin console alongside the
other policy keys. Without the grant the rules install but never match, and the device records the degraded state in its
local event log. Search engines can change their URL parameters at any time, which is why both keys default off and an
emergency settings migration can clear every rule Osprey installed.

`blockCategories` inside a `ManagedProviderSettings` entry force-sets that provider's block-category toggles. For
AlphaMountain this covers the security-adjacent toggles (`suspicious`, `newly_registered`, `dynamic_dns`) and the
content policy categories: `parked`, `adult_content`, `sex_education`, `dating`, `gambling`, `drugs`,
`alcohol_tobacco`, `weapons`, `hate_discrimination`, `violence_gore`, `piracy`, `hacking`, `social_media`,
`streaming_media`, `games`, `chat_messaging`, `file_sharing`, `shopping_auctions`, `job_search`, `webmail`,
`remote_access`, `ai_applications`, `cryptocurrency`. Content categories are acceptable-use policy blocks rather than
security verdicts: the warning page presents them as blocked by the organization's policy, and severe security verdicts
always take precedence in what the user sees. Keys unknown to an older extension version are ignored, so a document may
safely enable categories before every device has updated. Enabling a category implies the AlphaMountain lookup runs; a
document that enables categories while disabling the provider is contradictory and the provider setting wins.

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
