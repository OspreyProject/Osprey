# Outbound events and heartbeats

The `ReportingEndpoint` managed policy points the extension at an HTTP endpoint that receives two kinds of message: a
batch of detection and override events, and a periodic health heartbeat. Together they let an MSP watch a fleet without
a console. Detections and overrides arrive as they happen, and the heartbeat proves each endpoint is still installed,
enabled, current, and able to reach its backend.

When `ReportingEndpoint` is empty, nothing is sent. The endpoint must be an `http(s)` URL. A malformed or non-`http(s)`
value is treated as empty.

## Authentication

The optional `ReportingAuthToken` policy sets a bearer token. When it is present, every request carries an
`Authorization: Bearer <token>` header. When it is empty, no `Authorization` header is sent. The endpoint should reject
requests whose token does not match.

## What is sent, and when

Both message kinds POST JSON to the same `ReportingEndpoint`. They are told apart by the top-level `kind` field, so a
generic webhook, a SIEM such as Splunk or Sentinel, or the console built in a later step can route them.

- Events are flushed every 5 minutes and once on startup. Each flush sends every event that has not yet been accepted by
  the endpoint.
- The heartbeat is sent every 15 minutes and once on startup.

The heartbeat interval is deliberately short so that a gap reveals an endpoint where the extension was removed or
disabled. An MSP should alert on a missing heartbeat rather than expect a message that says the extension is gone,
because a removed extension cannot report its own removal. Treat any endpoint that has not sent a heartbeat within a few
intervals as tampered with or offline.

## Delivery semantics

Delivery is at-least-once. An event is marked as reported only after the endpoint returns a `2xx` status, and that
marking is persisted on the endpoint. If the service worker is stopped after a successful POST but before the marking is
saved, the same event can be sent again on the next flush. Each event carries a stable `id`, so the receiver should
deduplicate on `id`.

A failed POST is retried up to three times within a single flush, with exponential backoff of 1 and 2 seconds between
attempts. A `4xx` status other than `429` is treated as a permanent rejection and is not retried. When all attempts
fail, the events stay unreported and the next scheduled flush retries them, so a network outage never loses events that
are still held on the endpoint.

The local event log is a capped ring buffer of the most recent 1000 events. If reporting is unreachable long enough for
more than 1000 new events to accumulate, the oldest unreported events are evicted before they can be sent. Keeping the
reporting endpoint reachable avoids this.

## Host permission

The reporting origin must be reachable by the extension. In a managed deployment, grant the origin through the browser's
extension policy the same way you grant the proxy origin for `ProxyBaseUrl` and the config origin for
`ManagedConfigUrl`. The extension declares broad optional host access for this purpose. If you do not grant the origin
through policy, the endpoint must instead return permissive CORS headers, including a response to the preflight, because
a POST with a JSON body and an `Authorization` header is not a simple request.

## Events payload

```json
{
  "kind": "events",
  "schemaVersion": 1,
  "sentAt": 1700000000000,
  "deviceTag": "laptop-4821",
  "siteId": "acme-hq",
  "version": "2.0.6",
  "events": [
    {
      "id": "1c2f9d0e-5a3b-4c6d-9e7f-0a1b2c3d4e5f",
      "ts": 1699999999000,
      "type": "block",
      "action": null,
      "url": "https://phish.example/login",
      "providerId": "openphish",
      "verdict": "PHISHING",
      "deviceTag": "laptop-4821",
      "siteId": "acme-hq",
      "version": "2.0.6"
    }
  ]
}
```

The envelope fields are:

- `kind` is always `events` for this message.
- `schemaVersion` is the event schema version, currently `1`.
- `sentAt` is the epoch time in milliseconds when the batch was sent.
- `deviceTag` and `siteId` come from the policies of the same name and identify the endpoint and the client
  organization. They are empty strings when unset.
- `version` is the extension version.
- `events` is the batch, oldest first.

Each event carries:

- `id` is a stable unique identifier for deduplication.
- `ts` is the epoch time in milliseconds when the event occurred.
- `type` is `block` for a detection or `bypass` for a user override.
- `action` names the override for a bypass, either `continueToWebsite` or `allowWebsite`, and is `null` for a detection.
- `url` is the canonical URL that was flagged.
- `providerId` is the id of the provider that flagged the URL, or `null` when none applies.
- `verdict` is the provider verdict, such as `PHISHING` or `MALICIOUS`, or `null` when none applies.
- `deviceTag`, `siteId`, and `version` repeat the endpoint identity captured when the event was recorded.

## Heartbeat payload

```json
{
  "kind": "heartbeat",
  "schemaVersion": 1,
  "sentAt": 1700000000000,
  "installed": true,
  "enabled": true,
  "version": "2.0.6",
  "deviceTag": "laptop-4821",
  "siteId": "acme-hq",
  "proxyOrigin": "https://api.osprey.ac",
  "proxyReachable": true
}
```

The heartbeat fields are:

- `kind` is always `heartbeat` for this message.
- `schemaVersion` matches the event schema version.
- `sentAt` is the epoch time in milliseconds when the heartbeat was sent.
- `installed` and `enabled` are always `true` in a heartbeat, because only a running extension can send one. Their
  absence, meaning a missing heartbeat, is the real signal that an endpoint is gone.
- `version` is the extension version, so an MSP can see which build each endpoint runs.
- `deviceTag` and `siteId` identify the endpoint and the client organization.
- `proxyOrigin` is the backend origin the extension would send lookups to, which is the `ProxyBaseUrl` policy value when
  set and the default public backend otherwise.
- `proxyReachable` is `true` when the extension received any HTTP response from `proxyOrigin`, and `false` when the
  request failed or timed out. It reports whether the endpoint can reach its configured backend, independent of whether
  any single lookup succeeds.
