# Privacy Policy

**Effective Date:** 04/07/2026

Osprey: Browser Protection and the team behind [OspreyProject](https://github.com/OspreyProject) is committed to
protecting your privacy. This Privacy Policy explains what data is processed when you use the current browser
extension and its supporting proxy service, why that data is processed, and how it is handled.

The current Osprey service described in this Privacy Policy consists of two components:

- The **browser extension**, which runs locally on your device.
- The **proxy server** (OspreyProxy), which runs on a VPS hosted in New York, NY
  at [api.osprey.ac](https://api.osprey.ac).

This Privacy Policy applies to the current free browser extension and the OspreyProxy service described below. If Osprey
introduces additional products or an enterprise plan in the future, we may provide a separate privacy policy or a
supplemental notice describing the data practices for those services.

Understanding which component does what is important for understanding how your data is handled.

## What Data Is Processed and Why

URL checking is the core security function of the browser extension. When you navigate to a website, the browser
extension sends the URL to the proxy server, which checks it against threat intelligence providers, DNS filtering
services, and local threat intelligence lists to determine whether the URL is unsafe.

The browser extension sends the full URL to the proxy server for all checks. How the proxy server handles it depends
on the provider type:

- **DNS-based providers** (AdGuard DNS, CERT-EE, CleanBrowsing, Cloudflare, Control D, Quad9, and Switch.ch): the proxy server
  extracts only the hostname and submits it as a DNS-over-HTTPS query.
- **API-based providers** (AlphaMountain, ChainPatrol, and PrecisionSec): the proxy server forwards the full URL,
  including path.
- **Local threat intelligence lists**: the proxy server checks the hostname against its own in-memory domain sets.
  These lookups do not make per-request external calls, but the proxy server periodically refreshes those lists from
  third-party list sources.

In all cases, your IP address is not forwarded to third-party providers directly; providers see only the proxy
server's IP address.

The proxy server processes the client IP address to apply abuse protections such as rate limiting and invalid-request
blocking. For those purposes, the proxy converts the client IP address into an HMAC-hashed identifier and uses that
hashed value in memory. Osprey does not intentionally store raw client IP addresses in application-level rate-limit
state, and does not write raw client IP addresses to disk as part of its normal proxy operation.

The proxy server does not log request bodies under normal operation. It may log limited technical and operational
information needed to run and secure the service, such as provider names, response status codes, exception types,
rate-limit events, and invalid-request events. Some transient runtime logs may remain in memory on the VPS through the
system logging environment and may be lost on restart.

The proxy server does not collect user profiles, advertising identifiers, or analytics about individual users' browsing
behavior. The browser extension stores visited URLs locally in your browser as part of its caching system and does not
transmit this cached data anywhere; this is described further in the Data Stored Locally section below.

## Third-Party Recipients

When a URL is checked, the browser extension sends it to the proxy server, which then contacts the relevant
third-party providers on your behalf. Providers you have disabled in the browser extension's settings are not
contacted. Because all provider requests originate from the proxy server rather than your device, third-party
providers never receive your IP address from the browser extension's lookup request.

- **API-based providers** receive the full URL:
    - AlphaMountain ([privacy policy](https://alphamountain.ai/privacy-policy/))
    - ChainPatrol ([privacy policy](https://chainpatrol.com/legal/privacy))
    - PrecisionSec ([privacy policy](https://precisionsec.com/privacy-policy/))
- **DNS-based providers** receive only the hostname as part of a DNS-over-HTTPS query:
    - AdGuard DNS ([privacy policy](https://adguard-dns.io/en/privacy.html))
    - CERT-EE ([privacy policy](https://ria.ee/en/authority-news-and-contact/processing-personal-data))
    - CleanBrowsing ([privacy policy](https://cleanbrowsing.org/privacy))
    - Cloudflare ([privacy policy](https://cloudflare.com/privacypolicy))
    - Control D ([privacy policy](https://controld.com/privacy))
    - Quad9 ([privacy policy](https://quad9.net/privacy/policy))
    - Switch.ch ([privacy policy](https://switch.ch/en/data-protection))
- **Third-party list sources** may periodically provide updates for local threat intelligence lists used by the proxy
  server. Those refreshes are performed by the proxy server and are separate from individual user lookup requests.

## Browser Permissions

The browser extension requires several permissions to function:

- `tabs`: used to detect navigation events and apply protection.
- `storage`: used to cache results locally on your device and persist your settings.
- `webNavigation`: used to intercept page navigations before they complete.
- `notifications`: used to alert you when a malicious website is blocked.
- `contextMenus`: used to provide the right-click menu options.
- `host` permissions covering all URLs: used to inspect navigated URLs across all websites.

These permissions are used strictly for the security features described above and are not used to collect or transmit
personal information except as described in this Privacy Policy.

## Data Stored Locally

The browser extension stores several categories of data in your browser's local extension storage and session storage.
None of this data is transmitted to the proxy server or any third party.

- An **allowed cache** (local storage) containing URLs that have been checked and found safe, keyed per provider, each
  with an expiration time.
- A **blocked cache** (local storage) containing URLs that have been flagged, keyed per provider, each with an
  expiration time and the result type (such as malicious or phishing).
- A **processing cache** (session storage) tracking URLs that are currently being checked, to prevent duplicate
  requests. This cache is cleared when the browser session ends.
- Your **protection preferences** (local storage), such as which providers are enabled and your cache expiration
  settings.

All data in local storage is cleared when you uninstall the browser extension or manually via the context menu.

## Operational Analytics and Monitoring

Osprey uses limited operational observability tooling to monitor the health, stability, and capacity of the proxy
service. This may include metrics collected through **Micrometer** and exposed to **Prometheus**, with dashboards or
visualization through **Grafana**.

These operational metrics are used for service reliability, security, abuse prevention, troubleshooting, and capacity
planning. They are not used for advertising, cross-site tracking, or building marketing profiles about individual
users.

Depending on the metric, operational data may include aggregated counts such as requests handled by provider, cache
hits and misses, request-rate peaks, health or circuit-breaker state, and other system-performance indicators. Osprey
seeks to avoid storing raw client IP addresses in these operational metrics.

## Data Retention

Local extension data is retained until you uninstall the browser extension or clear it manually via the context menu.

Within the proxy service, some in-memory operational data may exist only temporarily, including hashed IP-based
rate-limit state, local-list snapshots, transient runtime logs, and short-lived counters. Operational metrics and
aggregate service telemetry may be retained for longer periods in monitoring systems such as Prometheus and Grafana,
subject to the retention settings of those systems. These records are intended for service operations and do not
include raw request bodies.

## Changes to This Privacy Policy

We may update this Privacy Policy from time to time. The effective date at the top of this page reflects the date of
the most recent revision. We encourage you to review this page periodically.

## Contact

For privacy-related questions, contact us at **support@osprey.ac**.
