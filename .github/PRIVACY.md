# Privacy Policy

**Effective Date:** 06/13/2026

Osprey: Browser Protection is committed to protecting your privacy. This Privacy Policy explains what data is processed
when you use the Osprey browser extension and its supporting proxy service, and how it is handled.

Osprey consists of two components:

- The **browser extension**, which runs locally on your device
- The **proxy server**, hosted in New York, NY at [api.osprey.ac](https://api.osprey.ac)

## How URL Checking Works

When you navigate to a website, the browser extension sends the URL to the proxy server, which checks it against threat
intelligence providers, DNS filtering services, and local threat intelligence lists.

**Providers never see which specific websites you visit.** All checks are routed through the proxy server, so providers
only ever see requests originating from the proxy's IP address, not yours. Thousands of users' checks are mixed together
from a single IP, making it practically impossible for any provider to associate a URL lookup with you specifically.

**Most URLs are never sent to providers at all.** The proxy server maintains a cache of previously checked URLs. If a
URL has already been recently evaluated, the result is returned from cache without contacting any provider.

When a URL does reach a provider, the data sent depends on the provider type:

- **DNS-based providers** receive only the hostname (never the full URL or path)
- **API-based providers** receive the full URL with query parameters stripped
- **Local threat intelligence lists** are checked entirely in-memory on the proxy server with no external calls per
  request

## Your IP Address

The proxy server uses your IP address **solely for abuse protections** such as rate limiting. For this purpose, your IP
is immediately hashed and stored in-memory. Raw IP addresses are not written to disk as part of normal proxy operation.

## Third-Party Integrations

If you configure a provider using your own API key, that provider receives requests directly from your device rather
than through the proxy server. The privacy protections described above (IP shielding and caching) **do not apply** to
those integrations. You are subject to that provider's own data handling practices when using a personal API key.

## Browser Permissions

The extension requires the following permissions, used strictly for its security features:

- `tabs`: detects tab navigation events
- `webNavigation`: detects web navigation events
- `storage`: caches results locally and persists your settings
- `host permissions for all URLs`: inspects navigated URLs across all websites

## Data Stored Locally

The extension stores the following data in your browser's local storage. None of it is transmitted to the proxy server
or any third party.

- **Allowed cache**: URLs checked and found safe, stored per provider with an expiration time
- **Blocked cache**: URLs that were flagged, stored per provider with an expiration time and threat type
- **Processing cache** (session storage): URLs currently being checked, to prevent duplicate requests
- **Your settings**: enabled providers, cache expiration preferences, and other protection settings

All local storage data is cleared when you uninstall the extension, or when you clear the list of allowed websites
using the settings page.

## Operational Monitoring

The proxy server uses standard operational tooling (Micrometer, Prometheus, Grafana) to monitor service health,
stability, and capacity. Metrics include aggregated counts such as requests per provider, cache hit/miss rates, and
system performance indicators. This data is used solely for service reliability and abuse prevention, not for
advertising or user profiling.

## Data Retention

On the proxy server, rate-limit states, local list snapshots, and transient runtime logs exist only in memory and may be
lost on restart. Aggregated operational metrics may be retained longer in Prometheus/Grafana subject to those systems'
retention settings.

## Changes to This Policy

We may update this Privacy Policy from time to time. The effective date at the top reflects the most recent revision.

## Contact

For privacy-related questions, contact us at support@osprey.ac.
