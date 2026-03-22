# Privacy Policy

**Effective Date:** 03/22/2026

Osprey: Browser Protection and the team behind [OspreyProject](https://github.com/OspreyProject) is committed to
protecting your privacy. This Privacy Policy explains what data is processed when you use the extension, why, and how.

Osprey consists of two components:

- The **browser extension**, which runs locally on your device.
- The **proxy server** (OspreyProxy), which runs on a VPS hosted in New York, NY
  at [api.osprey.ac](https://api.osprey.ac).

Understanding which component does what is important for understanding how your data is handled.

## What Data Is Processed and Why

URL checking is the core security function of the browser extension. When you navigate to a website, the browser
extension sends the URL to the proxy server, which checks it against threat intelligence providers, DNS filtering
services, and local threat intelligence lists to determine whether the URL is unsafe.

The browser extension sends the full URL to the proxy server for all checks. How the proxy server handles it depends
on the provider type:

- **DNS-based providers** (AdGuard DNS, CERT-EE, CleanBrowsing, Cloudflare, Control D, Quad9, and Switch.ch): the
  proxy server extracts only the hostname and submits it as a DNS-over-HTTPS query.
- **API-based providers** (alphaMountain and PrecisionSec): the proxy server forwards the full URL including path.
- **Local threat intelligence lists**: the proxy server checks the hostname against its own in-memory domain sets
  without making any external requests.

In all cases, your IP address is never forwarded to any provider directly; providers see only the proxy server's IP
address.

The proxy server does not log IP addresses in any form and does not log request bodies under normal operation. It may
log the submitted URL if an upstream provider returns a 400 response, and the hostname may appear in error output on
internal failures or blocked connection attempts. These messages are never written to disk; they exist only in the
VPS's runtime memory via journald and are lost when the server restarts. The proxy server also logs aggregate request
counts per provider (requests per minute and a running total), which contain no IP addresses or URLs. The proxy
server's source code is open-source and [available for review on GitHub](https://github.com/OspreyProject/OspreyProxy).

The proxy server does not collect browsing history, user identifiers, or analytics of any kind. The browser extension
stores visited URLs locally in your browser as part of its caching system and does not transmit this cached data
anywhere; this is described further in the Data Stored Locally section below.

## Third-Party Recipients

When a URL is checked, the browser extension sends it to the proxy server, which then contacts the relevant
third-party providers on your behalf. Providers you have disabled in the browser extension's settings are not
contacted. Because all provider requests originate from the proxy server rather than your device, third-party
providers never receive your IP address.

- **API-based providers** receive the full URL:
    - alphaMountain ([privacy policy](https://alphamountain.ai/privacy-policy/))
    - PrecisionSec ([privacy policy](https://precisionsec.com/privacy-policy/))
- **DNS-based providers** receive only the hostname as part of a DNS-over-HTTPS query:
    - AdGuard DNS ([privacy policy](https://adguard-dns.io/en/privacy.html))
    - CERT-EE ([privacy policy](https://ria.ee/en/authority-news-and-contact/processing-personal-data))
    - CleanBrowsing ([privacy policy](https://cleanbrowsing.org/privacy))
    - Cloudflare ([privacy policy](https://cloudflare.com/privacypolicy))
    - Control D ([privacy policy](https://controld.com/privacy))
    - Quad9 ([privacy policy](https://quad9.net/privacy/policy))
    - Switch.ch ([privacy policy](https://switch.ch/en/data-protection))
- **Local threat intelligence lists** are checked entirely within the proxy server and involve no external requests.

## Browser Permissions

The browser extension requires several permissions to function:

- `tabs`: used to detect navigation events and apply protection.
- `storage`: used to cache results locally on your device and persist your settings.
- `webNavigation`: used to intercept page navigations before they complete.
- `notifications`: used to alert you when a malicious website is blocked.
- `contextMenus`: used to provide the right-click menu options.
- `host` permissions covering all URLs: used to inspect navigated URLs across all websites.

These permissions are used strictly for the security features described above and are not used to collect or transmit
personal information.

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

## Data Retention

Local extension data is retained until you uninstall the browser extension or clear it manually via the context menu.
Any error-case log messages on the proxy server exist only in the VPS's runtime memory via journald and are never
written to disk; they are lost when the server restarts and are not retained in any form. Aggregate request counts on
the proxy server are retained indefinitely but contain no personal data.

## Changes to This Privacy Policy

We may update this Privacy Policy from time to time. The effective date at the top of this page reflects the date of
the most recent revision. We encourage you to review this page periodically.

## Contact

For privacy-related questions, contact us at **support@osprey.ac**.
