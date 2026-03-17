# Privacy Policy

**Effective Date:** 03/16/2026

Osprey: Browser Protection is committed to protecting your privacy. This Privacy Policy explains what data is processed
when you use the extension, why, and how. URL checking is the core security function of the extension. When you
navigate to a website, Osprey may send the URL to threat intelligence or DNS filtering services to determine whether
the destination is malicious or inappropriate. This processing is limited to what is necessary for that purpose.

## What Data Is Processed and Why

For DNS-based providers (AdGuard DNS, CERT-EE, CleanBrowsing, Cloudflare, Control D, Quad9, and Switch.ch), only the
hostname is sent as part of a DNS-over-HTTPS query. For API-based providers (alphaMountain and PrecisionSec), the full
URL including path is sent. These API requests are routed through Osprey's own proxy server hosted in New York, NY,
rather than directly to the provider.

The proxy does not log IP addresses in any form and does not log request bodies under normal operation. It may log the
submitted URL if an upstream provider returns a 400 response, and the hostname may appear in error output on internal
failures or blocked connection attempts. These messages are never written to disk; they exist only in the VPS's runtime
memory via journald and are lost when the server restarts. The proxy also logs aggregate request counts per provider
(requests per minute and a running total), which contain no IP addresses or URLs. The proxy source code is open-source
and [available for review on GitHub](https://github.com/OspreyProject/OspreyProxy).

Osprey does not collect browsing history, user identifiers, or analytics of any kind.

## Third-Party Recipients

When a URL is checked, the relevant third-party providers receive a network request as part of the standard HTTP
connection. Providers you have disabled in the extension's settings are not contacted.

For alphaMountain ([privacy policy](https://alphamountain.ai/privacy-policy/)) and
PrecisionSec ([privacy policy](https://precisionsec.com/privacy-policy/)), requests are routed through Osprey's proxy
server, so your IP address is not forwarded to those providers directly.

For DNS-based providers, your IP address is visible to the provider as part of the DNS-over-HTTPS query. These providers
are AdGuard DNS ([privacy policy](https://adguard-dns.io/en/privacy.html)),
CERT-EE ([privacy policy](https://ria.ee/en/authority-news-and-contact/processing-personal-data)),
CleanBrowsing ([privacy policy](https://cleanbrowsing.org/privacy)),
Cloudflare ([privacy policy](https://cloudflare.com/privacypolicy)),
Control D ([privacy policy](https://controld.com/privacy)),
Quad9 ([privacy policy](https://quad9.net/privacy/policy)),
and Switch.ch ([privacy policy](https://switch.ch/en/data-protection)).

Osprey also fetches local filtering lists from GitHub every 5 minutes to stay current. These requests are made to
GitHub's CDN (operated by Microsoft), which receives your IP address as part of the connection. The lists are
Phishing.Database and PhishDestroy. GitHub's privacy policy applies to these requests and is available
at [GitHub's General Privacy Statement](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement).

## Browser Permissions

Osprey requires several browser permissions to function. The tabs permission is used to detect navigation events and
apply protection. The storage permission is used to cache results locally and persist your settings. The webNavigation
permission is used to intercept page navigations before they complete. The notifications permission is used to alert you
when a malicious website is blocked. The contextMenus permission is used to provide the right-click menu options. The
host permissions entry covering all URLs is used to inspect navigated URLs across all websites.

These permissions are used strictly for the security features described above and are not used to collect or transmit
personal information.

## Data Stored Locally

Osprey stores several categories of data in your browser's local extension storage. It stores a URL cache containing
domains that have been checked, along with their result and an expiration time; this data never leaves your device
except as part of normal URL checking. It also stores your protection preferences, such as which providers are enabled,
and the downloaded local filtering lists from PhishDestroy and Phishing.Database. All locally stored data is cleared
when you uninstall the extension.

## Data Retention

Local extension data is retained until you uninstall the extension or clear it manually via the context menu. Any
error-case proxy server log messages exist only in the VPS's runtime memory via journald and are never written to disk;
they are lost when the server restarts and are not retained in any form. Aggregate request counts are retained
indefinitely but contain no personal data.

## Changes to This Privacy Policy

We may update this Privacy Policy from time to time. The effective date at the top of this page reflects the date of the
most recent revision. We encourage you to review this page periodically.

## Contact

For privacy-related questions, contact us at **support@osprey.ac**.
