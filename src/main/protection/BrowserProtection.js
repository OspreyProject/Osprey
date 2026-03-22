/*
 * Osprey - a browser extension that protects you from malicious websites.
 * Copyright (C) 2026 Osprey Project (https://github.com/OspreyProject)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
"use strict";

// Main object for managing browser protection functionality
const BrowserProtection = (() => {

    // Global variable for browser API compatibility
    const browserAPI = globalThis.chrome ?? globalThis.browser;

    // Map to store AbortControllers for each tab
    let tabAbortControllers = new Map();

    // Default request timeout in milliseconds (10 seconds)
    const REQUEST_TIMEOUT_MS = 10000;

    // Maximum number of tab abort controllers to prevent unbounded map growth
    const MAX_TAB_CONTROLLERS = 500;

    // Base URL for the local proxy server
    const PROXY_BASE_URL = "https://api.osprey.ac";

    /**
     * Descriptor table for all proxy-backed providers.
     * Each entry declares the settings key that enables the provider, its origin
     * constant, and the endpoint path on the local proxy.
     *
     * Whether the provider checks by full URL or hostname-only is indicated by
     * `useHostname`: true means cache lookups and processing cache use urlHostnameObject,
     * false means they use urlObject (the full URL).
     */
    const PROVIDER_DESCRIPTORS = [
        // Official Partners
        {
            settingsKey: "adGuardSecurityEnabled",
            origin: ProtectionResult.Origin.ADGUARD_SECURITY,
            endpoint: "adguard-security",
            useHostname: true
        },
        {
            settingsKey: "adGuardFamilyEnabled",
            origin: ProtectionResult.Origin.ADGUARD_FAMILY,
            endpoint: "adguard-family",
            useHostname: true
        },
        {
            settingsKey: "alphaMountainEnabled",
            origin: ProtectionResult.Origin.ALPHAMOUNTAIN,
            endpoint: "alphamountain",
            useHostname: false
        },
        {
            settingsKey: "precisionSecEnabled",
            origin: ProtectionResult.Origin.PRECISIONSEC,
            endpoint: "precisionsec",
            useHostname: false
        },

        // Non-Partnered Providers
        {
            settingsKey: "certEEEnabled",
            origin: ProtectionResult.Origin.CERT_EE,
            endpoint: "cert-ee",
            useHostname: true
        },
        {
            settingsKey: "cleanBrowsingSecurityEnabled",
            origin: ProtectionResult.Origin.CLEANBROWSING_SECURITY,
            endpoint: "cleanbrowsing-security",
            useHostname: true
        },
        {
            settingsKey: "cleanBrowsingFamilyEnabled",
            origin: ProtectionResult.Origin.CLEANBROWSING_FAMILY,
            endpoint: "cleanbrowsing-family",
            useHostname: true
        },
        {
            settingsKey: "cloudflareSecurityEnabled",
            origin: ProtectionResult.Origin.CLOUDFLARE_SECURITY,
            endpoint: "cloudflare-security",
            useHostname: true
        },
        {
            settingsKey: "cloudflareFamilyEnabled",
            origin: ProtectionResult.Origin.CLOUDFLARE_FAMILY,
            endpoint: "cloudflare-family",
            useHostname: true
        },
        {
            settingsKey: "controlDSecurityEnabled",
            origin: ProtectionResult.Origin.CONTROL_D_SECURITY,
            endpoint: "controld-security",
            useHostname: true
        },
        {
            settingsKey: "controlDFamilyEnabled",
            origin: ProtectionResult.Origin.CONTROL_D_FAMILY,
            endpoint: "controld-family",
            useHostname: true
        },
        {
            settingsKey: "phishDestroyEnabled",
            origin: ProtectionResult.Origin.PHISH_DESTROY,
            endpoint: "phishdestroy",
            useHostname: true
        },
        {
            settingsKey: "phishingDatabaseEnabled",
            origin: ProtectionResult.Origin.PHISHING_DATABASE,
            endpoint: "phishing-database",
            useHostname: true
        },
        {
            settingsKey: "quad9Enabled",
            origin: ProtectionResult.Origin.QUAD9,
            endpoint: "quad9",
            useHostname: true
        },
        {
            settingsKey: "switchCHEnabled",
            origin: ProtectionResult.Origin.SWITCH_CH,
            endpoint: "switch-ch",
            useHostname: true
        },
    ];

    /**
     * Creates an AbortSignal that times out after the specified duration.
     * Combines with an existing signal if provided.
     *
     * @param {AbortSignal} existingSignal An existing abort signal to combine with.
     * @param {number} timeoutMs Timeout in milliseconds.
     * @returns {AbortSignal} The combined abort signal.
     */
    const createTimeoutSignal = (existingSignal, timeoutMs = REQUEST_TIMEOUT_MS) => {
        const timeoutController = new AbortController();
        const timeoutId = setTimeout(() => timeoutController.abort('Request timeout'), timeoutMs);

        // Return a signal that aborts if either the timeout or existing signal aborts
        if (existingSignal) {
            if (existingSignal.aborted) {
                clearTimeout(timeoutId);
                return existingSignal;
            }

            const combinedController = new AbortController();

            existingSignal.addEventListener('abort', () => {
                clearTimeout(timeoutId);
                combinedController.abort(existingSignal.reason);
            }, {once: true});

            timeoutController.signal.addEventListener('abort', () => {
                clearTimeout(timeoutId);
                combinedController.abort('Request timeout');
            }, {once: true});
            return combinedController.signal;
        }
        return timeoutController.signal;
    };

    /**
     * Cleans up controllers for tabs that no longer exist.
     */
    const cleanupTabControllers = () => {
        // Remove controllers for tabs that no longer exist
        browserAPI.tabs.query({}, tabs => {
            if (browserAPI.runtime.lastError) {
                console.debug(`tabs.query failed: ${browserAPI.runtime.lastError.message}`);
                return;
            }

            const activeTabIds = new Set(tabs.map(tab => tab.id));
            const toDelete = [];

            for (const tabId of tabAbortControllers.keys()) {
                if (!activeTabIds.has(tabId)) {
                    toDelete.push(tabId);
                }
            }

            for (const tabId of toDelete) {
                tabAbortControllers.delete(tabId);
                console.debug(`Removed controller for tab ID: ${tabId}`);
            }
        });
    };

    /**
     * Abandons all pending requests for a specific tab.
     *
     * @param {number} tabId The ID of the tab for which to abandon requests.
     * @param {string} reason The reason for abandoning the requests.
     */
    const abandonPendingRequests = (tabId, reason) => {
        if (tabAbortControllers.has(tabId)) {
            tabAbortControllers.get(tabId).abort(reason);
            tabAbortControllers.delete(tabId);
        }
    };

    /**
     * Dispatches a proxy result string to the appropriate cache update and callback.
     * Shared by both provider and local list checks.
     *
     * @param {string} result The result string from the proxy response.
     * @param {string} urlString The URL that was checked.
     * @param {URL} urlObject The parsed URL object (used for full-URL cache writes).
     * @param {string} cacheName The cache name for this provider.
     * @param {string} origin The origin constant for this provider.
     * @param {string} shortName The short display name for logging.
     * @param {Response} filteringResponse The raw fetch response (used for status logging on "failed").
     * @param {function} callback The result callback.
     * @param {*} data The raw parsed response data (used for unexpected-result logging).
     */
    const dispatchResult = (result, urlString, urlObject, cacheName, origin,
                            shortName, filteringResponse, callback, data) => {
        switch (result) {
            case "failed":
                console.warn(`[${shortName}] Invalid status received: ${filteringResponse.status}`);
                CacheManager.removeUrlFromProcessingCache(cacheObject, cacheName);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.FAILED, origin));
                return;

            case "allowed":
                console.debug(`[${shortName}] Added URL to allowed cache: ${urlString}`);
                CacheManager.addUrlToAllowedCache(urlObject, cacheName);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.ALLOWED, origin));
                return;

            case "malicious":
                console.debug(`[${shortName}] Added URL to blocked cache: ${urlString}`);
                CacheManager.addUrlToBlockedCache(urlObject, cacheName, ProtectionResult.ResultType.MALICIOUS);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.MALICIOUS, origin));
                return;

            case "phishing":
                console.debug(`[${shortName}] Added URL to blocked cache: ${urlString}`);
                CacheManager.addUrlToBlockedCache(urlObject, cacheName, ProtectionResult.ResultType.PHISHING);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.PHISHING, origin));
                return;

            case "untrusted":
                console.debug(`[${shortName}] Added URL to blocked cache: ${urlString}`);
                CacheManager.addUrlToBlockedCache(urlObject, cacheName, ProtectionResult.ResultType.UNTRUSTED);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.UNTRUSTED, origin));
                return;

            case "adult_content":
                console.debug(`[${shortName}] Added URL to blocked cache: ${urlString}`);
                CacheManager.addUrlToBlockedCache(urlObject, cacheName, ProtectionResult.ResultType.ADULT_CONTENT);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.ADULT_CONTENT, origin));
                return;

            default:
                console.warn(`[${shortName}] Returned an unexpected result for URL ${urlString}: ${data}`);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.ALLOWED, origin));
        }
    };

    /**
     * Checks if a URL is malicious or trusted.
     *
     * @param {number} tabId The ID of the tab that initiated the request.
     * @param {string} urlString The URL to check.
     * @param {function} callback The callback function to handle the result.
     */
    const checkIfUrlIsMalicious = async (tabId, urlString, callback) => {
        if (typeof callback !== 'function') {
            console.error('checkIfUrlIsMalicious: callback must be a function');
            return;
        }

        if (!Number.isInteger(tabId) || tabId <= 0) {
            console.error(`checkIfUrlIsMalicious: invalid tabId: ${tabId}`);
            return;
        }

        // Parses the URL object
        let urlObject;
        try {
            urlObject = new URL(urlString);
        } catch (error) {
            console.warn(`Invalid URL format: ${error.message}`);
            return;
        }

        // Checks if the URL is missing a hostname
        if (!urlObject.hostname) {
            console.warn(`Invalid URL, missing hostname: ${urlString}`);
            return;
        }

        const urlHostname = urlObject.hostname;

        // Reconstructs a new URL with just the hostname
        let urlHostnameObject;
        try {
            urlHostnameObject = new URL(`https://${urlHostname}`);
        } catch (error) {
            console.warn(`Invalid URL hostname format: ${error.message}`);
            return;
        }

        // Encodes the URL components for use in API requests
        const encodedURLHostname = encodeURIComponent(urlHostname);

        // The non-filtering URL used for DNS lookups
        const nonFilteringURL = `https://cloudflare-dns.com/dns-query?name=${encodedURLHostname}`;

        // Other Cloudflare Resolver information
        const origin = ProtectionResult.Origin.CLOUDFLARE_RESOLVER;
        const shortName = ProtectionResult.ShortName[origin];
        const cacheName = ProtectionResult.CacheName[origin];

        // Ensures there is an AbortController for the tab
        if (!tabAbortControllers.has(tabId)) {
            if (tabAbortControllers.size >= MAX_TAB_CONTROLLERS) {
                const oldestTabId = tabAbortControllers.keys().next().value;
                tabAbortControllers.get(oldestTabId).abort('Controller evicted due to map size limit');
                tabAbortControllers.delete(oldestTabId);
                console.warn(`tabAbortControllers map at capacity; evicted oldest entry for tab ${oldestTabId}.`);
            }

            tabAbortControllers.set(tabId, new AbortController());
        }

        // Gets the signal from the current AbortController
        const {signal} = tabAbortControllers.get(tabId);

        // Make a validation request with Cloudflare before querying other providers
        // Only proceed if the domain is valid and online to avoid unnecessary requests
        if (!CacheManager.isUrlInAllowedCache(urlHostnameObject, cacheName)) {

            // Checks if the URL is already being validated by another in-flight request
            if (CacheManager.isUrlInProcessingCache(urlHostnameObject, cacheName)) {
                console.debug(`[${shortName}] URL is already processing: ${urlString}`);
                return;
            }

            // Adds the URL to the processing cache to prevent duplicate validation requests
            CacheManager.addUrlToProcessingCache(urlHostnameObject, cacheName, tabId);
            console.debug(`[${shortName}] URL is not in allowed cache, validating with non-filtering resolver: ${urlHostname}`);

            try {
                const nonFilteringResponse = await fetch(nonFilteringURL, {
                    method: "GET",
                    headers: {
                        "Accept": "application/dns-json"
                    },
                    signal: createTimeoutSignal(signal)
                });

                const validContentType = Validate.hasValidContentType(nonFilteringResponse, 'application/dns-json');

                // Checks if the domain is offline
                if (nonFilteringResponse.ok && validContentType) {
                    const nonFilteringData = await nonFilteringResponse.json();
                    const {Status, Answer} = nonFilteringData;

                    // Adds the URL to the allowed cache if the domain resolves
                    if (Status === 0 && Answer && Answer.length > 0) {
                        console.debug(`[${shortName}] Response status is ${Status}; adding to allowed cache...`);
                        CacheManager.addUrlToAllowedCache(urlHostnameObject, cacheName);
                        CacheManager.removeUrlFromProcessingCache(urlHostnameObject, cacheName);
                    } else {
                        console.debug(`[${shortName}] Domain appears to be offline (${urlHostname})`);
                        CacheManager.removeUrlFromProcessingCache(urlHostnameObject, cacheName);
                        return;
                    }
                } else {
                    console.warn(`[${shortName}] Invalid resolver response received: ${nonFilteringResponse.ok} - ${validContentType}`);
                    CacheManager.removeUrlFromProcessingCache(urlHostnameObject, cacheName);
                    return;
                }
            } catch (error) {
                console.debug(`[${shortName}] Failed to validate domain '${urlString}': ${error}`);
                CacheManager.removeUrlFromProcessingCache(urlHostnameObject, cacheName);
                return;
            }
        }

        /**
         * Checks the URL against a single proxy-backed provider.
         * All provider-specific behavior is declared in PROVIDER_DESCRIPTORS above;
         * this function contains only the shared fetch-and-dispatch logic.
         *
         * @param {Object} descriptor An entry from PROVIDER_DESCRIPTORS.
         * @param {Object} settings The settings object containing user preferences.
         */
        const checkUrlWithProvider = async (descriptor, settings) => {
            if (!settings[descriptor.settingsKey]) {
                return;
            }

            const {origin, endpoint, useHostname} = descriptor;
            const shortName = ProtectionResult.ShortName[origin];
            const cacheName = ProtectionResult.CacheName[origin];

            // Use the hostname-only object for DNS providers, full URL object for API providers
            const cacheObject = useHostname ? urlHostnameObject : urlObject;

            // Checks if the URL is in the allowed cache
            if (CacheManager.isUrlInAllowedCache(cacheObject, cacheName)) {
                console.debug(`[${shortName}] URL is already allowed: ${urlString}`);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.KNOWN_SAFE, origin));
                return;
            }

            // Checks if the URL is in the blocked cache
            if (CacheManager.isUrlInBlockedCache(cacheObject, cacheName)) {
                console.debug(`[${shortName}] URL is already blocked: ${urlString}`);
                callback(new ProtectionResult(urlString, CacheManager.getBlockedResultType(cacheObject, cacheName), origin));
                return;
            }

            // Checks if the URL is in the processing cache
            if (CacheManager.isUrlInProcessingCache(cacheObject, cacheName)) {
                console.debug(`[${shortName}] URL is already processing: ${urlString}`);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.WAITING, origin));
                return;
            }

            // Adds the URL to the processing cache to prevent duplicate requests
            CacheManager.addUrlToProcessingCache(cacheObject, cacheName, tabId);

            try {
                const filteringResponse = await fetch(`${PROXY_BASE_URL}/${endpoint}`, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                    },
                    body: JSON.stringify({url: urlString}),
                    signal: createTimeoutSignal(signal)
                });

                // Checks if the response status is valid
                if (!filteringResponse.ok) {
                    console.warn(`[${shortName}] Invalid status received: ${filteringResponse.status}`);
                    CacheManager.removeUrlFromProcessingCache(cacheObject, cacheName); // add this
                    callback(new ProtectionResult(urlString, ProtectionResult.ResultType.FAILED, origin));
                    return;
                }

                // Checks if the Content-Type is valid
                if (!Validate.hasValidContentType(filteringResponse, 'application/json')) {
                    console.warn(`[${shortName}] Unexpected Content-Type: ${filteringResponse.headers.get('Content-Type')}`);
                    CacheManager.removeUrlFromProcessingCache(cacheObject, cacheName); // add this
                    callback(new ProtectionResult(urlString, ProtectionResult.ResultType.FAILED, origin));
                    return;
                }

                const data = await filteringResponse.json();
                const {result} = data;

                dispatchResult(result, urlString, urlObject, cacheName, origin, shortName, filteringResponse, callback, data);
            } catch (error) {
                console.debug(`[${shortName}] Failed to check URL: ${error}`);
                CacheManager.removeUrlFromProcessingCache(cacheObject, cacheName);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.FAILED, origin));
            }
        };

        // Call all the check functions asynchronously
        Settings.get(settings => {
            if (!settings || typeof settings !== 'object') {
                console.error('checkIfUrlIsMalicious: Settings.get returned invalid settings; aborting all checks.');
                return;
            }

            // Proxy-backed providers
            for (const descriptor of PROVIDER_DESCRIPTORS) {
                checkUrlWithProvider(descriptor, settings);
            }
        });
    };

    return Object.freeze({
        abandonPendingRequests,
        checkIfUrlIsMalicious,
        cleanupTabControllers,
    });
})();
