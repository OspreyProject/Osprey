/*
 * Osprey - a browser extension that protects you from malicious websites.
 * Copyright (C) 2025 Foulest (https://github.com/Foulest)
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

    // Browser API compatibility between Chrome and Firefox
    const browserAPI = globalThis.chrome ?? globalThis.browser;

    // Delay in milliseconds for non-partnered providers
    const nonPartnerDelay = 100;

    // API keys for various protection services
    // These aren't meant to be secret, but they are obfuscated to stop secret sniffers.
    let alphaMountainKey = atob("NjkyZDE1MzItZTRmYy00MjFmLWJkMzYtZGFmMGNjYzZlMTFi");
    let precisionSecKey = atob("MGI1Yjc2MjgtMzgyYi0xMWYwLWE1OWMtYjNiNTIyN2IxMDc2");

    // Map to store AbortControllers for each tab
    let tabAbortControllers = new Map();

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

            for (const tabId of tabAbortControllers.keys()) {
                if (!activeTabIds.has(tabId)) {
                    tabAbortControllers.delete(tabId);
                    console.debug(`Removed controller for tab ID: ${tabId}`);
                }
            }
        });
    };

    /**
     * Abandons all pending requests for a specific tab.
     *
     * @param {number} tabId - The ID of the tab for which to abandon requests.
     * @param {string} reason - The reason for abandoning the requests.
     */
    const abandonPendingRequests = (tabId, reason) => {
        if (tabAbortControllers.has(tabId)) {
            tabAbortControllers.get(tabId).abort(reason); // Abort all pending requests for the tab
            tabAbortControllers.set(tabId, new AbortController()); // Create a new controller for future requests
        }
    };

    /**
     * Checks if a URL is malicious or trusted.
     *
     * @param {number} tabId - The ID of the tab that initiated the request.
     * @param {string} urlString - The URL to check.
     * @param {function} callback - The callback function to handle the result.
     */
    const checkIfUrlIsMalicious = (tabId, urlString, callback) => {
        // Returns early if any of the parameters are missing
        if (!tabId || !urlString || !callback) {
            console.warn(`Missing parameters: tabId=${tabId}, url=${urlString}, callback=${callback}`);
            return;
        }

        let urlObject;

        // Validates the URL format
        try {
            urlObject = new URL(urlString);
        } catch (error) {
            console.warn(`Invalid URL format: ${error.message}`);
            return;
        }

        // Returns early if the URL is missing a hostname
        if (!urlObject.hostname) {
            console.warn(`Invalid URL, missing hostname: ${urlString}`);
            return;
        }

        const urlHostname = urlObject.hostname;
        let encodedDNSQuery;

        // Validates and encodes the DNS query
        try {
            encodedDNSQuery = UrlHelpers.encodeDNSQuery(urlHostname);
        } catch (error) {
            console.warn(`Failed to encode DNS query for hostname ${urlHostname}: ${error.message}`);
            return;
        }

        // Encodes the URL components for use in API requests
        const encodedURL = encodeURIComponent(urlString);
        const encodedURLHostname = encodeURIComponent(urlHostname);

        // The non-filtering URL used for DNS lookups
        const nonFilteringURL = `https://cloudflare-dns.com/dns-query?name=${encodedURLHostname}`;

        // Ensures there is an AbortController for the tab
        if (!tabAbortControllers.has(tabId)) {
            tabAbortControllers.set(tabId, new AbortController());
        }

        // Gets the signal from the current AbortController
        const {signal} = tabAbortControllers.get(tabId);

        /**
         * Checks the URL with AdGuard's Security DNS API.
         *
         * @param {Object} settings - The settings object containing user preferences.
         */
        const checkUrlWithAdGuardSecurity = async settings => {
            // Checks if the provider is enabled
            if (!settings.adGuardSecurityEnabled) {
                return;
            }

            const origin = ProtectionResult.Origin.ADGUARD_SECURITY;
            const shortName = ProtectionResult.ShortName[origin];
            const cacheName = ProtectionResult.CacheName[origin];

            // Checks if the URL is in the allowed cache
            if (CacheManager.isUrlInAllowedCache(urlObject, cacheName)) {
                console.debug(`[${shortName}] URL is already allowed: ${urlString}`);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.KNOWN_SAFE, origin));
                return;
            }

            // Checks if the URL is in the blocked cache
            if (CacheManager.isUrlInBlockedCache(urlObject, cacheName)) {
                console.debug(`[${shortName}] URL is already blocked: ${urlString}`);
                callback(new ProtectionResult(urlString, CacheManager.getBlockedResultType(urlString, cacheName), origin));
                return;
            }

            // Checks if the URL is in the processing cache
            if (CacheManager.isUrlInProcessingCache(urlObject, cacheName)) {
                console.debug(`[${shortName}] URL is already processing: ${urlString}`);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.WAITING, origin));
                return;
            }

            // Adds the URL to the processing cache to prevent duplicate requests
            CacheManager.addUrlToProcessingCache(urlObject, cacheName, tabId);

            const filteringURL = `https://dns.adguard-dns.com/dns-query?dns=${encodedDNSQuery}`;

            try {
                const filteringResponse = await fetch(filteringURL, {
                    method: "GET",
                    headers: {
                        "Accept": "application/dns-message"
                    },
                    signal
                });

                const nonFilteringResponse = await fetch(nonFilteringURL, {
                    method: "GET",
                    headers: {
                        "Accept": "application/dns-json"
                    },
                    signal
                });

                // Returns early if one or more of the responses is not OK
                if (!filteringResponse.ok || !nonFilteringResponse.ok) {
                    console.warn(`[${shortName}] Returned early: ${filteringResponse.status}`);
                    callback(new ProtectionResult(urlString, ProtectionResult.ResultType.FAILED, origin));
                    return;
                }

                const filteringData = new Uint8Array(await filteringResponse.arrayBuffer());
                const filteringDataString = Array.from(filteringData).toString();
                const nonFilteringData = await nonFilteringResponse.json();
                const {Status, Answer} = nonFilteringData;

                // Returns early if the domain is offline
                if (!(Status === 0 && Answer && Answer.length > 0)) {
                    console.warn(`[${shortName}] Returned early: domain offline`);
                    callback(new ProtectionResult(urlString, ProtectionResult.ResultType.FAILED, origin));
                    return;
                }

                // If the data matches this specific pattern, it's blocked
                if (filteringDataString.includes("0,0,1,0,1,192,12,0,1,0,1,0,0,14,16,0,4,94,140,14,3")) {
                    console.debug(`[${shortName}] Added URL to blocked cache: ${urlString}`);
                    CacheManager.addUrlToBlockedCache(urlObject, cacheName, ProtectionResult.ResultType.MALICIOUS);
                    callback(new ProtectionResult(urlString, ProtectionResult.ResultType.MALICIOUS, origin));
                    return;
                }

                // Otherwise, the domain is either invalid or not blocked
                console.debug(`[${shortName}] Added URL to allowed cache: ${urlString}`);
                CacheManager.addUrlToAllowedCache(urlObject, cacheName);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.ALLOWED, origin));
            } catch (error) {
                console.debug(`[${shortName}] Failed to check URL ${urlString}: ${error}`);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.FAILED, origin));
            }
        };

        /**
         * Checks the URL with AdGuard's Family DNS API.
         *
         * @param {Object} settings - The settings object containing user preferences.
         */
        const checkUrlWithAdGuardFamily = async settings => {
            // Checks if the provider is enabled
            if (!settings.adGuardFamilyEnabled) {
                return;
            }

            const origin = ProtectionResult.Origin.ADGUARD_FAMILY;
            const shortName = ProtectionResult.ShortName[origin];
            const cacheName = ProtectionResult.CacheName[origin];

            // Checks if the URL is in the allowed cache
            if (CacheManager.isUrlInAllowedCache(urlObject, cacheName)) {
                console.debug(`[${shortName}] URL is already allowed: ${urlString}`);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.KNOWN_SAFE, origin));
                return;
            }

            // Checks if the URL is in the blocked cache
            if (CacheManager.isUrlInBlockedCache(urlObject, cacheName)) {
                console.debug(`[${shortName}] URL is already blocked: ${urlString}`);
                callback(new ProtectionResult(urlString, CacheManager.getBlockedResultType(urlString, cacheName), origin));
                return;
            }

            // Checks if the URL is in the processing cache
            if (CacheManager.isUrlInProcessingCache(urlObject, cacheName)) {
                console.debug(`[${shortName}] URL is already processing: ${urlString}`);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.WAITING, origin));
                return;
            }

            // Adds the URL to the processing cache to prevent duplicate requests
            CacheManager.addUrlToProcessingCache(urlObject, cacheName, tabId);

            const filteringURL = `https://family.adguard-dns.com/dns-query?dns=${encodedDNSQuery}`;

            try {
                const filteringResponse = await fetch(filteringURL, {
                    method: "GET",
                    headers: {
                        "Accept": "application/dns-message"
                    },
                    signal
                });

                const nonFilteringResponse = await fetch(nonFilteringURL, {
                    method: "GET",
                    headers: {
                        "Accept": "application/dns-json"
                    },
                    signal
                });

                // Returns early if one or more of the responses is not OK
                if (!filteringResponse.ok || !nonFilteringResponse.ok) {
                    console.warn(`[${shortName}] Returned early: ${filteringResponse.status}`);
                    callback(new ProtectionResult(urlString, ProtectionResult.ResultType.FAILED, origin));
                    return;
                }

                const filteringData = new Uint8Array(await filteringResponse.arrayBuffer());
                const filteringDataString = Array.from(filteringData).toString();
                const nonFilteringData = await nonFilteringResponse.json();
                const {Status, Answer} = nonFilteringData;

                // Returns early if the domain is offline
                if (!(Status === 0 && Answer && Answer.length > 0)) {
                    console.warn(`[${shortName}] Returned early: domain offline`);
                    callback(new ProtectionResult(urlString, ProtectionResult.ResultType.FAILED, origin));
                    return;
                }

                // If the data matches this specific pattern, it's blocked
                if (filteringDataString.includes("0,0,1,0,1,192,12,0,1,0,1,0,0,14,16,0,4,94,140,14,3")) {
                    console.debug(`[${shortName}] Added URL to blocked cache: ${urlString}`);
                    CacheManager.addUrlToBlockedCache(urlObject, cacheName, ProtectionResult.ResultType.ADULT_CONTENT);
                    callback(new ProtectionResult(urlString, ProtectionResult.ResultType.ADULT_CONTENT, origin));
                    return;
                }

                // Otherwise, the domain is either invalid or not blocked
                console.debug(`[${shortName}] Added URL to allowed cache: ${urlString}`);
                CacheManager.addUrlToAllowedCache(urlObject, cacheName);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.ALLOWED, origin));
            } catch (error) {
                console.debug(`[${shortName}] Failed to check URL ${urlString}: ${error}`);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.FAILED, origin));
            }
        };

        /**
         * Checks the URL with alphaMountain's API.
         *
         * @param {Object} settings - The settings object containing user preferences.
         */
        const checkUrlWithAlphaMountain = async settings => {
            // Checks if the provider is enabled
            if (!settings.alphaMountainEnabled) {
                return;
            }

            const origin = ProtectionResult.Origin.ALPHAMOUNTAIN;
            const shortName = ProtectionResult.ShortName[origin];
            const cacheName = ProtectionResult.CacheName[origin];

            // Checks if the URL is in the allowed cache
            if (CacheManager.isUrlInAllowedCache(urlObject, cacheName)) {
                console.debug(`[${shortName}] URL is already allowed: ${urlString}`);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.KNOWN_SAFE, origin));
                return;
            }

            // Checks if the URL is in the blocked cache
            if (CacheManager.isUrlInBlockedCache(urlObject, cacheName)) {
                console.debug(`[${shortName}] URL is already blocked: ${urlString}`);
                callback(new ProtectionResult(urlString, CacheManager.getBlockedResultType(urlString, cacheName), origin));
                return;
            }

            // Checks if the URL is in the processing cache
            if (CacheManager.isUrlInProcessingCache(urlObject, cacheName)) {
                console.debug(`[${shortName}] URL is already processing: ${urlString}`);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.WAITING, origin));
                return;
            }

            // Adds the URL to the processing cache to prevent duplicate requests
            CacheManager.addUrlToProcessingCache(urlObject, cacheName, tabId);

            const apiUrl = `https://api.alphamountain.ai/category/uri`;
            const body = {
                uri: urlString,
                license: alphaMountainKey,
                version: 1,
                type: "partner.info"
            };

            try {
                const response = await fetch(apiUrl, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                    },
                    body: JSON.stringify(body),
                    signal
                });

                // Return early if the response is not OK
                if (!response.ok) {
                    console.warn(`[${shortName}] Returned early: ${response.status}`);
                    callback(new ProtectionResult(urlString, ProtectionResult.ResultType.FAILED, origin));
                    return;
                }

                const data = await response.json();
                const categories = data.category?.categories;

                // Check if the categories array is empty
                if (!categories || !Array.isArray(categories) || categories.length === 0) {
                    console.info(`[${shortName}] No categories found for URL: ${urlString}`);
                    callback(new ProtectionResult(urlString, ProtectionResult.ResultType.FAILED, origin));
                    return;
                }

                // Untrusted Categories
                const untrustedCategories = new Set([
                    11, // Child Sexual Abuse Material (CSAM)
                    55, // Potentially Unwanted Applications (PUA)
                ]);

                // Malicious Categories
                const maliciousCategories = new Set([
                    39, // Malicious
                ]);

                // Phishing Categories
                const phishingCategories = new Set([
                    51, // Phishing
                ]);

                // Check if the URL falls into any of the untrusted categories
                if (categories.some(category => untrustedCategories.has(category))) {
                    console.debug(`[${shortName}] Added URL to blocked cache: ${urlString}`);
                    CacheManager.addUrlToBlockedCache(urlObject, cacheName, ProtectionResult.ResultType.UNTRUSTED);
                    callback(new ProtectionResult(urlString, ProtectionResult.ResultType.UNTRUSTED, origin));
                    return;
                }

                // Check if the URL falls into any of the malicious categories
                if (categories.some(category => maliciousCategories.has(category))) {
                    console.debug(`[${shortName}] Added URL to blocked cache: ${urlString}`);
                    CacheManager.addUrlToBlockedCache(urlObject, cacheName, ProtectionResult.ResultType.MALICIOUS);
                    callback(new ProtectionResult(urlString, ProtectionResult.ResultType.MALICIOUS, origin));
                    return;
                }

                // Check if the URL falls into any of the phishing categories
                if (categories.some(category => phishingCategories.has(category))) {
                    console.debug(`[${shortName}] Added URL to blocked cache: ${urlString}`);
                    CacheManager.addUrlToBlockedCache(urlObject, cacheName, ProtectionResult.ResultType.PHISHING);
                    callback(new ProtectionResult(urlString, ProtectionResult.ResultType.PHISHING, origin));
                    return;
                }

                // If the URL does not fall into any of the categories, it is considered safe
                console.debug(`[${shortName}] Added URL to allowed cache: ${urlString}`);
                CacheManager.addUrlToAllowedCache(urlObject, cacheName);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.ALLOWED, origin));
            } catch (error) {
                console.debug(`[${shortName}] Failed to check URL: ${error}`);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.FAILED, origin));
            }
        };

        /**
         * Checks the URL with PrecisionSec's API.
         *
         * @param {Object} settings - The settings object containing user preferences.
         */
        const checkUrlWithPrecisionSec = async settings => {
            // Checks if the provider is enabled
            if (!settings.precisionSecEnabled) {
                return;
            }

            const origin = ProtectionResult.Origin.PRECISIONSEC;
            const shortName = ProtectionResult.ShortName[origin];
            const cacheName = ProtectionResult.CacheName[origin];

            // Checks if the URL is in the allowed cache
            if (CacheManager.isUrlInAllowedCache(urlObject, cacheName)) {
                console.debug(`[${shortName}] URL is already allowed: ${urlString}`);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.KNOWN_SAFE, origin));
                return;
            }

            // Checks if the URL is in the blocked cache
            if (CacheManager.isUrlInBlockedCache(urlObject, cacheName)) {
                console.debug(`[${shortName}] URL is already blocked: ${urlString}`);
                callback(new ProtectionResult(urlString, CacheManager.getBlockedResultType(urlString, cacheName), origin));
                return;
            }

            // Checks if the URL is in the processing cache
            if (CacheManager.isUrlInProcessingCache(urlObject, cacheName)) {
                console.debug(`[${shortName}] URL is already processing: ${urlString}`);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.WAITING, origin));
                return;
            }

            // Adds the URL to the processing cache to prevent duplicate requests
            CacheManager.addUrlToProcessingCache(urlObject, cacheName, tabId);

            const apiUrl = `https://api.precisionsec.com/check_url/${encodedURL}`;

            try {
                const response = await fetch(apiUrl, {
                    method: "GET",
                    headers: {
                        "Content-Type": "application/json",
                        "API-Key": precisionSecKey,
                    },
                    signal
                });

                // Return early if the response is not OK
                if (!response.ok) {
                    console.warn(`[${shortName}] Returned early: ${response.status}`);
                    callback(new ProtectionResult(urlString, ProtectionResult.ResultType.FAILED, origin));
                    return;
                }

                const data = await response.json();
                const {result} = data;

                // Malicious
                if (result === "Malicious") {
                    console.debug(`[${shortName}] Added URL to blocked cache: ${urlString}`);
                    CacheManager.addUrlToBlockedCache(urlObject, cacheName, ProtectionResult.ResultType.MALICIOUS);
                    callback(new ProtectionResult(urlString, ProtectionResult.ResultType.MALICIOUS, origin));
                    return;
                }

                // Safe/Trusted
                if (result === "No result") {
                    console.debug(`[${shortName}] Added URL to allowed cache: ${urlString}`);
                    CacheManager.addUrlToAllowedCache(urlObject, cacheName);
                    callback(new ProtectionResult(urlString, ProtectionResult.ResultType.ALLOWED, origin));
                    return;
                }

                // Unexpected result
                console.warn(`[${shortName}] Returned an unexpected result for URL ${urlString}: ${data}`);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.ALLOWED, origin));
            } catch (error) {
                console.debug(`[${shortName}] Failed to check URL: ${error}`);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.FAILED, origin));
            }
        };

        /**
         * Checks the URL with CERT-EE's DNS API.
         *
         * @param {Object} settings - The settings object containing user preferences.
         */
        const checkUrlWithCERTEE = async settings => {
            // Checks if the provider is enabled
            if (!settings.certEEEnabled) {
                return;
            }

            const origin = ProtectionResult.Origin.CERT_EE;
            const shortName = ProtectionResult.ShortName[origin];
            const cacheName = ProtectionResult.CacheName[origin];

            // Checks if the URL is in the allowed cache
            if (CacheManager.isUrlInAllowedCache(urlObject, cacheName)) {
                console.debug(`[${shortName}] URL is already allowed: ${urlString}`);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.KNOWN_SAFE, origin));
                return;
            }

            // Checks if the URL is in the blocked cache
            if (CacheManager.isUrlInBlockedCache(urlObject, cacheName)) {
                console.debug(`[${shortName}] URL is already blocked: ${urlString}`);
                callback(new ProtectionResult(urlString, CacheManager.getBlockedResultType(urlString, cacheName), origin));
                return;
            }

            // Checks if the URL is in the processing cache
            if (CacheManager.isUrlInProcessingCache(urlObject, cacheName)) {
                console.debug(`[${shortName}] URL is already processing: ${urlString}`);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.WAITING, origin));
                return;
            }

            // Adds the URL to the processing cache to prevent duplicate requests
            CacheManager.addUrlToProcessingCache(urlObject, cacheName, tabId);

            // Adds a small delay for non-partnered providers
            if (!Settings.allPartnersDisabled(settings)) {
                await new Promise(resolve => setTimeout(resolve, nonPartnerDelay));
            }

            const filteringURL = `https://dns.cert.ee/dns-query?dns=${encodedDNSQuery}`;

            try {
                const filteringResponse = await fetch(filteringURL, {
                    method: "GET",
                    headers: {
                        "Accept": "application/dns-message"
                    },
                    signal
                });

                const nonFilteringResponse = await fetch(nonFilteringURL, {
                    method: "GET",
                    headers: {
                        "Accept": "application/dns-json"
                    },
                    signal
                });

                // Returns early if one or more of the responses is not OK
                if (!filteringResponse.ok || !nonFilteringResponse.ok) {
                    console.warn(`[${shortName}] Returned early: ${filteringResponse.status}`);
                    callback(new ProtectionResult(urlString, ProtectionResult.ResultType.FAILED, origin));
                    return;
                }

                const filteringData = new Uint8Array(await filteringResponse.arrayBuffer());
                const filteringDataString = Array.from(filteringData).toString();
                const nonFilteringData = await nonFilteringResponse.json();
                const {Status, Answer} = nonFilteringData;

                // Returns early if the domain is offline
                if (!(Status === 0 && Answer && Answer.length > 0)) {
                    console.warn(`[${shortName}] Returned early: domain offline`);
                    callback(new ProtectionResult(urlString, ProtectionResult.ResultType.FAILED, origin));
                    return;
                }

                // If the data matches this specific pattern, it's blocked
                if (filteringDataString.endsWith("0,0,0,60,0,0,0,60,0,0,7,8,0,0,0,60")) {
                    console.debug(`[${shortName}] Added URL to blocked cache: ${urlString}`);
                    CacheManager.addUrlToBlockedCache(urlObject, cacheName, ProtectionResult.ResultType.MALICIOUS);
                    callback(new ProtectionResult(urlString, ProtectionResult.ResultType.MALICIOUS, origin));
                    return;
                }

                // Otherwise, the domain is either invalid or not blocked
                console.debug(`[${shortName}] Added URL to allowed cache: ${urlString}`);
                CacheManager.addUrlToAllowedCache(urlObject, cacheName);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.ALLOWED, origin));
            } catch (error) {
                console.debug(`[${shortName}] Failed to check URL ${urlString}: ${error}`);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.FAILED, origin));
            }
        };

        /**
         * Checks the URL with CleanBrowsing's Security DNS API.
         *
         * @param {Object} settings - The settings object containing user preferences.
         */
        const checkUrlWithCleanBrowsingSecurity = async settings => {
            // Checks if the provider is enabled
            if (!settings.cleanBrowsingSecurityEnabled) {
                return;
            }

            const origin = ProtectionResult.Origin.CLEANBROWSING_SECURITY;
            const shortName = ProtectionResult.ShortName[origin];
            const cacheName = ProtectionResult.CacheName[origin];

            // Checks if the URL is in the allowed cache
            if (CacheManager.isUrlInAllowedCache(urlObject, cacheName)) {
                console.debug(`[${shortName}] URL is already allowed: ${urlString}`);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.KNOWN_SAFE, origin));
                return;
            }

            // Checks if the URL is in the blocked cache
            if (CacheManager.isUrlInBlockedCache(urlObject, cacheName)) {
                console.debug(`[${shortName}] URL is already blocked: ${urlString}`);
                callback(new ProtectionResult(urlString, CacheManager.getBlockedResultType(urlString, cacheName), origin));
                return;
            }

            // Checks if the URL is in the processing cache
            if (CacheManager.isUrlInProcessingCache(urlObject, cacheName)) {
                console.debug(`[${shortName}] URL is already processing: ${urlString}`);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.WAITING, origin));
                return;
            }

            // Adds the URL to the processing cache to prevent duplicate requests
            CacheManager.addUrlToProcessingCache(urlObject, cacheName, tabId);

            // Adds a small delay for non-partnered providers
            if (!Settings.allPartnersDisabled(settings)) {
                await new Promise(resolve => setTimeout(resolve, nonPartnerDelay));
            }

            const filteringURL = `https://doh.cleanbrowsing.org/doh/security-filter/dns-query?dns=${encodedDNSQuery}`;

            try {
                const filteringResponse = await fetch(filteringURL, {
                    method: "GET",
                    headers: {
                        "Accept": "application/dns-message"
                    },
                    signal
                });

                const nonFilteringResponse = await fetch(nonFilteringURL, {
                    method: "GET",
                    headers: {
                        "Accept": "application/dns-json"
                    },
                    signal
                });

                // Returns early if one or more of the responses is not OK
                if (!filteringResponse.ok || !nonFilteringResponse.ok) {
                    console.warn(`[${shortName}] Returned early: ${filteringResponse.status}`);
                    callback(new ProtectionResult(urlString, ProtectionResult.ResultType.FAILED, origin));
                    return;
                }

                const filteringData = new Uint8Array(await filteringResponse.arrayBuffer());
                const nonFilteringData = await nonFilteringResponse.json();
                const {Status, Answer} = nonFilteringData;

                // Returns early if the domain is offline
                if (!(Status === 0 && Answer && Answer.length > 0)) {
                    console.warn(`[${shortName}] Returned early: domain offline`);
                    callback(new ProtectionResult(urlString, ProtectionResult.ResultType.FAILED, origin));
                    return;
                }

                // If the data matches this specific pattern, it's blocked
                if (filteringData.length >= 4 && filteringData[3] === 131) {
                    console.debug(`[${shortName}] Added URL to blocked cache: ${urlString}`);
                    CacheManager.addUrlToBlockedCache(urlObject, cacheName, ProtectionResult.ResultType.MALICIOUS);
                    callback(new ProtectionResult(urlString, ProtectionResult.ResultType.MALICIOUS, origin));
                    return;
                }

                // Otherwise, the domain is either invalid or not blocked
                console.debug(`[${shortName}] Added URL to allowed cache: ${urlString}`);
                CacheManager.addUrlToAllowedCache(urlObject, cacheName);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.ALLOWED, origin));
            } catch (error) {
                console.debug(`[${shortName}] Failed to check URL ${urlString}: ${error}`);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.FAILED, origin));
            }
        };

        /**
         * Checks the URL with CleanBrowsing's Family DNS API.
         *
         * @param {Object} settings - The settings object containing user preferences.
         */
        const checkUrlWithCleanBrowsingFamily = async settings => {
            // Checks if the provider is enabled
            if (!settings.cleanBrowsingFamilyEnabled) {
                return;
            }

            const origin = ProtectionResult.Origin.CLEANBROWSING_FAMILY;
            const shortName = ProtectionResult.ShortName[origin];
            const cacheName = ProtectionResult.CacheName[origin];

            // Checks if the URL is in the allowed cache
            if (CacheManager.isUrlInAllowedCache(urlObject, cacheName)) {
                console.debug(`[${shortName}] URL is already allowed: ${urlString}`);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.KNOWN_SAFE, origin));
                return;
            }

            // Checks if the URL is in the blocked cache
            if (CacheManager.isUrlInBlockedCache(urlObject, cacheName)) {
                console.debug(`[${shortName}] URL is already blocked: ${urlString}`);
                callback(new ProtectionResult(urlString, CacheManager.getBlockedResultType(urlString, cacheName), origin));
                return;
            }

            // Checks if the URL is in the processing cache
            if (CacheManager.isUrlInProcessingCache(urlObject, cacheName)) {
                console.debug(`[${shortName}] URL is already processing: ${urlString}`);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.WAITING, origin));
                return;
            }

            // Adds the URL to the processing cache to prevent duplicate requests
            CacheManager.addUrlToProcessingCache(urlObject, cacheName, tabId);

            // Adds a small delay for non-partnered providers
            if (!Settings.allPartnersDisabled(settings)) {
                await new Promise(resolve => setTimeout(resolve, nonPartnerDelay));
            }

            const filteringURL = `https://doh.cleanbrowsing.org/doh/adult-filter/dns-query?dns=${encodedDNSQuery}`;

            try {
                const filteringResponse = await fetch(filteringURL, {
                    method: "GET",
                    headers: {
                        "Accept": "application/dns-message"
                    },
                    signal
                });

                const nonFilteringResponse = await fetch(nonFilteringURL, {
                    method: "GET",
                    headers: {
                        "Accept": "application/dns-json"
                    },
                    signal
                });

                // Returns early if one or more of the responses is not OK
                if (!filteringResponse.ok || !nonFilteringResponse.ok) {
                    console.warn(`[${shortName}] Returned early: ${filteringResponse.status}`);
                    callback(new ProtectionResult(urlString, ProtectionResult.ResultType.FAILED, origin));
                    return;
                }

                const filteringData = new Uint8Array(await filteringResponse.arrayBuffer());
                const nonFilteringData = await nonFilteringResponse.json();
                const {Status, Answer} = nonFilteringData;

                // Returns early if the domain is offline
                if (!(Status === 0 && Answer && Answer.length > 0)) {
                    console.warn(`[${shortName}] Returned early: domain offline`);
                    callback(new ProtectionResult(urlString, ProtectionResult.ResultType.FAILED, origin));
                    return;
                }

                // If the data matches this specific pattern, it's blocked
                if (filteringData.length >= 4 && filteringData[3] === 131) {
                    console.debug(`[${shortName}] Added URL to blocked cache: ${urlString}`);
                    CacheManager.addUrlToBlockedCache(urlObject, cacheName, ProtectionResult.ResultType.ADULT_CONTENT);
                    callback(new ProtectionResult(urlString, ProtectionResult.ResultType.ADULT_CONTENT, origin));
                    return;
                }

                // Otherwise, the domain is either invalid or not blocked
                console.debug(`[${shortName}] Added URL to allowed cache: ${urlString}`);
                CacheManager.addUrlToAllowedCache(urlObject, cacheName);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.ALLOWED, origin));
            } catch (error) {
                console.debug(`[${shortName}] Failed to check URL ${urlString}: ${error}`);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.FAILED, origin));
            }
        };

        /**
         * Checks the URL with Cloudflare's Security DNS APIs.
         *
         * @param {Object} settings - The settings object containing user preferences.
         */
        const checkUrlWithCloudflareSecurity = async settings => {
            // Checks if the provider is enabled
            if (!settings.cloudflareSecurityEnabled) {
                return;
            }

            const origin = ProtectionResult.Origin.CLOUDFLARE_SECURITY;
            const shortName = ProtectionResult.ShortName[origin];
            const cacheName = ProtectionResult.CacheName[origin];

            // Checks if the URL is in the allowed cache
            if (CacheManager.isUrlInAllowedCache(urlObject, cacheName)) {
                console.debug(`[${shortName}] URL is already allowed: ${urlString}`);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.KNOWN_SAFE, origin));
                return;
            }

            // Checks if the URL is in the blocked cache
            if (CacheManager.isUrlInBlockedCache(urlObject, cacheName)) {
                console.debug(`[${shortName}] URL is already blocked: ${urlString}`);
                callback(new ProtectionResult(urlString, CacheManager.getBlockedResultType(urlString, cacheName), origin));
                return;
            }

            // Checks if the URL is in the processing cache
            if (CacheManager.isUrlInProcessingCache(urlObject, cacheName)) {
                console.debug(`[${shortName}] URL is already processing: ${urlString}`);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.WAITING, origin));
                return;
            }

            // Adds the URL to the processing cache to prevent duplicate requests
            CacheManager.addUrlToProcessingCache(urlObject, cacheName, tabId);

            // Adds a small delay for non-partnered providers
            if (!Settings.allPartnersDisabled(settings)) {
                await new Promise(resolve => setTimeout(resolve, nonPartnerDelay));
            }

            const filteringURL = `https://security.cloudflare-dns.com/dns-query?name=${encodedURLHostname}`;

            try {
                const filteringResponse = await fetch(filteringURL, {
                    method: "GET",
                    headers: {
                        "Accept": "application/dns-json"
                    },
                    signal
                });

                const nonFilteringResponse = await fetch(nonFilteringURL, {
                    method: "GET",
                    headers: {
                        "Accept": "application/dns-json"
                    },
                    signal
                });

                // Returns early if one or more of the responses is not OK
                if (!filteringResponse.ok || !nonFilteringResponse.ok) {
                    console.warn(`[${shortName}] Returned early: ${filteringResponse.status}`);
                    callback(new ProtectionResult(urlString, ProtectionResult.ResultType.FAILED, origin));
                    return;
                }

                const filteringData = await filteringResponse.json();
                const filteringDataString = JSON.stringify(filteringData);
                const nonFilteringData = await nonFilteringResponse.json();
                const {Status, Answer} = nonFilteringData;

                // Returns early if the domain is offline
                if (!(Status === 0 && Answer && Answer.length > 0)) {
                    console.warn(`[${shortName}] Returned early: domain offline`);
                    callback(new ProtectionResult(urlString, ProtectionResult.ResultType.FAILED, origin));
                    return;
                }

                // If the data matches this specific pattern, it's blocked
                if (filteringDataString.includes("EDE(16): Censored") ||
                    filteringDataString.includes("\"TTL\":60,\"data\":\"0.0.0.0\"")) {
                    console.debug(`[${shortName}] Added URL to blocked cache: ${urlString}`);
                    CacheManager.addUrlToBlockedCache(urlObject, cacheName, ProtectionResult.ResultType.MALICIOUS);
                    callback(new ProtectionResult(urlString, ProtectionResult.ResultType.MALICIOUS, origin));
                    return;
                }

                // Otherwise, the domain is either invalid or not blocked
                console.debug(`[${shortName}] Added URL to allowed cache: ${urlString}`);
                CacheManager.addUrlToAllowedCache(urlObject, cacheName);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.ALLOWED, origin));
            } catch (error) {
                console.debug(`[${shortName}] Failed to check URL ${urlString}: ${error}`);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.FAILED, origin));
            }
        };

        /**
         * Checks the URL with Cloudflare's Family DNS APIs.
         *
         * @param {Object} settings - The settings object containing user preferences.
         */
        const checkUrlWithCloudflareFamily = async settings => {
            // Checks if the provider is enabled
            if (!settings.cloudflareFamilyEnabled) {
                return;
            }

            const origin = ProtectionResult.Origin.CLOUDFLARE_FAMILY;
            const shortName = ProtectionResult.ShortName[origin];
            const cacheName = ProtectionResult.CacheName[origin];

            // Checks if the URL is in the allowed cache
            if (CacheManager.isUrlInAllowedCache(urlObject, cacheName)) {
                console.debug(`[${shortName}] URL is already allowed: ${urlString}`);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.KNOWN_SAFE, origin));
                return;
            }

            // Checks if the URL is in the blocked cache
            if (CacheManager.isUrlInBlockedCache(urlObject, cacheName)) {
                console.debug(`[${shortName}] URL is already blocked: ${urlString}`);
                callback(new ProtectionResult(urlString, CacheManager.getBlockedResultType(urlString, cacheName), origin));
                return;
            }

            // Checks if the URL is in the processing cache
            if (CacheManager.isUrlInProcessingCache(urlObject, cacheName)) {
                console.debug(`[${shortName}] URL is already processing: ${urlString}`);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.WAITING, origin));
                return;
            }

            // Adds the URL to the processing cache to prevent duplicate requests
            CacheManager.addUrlToProcessingCache(urlObject, cacheName, tabId);

            // Adds a small delay for non-partnered providers
            if (!Settings.allPartnersDisabled(settings)) {
                await new Promise(resolve => setTimeout(resolve, nonPartnerDelay));
            }

            const filteringURL = `https://family.cloudflare-dns.com/dns-query?name=${encodedURLHostname}`;

            try {
                const filteringResponse = await fetch(filteringURL, {
                    method: "GET",
                    headers: {
                        "Accept": "application/dns-json"
                    },
                    signal
                });

                const nonFilteringResponse = await fetch(nonFilteringURL, {
                    method: "GET",
                    headers: {
                        "Accept": "application/dns-json"
                    },
                    signal
                });

                // Returns early if one or more of the responses is not OK
                if (!filteringResponse.ok || !nonFilteringResponse.ok) {
                    console.warn(`[${shortName}] Returned early: ${filteringResponse.status}`);
                    callback(new ProtectionResult(urlString, ProtectionResult.ResultType.FAILED, origin));
                    return;
                }

                const filteringData = await filteringResponse.json();
                const filteringDataString = JSON.stringify(filteringData);
                const nonFilteringData = await nonFilteringResponse.json();
                const {Status, Answer} = nonFilteringData;

                // Returns early if the domain is offline
                if (!(Status === 0 && Answer && Answer.length > 0)) {
                    console.warn(`[${shortName}] Returned early: domain offline`);
                    callback(new ProtectionResult(urlString, ProtectionResult.ResultType.FAILED, origin));
                    return;
                }

                // If the data matches this specific pattern, it's blocked
                if (filteringDataString.includes("EDE(16): Censored") ||
                    filteringDataString.includes("\"TTL\":60,\"data\":\"0.0.0.0\"")) {
                    console.debug(`[${shortName}] Added URL to blocked cache: ${urlString}`);
                    CacheManager.addUrlToBlockedCache(urlObject, cacheName, ProtectionResult.ResultType.ADULT_CONTENT);
                    callback(new ProtectionResult(urlString, ProtectionResult.ResultType.ADULT_CONTENT, origin));
                    return;
                }

                // Otherwise, the domain is either invalid or not blocked
                console.debug(`[${shortName}] Added URL to allowed cache: ${urlString}`);
                CacheManager.addUrlToAllowedCache(urlObject, cacheName);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.ALLOWED, origin));
            } catch (error) {
                console.debug(`[${shortName}] Failed to check URL ${urlString}: ${error}`);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.FAILED, origin));
            }
        };

        /**
         * Checks the URL with Control D's Security DNS API.
         *
         * @param {Object} settings - The settings object containing user preferences.
         */
        const checkUrlWithControlDSecurity = async settings => {
            // Checks if the provider is enabled
            if (!settings.controlDSecurityEnabled) {
                return;
            }

            const origin = ProtectionResult.Origin.CONTROL_D_SECURITY;
            const shortName = ProtectionResult.ShortName[origin];
            const cacheName = ProtectionResult.CacheName[origin];

            // Checks if the URL is in the allowed cache
            if (CacheManager.isUrlInAllowedCache(urlObject, cacheName)) {
                console.debug(`[${shortName}] URL is already allowed: ${urlString}`);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.KNOWN_SAFE, origin));
                return;
            }

            // Checks if the URL is in the blocked cache
            if (CacheManager.isUrlInBlockedCache(urlObject, cacheName)) {
                console.debug(`[${shortName}] URL is already blocked: ${urlString}`);
                callback(new ProtectionResult(urlString, CacheManager.getBlockedResultType(urlString, cacheName), origin));
                return;
            }

            // Checks if the URL is in the processing cache
            if (CacheManager.isUrlInProcessingCache(urlObject, cacheName)) {
                console.debug(`[${shortName}] URL is already processing: ${urlString}`);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.WAITING, origin));
                return;
            }

            // Adds the URL to the processing cache to prevent duplicate requests
            CacheManager.addUrlToProcessingCache(urlObject, cacheName, tabId);

            const filteringURL = `https://freedns.controld.com/no-malware-typo?name=${encodedURLHostname}`;

            try {
                const filteringResponse = await fetch(filteringURL, {
                    method: "GET",
                    headers: {
                        "Accept": "application/dns-message"
                    },
                    signal
                });

                const nonFilteringResponse = await fetch(nonFilteringURL, {
                    method: "GET",
                    headers: {
                        "Accept": "application/dns-json"
                    },
                    signal
                });

                // Returns early if one or more of the responses is not OK
                if (!filteringResponse.ok || !nonFilteringResponse.ok) {
                    console.warn(`[${shortName}] Returned early: ${filteringResponse.status}`);
                    callback(new ProtectionResult(urlString, ProtectionResult.ResultType.FAILED, origin));
                    return;
                }

                const filteringData = new Uint8Array(await filteringResponse.arrayBuffer());
                const filteringDataString = Array.from(filteringData).toString();
                const nonFilteringData = await nonFilteringResponse.json();
                const {Status, Answer} = nonFilteringData;

                // Returns early if the domain is offline
                if (!(Status === 0 && Answer && Answer.length > 0)) {
                    console.warn(`[${shortName}] Returned early: domain offline`);
                    callback(new ProtectionResult(urlString, ProtectionResult.ResultType.FAILED, origin));
                    return;
                }

                // If the data matches this specific pattern, it's blocked
                if (filteringDataString.endsWith("0,4,0,0,0,0")) {
                    console.debug(`[${shortName}] Added URL to blocked cache: ${urlString}`);
                    CacheManager.addUrlToBlockedCache(urlObject, cacheName, ProtectionResult.ResultType.MALICIOUS);
                    callback(new ProtectionResult(urlString, ProtectionResult.ResultType.MALICIOUS, origin));
                    return;
                }

                // Otherwise, the domain is either invalid or not blocked
                console.debug(`[${shortName}] Added URL to allowed cache: ${urlString}`);
                CacheManager.addUrlToAllowedCache(urlObject, cacheName);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.ALLOWED, origin));
            } catch (error) {
                console.debug(`[${shortName}] Failed to check URL ${urlString}: ${error}`);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.FAILED, origin));
            }
        };

        /**
         * Checks the URL with Control D's Family DNS API.
         *
         * @param {Object} settings - The settings object containing user preferences.
         */
        const checkUrlWithControlDFamily = async settings => {
            // Checks if the provider is enabled
            if (!settings.controlDFamilyEnabled) {
                return;
            }

            const origin = ProtectionResult.Origin.CONTROL_D_FAMILY;
            const shortName = ProtectionResult.ShortName[origin];
            const cacheName = ProtectionResult.CacheName[origin];

            // Checks if the URL is in the allowed cache
            if (CacheManager.isUrlInAllowedCache(urlObject, cacheName)) {
                console.debug(`[${shortName}] URL is already allowed: ${urlString}`);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.KNOWN_SAFE, origin));
                return;
            }

            // Checks if the URL is in the blocked cache
            if (CacheManager.isUrlInBlockedCache(urlObject, cacheName)) {
                console.debug(`[${shortName}] URL is already blocked: ${urlString}`);
                callback(new ProtectionResult(urlString, CacheManager.getBlockedResultType(urlString, cacheName), origin));
                return;
            }

            // Checks if the URL is in the processing cache
            if (CacheManager.isUrlInProcessingCache(urlObject, cacheName)) {
                console.debug(`[${shortName}] URL is already processing: ${urlString}`);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.WAITING, origin));
                return;
            }

            // Adds the URL to the processing cache to prevent duplicate requests
            CacheManager.addUrlToProcessingCache(urlObject, cacheName, tabId);

            const filteringURL = `https://freedns.controld.com/no-drugs-porn-gambling-malware-typo?name=${encodedURLHostname}`;

            try {
                const filteringResponse = await fetch(filteringURL, {
                    method: "GET",
                    headers: {
                        "Accept": "application/dns-message"
                    },
                    signal
                });

                const nonFilteringResponse = await fetch(nonFilteringURL, {
                    method: "GET",
                    headers: {
                        "Accept": "application/dns-json"
                    },
                    signal
                });

                // Returns early if one or more of the responses is not OK
                if (!filteringResponse.ok || !nonFilteringResponse.ok) {
                    console.warn(`[${shortName}] Returned early: ${filteringResponse.status}`);
                    callback(new ProtectionResult(urlString, ProtectionResult.ResultType.FAILED, origin));
                    return;
                }

                const filteringData = new Uint8Array(await filteringResponse.arrayBuffer());
                const filteringDataString = Array.from(filteringData).toString();
                const nonFilteringData = await nonFilteringResponse.json();
                const {Status, Answer} = nonFilteringData;

                // Returns early if the domain is offline
                if (!(Status === 0 && Answer && Answer.length > 0)) {
                    console.warn(`[${shortName}] Returned early: domain offline`);
                    callback(new ProtectionResult(urlString, ProtectionResult.ResultType.FAILED, origin));
                    return;
                }

                // If the data matches this specific pattern, it's blocked
                if (filteringDataString.endsWith("0,4,0,0,0,0")) {
                    console.debug(`[${shortName}] Added URL to blocked cache: ${urlString}`);
                    CacheManager.addUrlToBlockedCache(urlObject, cacheName, ProtectionResult.ResultType.MALICIOUS);
                    callback(new ProtectionResult(urlString, ProtectionResult.ResultType.MALICIOUS, origin));
                    return;
                }

                // Otherwise, the domain is either invalid or not blocked
                console.debug(`[${shortName}] Added URL to allowed cache: ${urlString}`);
                CacheManager.addUrlToAllowedCache(urlObject, cacheName);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.ALLOWED, origin));
            } catch (error) {
                console.debug(`[${shortName}] Failed to check URL ${urlString}: ${error}`);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.FAILED, origin));
            }
        };

        /**
         * Checks the URL with DNS4EU's Security DNS API.
         *
         * @param {Object} settings - The settings object containing user preferences.
         */
        const checkUrlWithDNS4EUSecurity = async settings => {
            // Checks if the provider is enabled
            if (!settings.dns4EUSecurityEnabled) {
                return;
            }

            const origin = ProtectionResult.Origin.DNS4EU_SECURITY;
            const shortName = ProtectionResult.ShortName[origin];
            const cacheName = ProtectionResult.CacheName[origin];

            // Checks if the URL is in the allowed cache
            if (CacheManager.isUrlInAllowedCache(urlObject, cacheName)) {
                console.debug(`[${shortName}] URL is already allowed: ${urlString}`);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.KNOWN_SAFE, origin));
                return;
            }

            // Checks if the URL is in the blocked cache
            if (CacheManager.isUrlInBlockedCache(urlObject, cacheName)) {
                console.debug(`[${shortName}] URL is already blocked: ${urlString}`);
                callback(new ProtectionResult(urlString, CacheManager.getBlockedResultType(urlString, cacheName), origin));
                return;
            }

            // Checks if the URL is in the processing cache
            if (CacheManager.isUrlInProcessingCache(urlObject, cacheName)) {
                console.debug(`[${shortName}] URL is already processing: ${urlString}`);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.WAITING, origin));
                return;
            }

            // Adds the URL to the processing cache to prevent duplicate requests
            CacheManager.addUrlToProcessingCache(urlObject, cacheName, tabId);

            // Adds a small delay for non-partnered providers
            if (!Settings.allPartnersDisabled(settings)) {
                await new Promise(resolve => setTimeout(resolve, nonPartnerDelay));
            }

            const filteringURL = `https://protective.joindns4.eu/dns-query?dns=${encodedDNSQuery}`;

            try {
                const filteringResponse = await fetch(filteringURL, {
                    method: "GET",
                    headers: {
                        "Accept": "application/dns-message"
                    },
                    signal
                });

                const nonFilteringResponse = await fetch(nonFilteringURL, {
                    method: "GET",
                    headers: {
                        "Accept": "application/dns-json"
                    },
                    signal
                });

                // Returns early if one or more of the responses is not OK
                if (!filteringResponse.ok || !nonFilteringResponse.ok) {
                    console.warn(`[${shortName}] Returned early: ${filteringResponse.status}`);
                    callback(new ProtectionResult(urlString, ProtectionResult.ResultType.FAILED, origin));
                    return;
                }

                const filteringData = new Uint8Array(await filteringResponse.arrayBuffer());
                const filteringDataString = Array.from(filteringData).toString();
                const nonFilteringData = await nonFilteringResponse.json();
                const {Status, Answer} = nonFilteringData;

                // Returns early if the domain is offline
                if (!(Status === 0 && Answer && Answer.length > 0)) {
                    console.warn(`[${shortName}] Returned early: domain offline`);
                    callback(new ProtectionResult(urlString, ProtectionResult.ResultType.FAILED, origin));
                    return;
                }

                // If the data matches this specific pattern, it's blocked
                if (filteringDataString.endsWith("0,1,0,0,0,1,0,4,51,15,69,11")) {
                    console.debug(`[${shortName}] Added URL to blocked cache: ${urlString}`);
                    CacheManager.addUrlToBlockedCache(urlObject, cacheName, ProtectionResult.ResultType.MALICIOUS);
                    callback(new ProtectionResult(urlString, ProtectionResult.ResultType.MALICIOUS, origin));
                    return;
                }

                // Otherwise, the domain is either invalid or not blocked
                console.debug(`[${shortName}] Added URL to allowed cache: ${urlString}`);
                CacheManager.addUrlToAllowedCache(urlObject, cacheName);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.ALLOWED, origin));
            } catch (error) {
                console.debug(`[${shortName}] Failed to check URL ${urlString}: ${error}`);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.FAILED, origin));
            }
        };

        /**
         * Checks the URL with DNS4EU's Family DNS API.
         *
         * @param {Object} settings - The settings object containing user preferences.
         */
        const checkUrlWithDNS4EUFamily = async settings => {
            // Checks if the provider is enabled
            if (!settings.dns4EUFamilyEnabled) {
                return;
            }

            const origin = ProtectionResult.Origin.DNS4EU_FAMILY;
            const shortName = ProtectionResult.ShortName[origin];
            const cacheName = ProtectionResult.CacheName[origin];

            // Checks if the URL is in the allowed cache
            if (CacheManager.isUrlInAllowedCache(urlObject, cacheName)) {
                console.debug(`[${shortName}] URL is already allowed: ${urlString}`);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.KNOWN_SAFE, origin));
                return;
            }

            // Checks if the URL is in the blocked cache
            if (CacheManager.isUrlInBlockedCache(urlObject, cacheName)) {
                console.debug(`[${shortName}] URL is already blocked: ${urlString}`);
                callback(new ProtectionResult(urlString, CacheManager.getBlockedResultType(urlString, cacheName), origin));
                return;
            }

            // Checks if the URL is in the processing cache
            if (CacheManager.isUrlInProcessingCache(urlObject, cacheName)) {
                console.debug(`[${shortName}] URL is already processing: ${urlString}`);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.WAITING, origin));
                return;
            }

            // Adds the URL to the processing cache to prevent duplicate requests
            CacheManager.addUrlToProcessingCache(urlObject, cacheName, tabId);

            // Adds a small delay for non-partnered providers
            if (!Settings.allPartnersDisabled(settings)) {
                await new Promise(resolve => setTimeout(resolve, nonPartnerDelay));
            }

            const filteringURL = `https://child.joindns4.eu/dns-query?dns=${encodedDNSQuery}`;

            try {
                const filteringResponse = await fetch(filteringURL, {
                    method: "GET",
                    headers: {
                        "Accept": "application/dns-message"
                    },
                    signal
                });

                const nonFilteringResponse = await fetch(nonFilteringURL, {
                    method: "GET",
                    headers: {
                        "Accept": "application/dns-json"
                    },
                    signal
                });

                // Returns early if one or more of the responses is not OK
                if (!filteringResponse.ok || !nonFilteringResponse.ok) {
                    console.warn(`[${shortName}] Returned early: ${filteringResponse.status}`);
                    callback(new ProtectionResult(urlString, ProtectionResult.ResultType.FAILED, origin));
                    return;
                }

                const filteringData = new Uint8Array(await filteringResponse.arrayBuffer());
                const filteringDataString = Array.from(filteringData).toString();
                const nonFilteringData = await nonFilteringResponse.json();
                const {Status, Answer} = nonFilteringData;

                // Returns early if the domain is offline
                if (!(Status === 0 && Answer && Answer.length > 0)) {
                    console.warn(`[${shortName}] Returned early: domain offline`);
                    callback(new ProtectionResult(urlString, ProtectionResult.ResultType.FAILED, origin));
                    return;
                }

                // If the data matches this specific pattern, it's blocked
                if (filteringDataString.endsWith("0,1,0,0,0,1,0,4,51,15,69,11")) {
                    console.debug(`[${shortName}] Added URL to blocked cache: ${urlString}`);
                    CacheManager.addUrlToBlockedCache(urlObject, cacheName, ProtectionResult.ResultType.ADULT_CONTENT);
                    callback(new ProtectionResult(urlString, ProtectionResult.ResultType.ADULT_CONTENT, origin));
                    return;
                }

                // Otherwise, the domain is either invalid or not blocked
                console.debug(`[${shortName}] Added URL to allowed cache: ${urlString}`);
                CacheManager.addUrlToAllowedCache(urlObject, cacheName);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.ALLOWED, origin));
            } catch (error) {
                console.debug(`[${shortName}] Failed to check URL ${urlString}: ${error}`);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.FAILED, origin));
            }
        };

        /**
         * Checks the URL with Quad9's DNS API.
         *
         * @param {Object} settings - The settings object containing user preferences.
         */
        const checkUrlWithQuad9 = async settings => {
            // Checks if the provider is enabled
            if (!settings.quad9Enabled) {
                return;
            }

            const origin = ProtectionResult.Origin.QUAD9;
            const shortName = ProtectionResult.ShortName[origin];
            const cacheName = ProtectionResult.CacheName[origin];

            // Checks if the URL is in the allowed cache
            if (CacheManager.isUrlInAllowedCache(urlObject, cacheName)) {
                console.debug(`[${shortName}] URL is already allowed: ${urlString}`);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.KNOWN_SAFE, origin));
                return;
            }

            // Checks if the URL is in the blocked cache
            if (CacheManager.isUrlInBlockedCache(urlObject, cacheName)) {
                console.debug(`[${shortName}] URL is already blocked: ${urlString}`);
                callback(new ProtectionResult(urlString, CacheManager.getBlockedResultType(urlString, cacheName), origin));
                return;
            }

            // Checks if the URL is in the processing cache
            if (CacheManager.isUrlInProcessingCache(urlObject, cacheName)) {
                console.debug(`[${shortName}] URL is already processing: ${urlString}`);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.WAITING, origin));
                return;
            }

            // Adds the URL to the processing cache to prevent duplicate requests
            CacheManager.addUrlToProcessingCache(urlObject, cacheName, tabId);

            // Adds a small delay for non-partnered providers
            if (!Settings.allPartnersDisabled(settings)) {
                await new Promise(resolve => setTimeout(resolve, nonPartnerDelay));
            }

            const filteringURL = `https://dns.quad9.net/dns-query?dns=${encodedDNSQuery}`;

            try {
                const filteringResponse = await fetch(filteringURL, {
                    method: "GET",
                    headers: {
                        "Accept": "application/dns-message"
                    },
                    signal
                });

                const nonFilteringResponse = await fetch(nonFilteringURL, {
                    method: "GET",
                    headers: {
                        "Accept": "application/dns-json"
                    },
                    signal
                });

                // Returns early if one or more of the responses is not OK
                if (!filteringResponse.ok || !nonFilteringResponse.ok) {
                    console.warn(`[${shortName}] Returned early: ${filteringResponse.status}`);
                    callback(new ProtectionResult(urlString, ProtectionResult.ResultType.FAILED, origin));
                    return;
                }

                const filteringData = new Uint8Array(await filteringResponse.arrayBuffer());
                const nonFilteringData = await nonFilteringResponse.json();
                const {Status, Answer} = nonFilteringData;

                // Returns early if the domain is offline
                if (!(Status === 0 && Answer && Answer.length > 0)) {
                    console.warn(`[${shortName}] Returned early: domain offline`);
                    callback(new ProtectionResult(urlString, ProtectionResult.ResultType.FAILED, origin));
                    return;
                }

                // If the data matches this specific pattern, it's blocked
                if (filteringData.length >= 4 && filteringData[3] === 3) {
                    console.debug(`[${shortName}] Added URL to blocked cache: ${urlString}`);
                    CacheManager.addUrlToBlockedCache(urlObject, cacheName, ProtectionResult.ResultType.MALICIOUS);
                    callback(new ProtectionResult(urlString, ProtectionResult.ResultType.MALICIOUS, origin));
                    return;
                }

                // Otherwise, the domain is either invalid or not blocked
                console.debug(`[${shortName}] Added URL to allowed cache: ${urlString}`);
                CacheManager.addUrlToAllowedCache(urlObject, cacheName);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.ALLOWED, origin));
            } catch (error) {
                console.debug(`[${shortName}] Failed to check URL ${urlString}: ${error}`);
                callback(new ProtectionResult(urlString, ProtectionResult.ResultType.FAILED, origin));
            }
        };

        // Call all the check functions asynchronously
        Settings.get(settings => {
            // Official Partners
            checkUrlWithAdGuardSecurity(settings);
            checkUrlWithAdGuardFamily(settings);
            checkUrlWithAlphaMountain(settings);
            checkUrlWithPrecisionSec(settings);

            // Non-Partnered Providers
            checkUrlWithCERTEE(settings);
            checkUrlWithCleanBrowsingSecurity(settings);
            checkUrlWithCleanBrowsingFamily(settings);
            checkUrlWithCloudflareSecurity(settings);
            checkUrlWithCloudflareFamily(settings);
            checkUrlWithControlDSecurity(settings);
            checkUrlWithControlDFamily(settings);
            checkUrlWithDNS4EUSecurity(settings);
            checkUrlWithDNS4EUFamily(settings);
            checkUrlWithQuad9(settings);
        });

        // Cleans up controllers for tabs that no longer exist
        cleanupTabControllers();
    };

    return {
        abandonPendingRequests,
        checkIfUrlIsMalicious
    };
})();
