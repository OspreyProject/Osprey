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

// Manages the cache for the allowed protection providers
const CacheManager = (() => {

    // Key names for the caches in local and session storage
    const allowedKey = "allowedCache";
    const blockedKey = "blockedCache";
    const processingKey = "processingCache";

    // Caches for allowed, blocked, and processing entries
    let allowedCaches = Object.create(null);
    let allowedPatternCaches = Object.create(null);
    let blockedCaches = Object.create(null);
    let processingCaches = Object.create(null);

    // Timeout ID for debounced updates
    let localStorageTimeoutID = null;
    let sessionStorageTimeoutID = null;

    // Debounce delay for local and session storage updates
    const debounceDelay = 100;

    // Cleanup interval for expired entries (5 minutes)
    const cleanupInterval = 5 * 60 * 1000;

    // Expiration time for cache entries in seconds (7 days by default)
    let expirationTime = 604800;

    // Sets the expiration time for cache entries based on user settings
    Settings.get(settings => {
        if (!settings || typeof settings !== 'object') {
            console.error('CacheManager: Settings.get returned invalid settings; using default expiration time.');
            return;
        }

        const expSeconds = Number(settings.cacheExpirationSeconds);
        const min = 60; // 1 minute in seconds
        const max = 31536000; // 1 year in seconds
        const def = 604800; // 7 days in seconds
        expirationTime = Number.isFinite(expSeconds) && expSeconds >= min && expSeconds <= max ? expSeconds : def;
    });

    const providers = Object.freeze([
        // Global
        "global",

        // Cloudflare Resolver
        "cloudflareResolver",

        // Official Partners
        "adGuardSecurity", "adGuardFamily",
        "alphaMountain",
        "precisionSec",

        // Non-Partnered Providers
        "certEE",
        "cleanBrowsingSecurity", "cleanBrowsingFamily",
        "cloudflareSecurity", "cloudflareFamily",
        "controlDSecurity", "controlDFamily",
        "quad9",
        "switchCH",

        // Local Filtering Lists
        "phishDestroy",
        "phishingDatabase",
    ]);

    // Set for O(1) provider name validation
    const providersSet = new Set(providers);

    // Initialize caches for each provider
    for (const name of providers) {
        allowedCaches[name] = new Map();
        allowedPatternCaches[name] = new Set();
        blockedCaches[name] = new Map();
        processingCaches[name] = new Map();
    }

    /**
     * Loads allowed caches (without tabId) from local storage.
     *
     * @param {string} allowedKey The key used to retrieve the allowed caches from local storage.
     * @param {Object} callback The callback function to execute after loading the allowed caches.
     */
    StorageUtil.getFromLocalStore(allowedKey, callback => {
        for (const name of Object.keys(allowedCaches)) {
            if (callback?.[name] && typeof callback[name] === 'object') {
                const entries = Object.entries(callback[name]).filter(([key]) => !StorageUtil.isDangerousKey(key));
                allowedCaches[name] = new Map(entries);
            }
        }
    });

    /**
     * Loads blocked caches (without tabId) from local storage.
     *
     * @param {string} blockedKey The key used to retrieve the blocked caches from local storage.
     * @param {Object} callback The callback function to execute after loading the blocked caches.
     */
    StorageUtil.getFromLocalStore(blockedKey, callback => {
        const validResultTypes = new Set(Object.values(ProtectionResult.ResultType));

        for (const name of Object.keys(blockedCaches)) {
            if (callback?.[name] && typeof callback[name] === 'object') {
                const entries = Object.entries(callback[name]).filter(([key]) => !StorageUtil.isDangerousKey(key));

                blockedCaches[name] = new Map(
                    entries.flatMap(([url, {exp, resultType}]) => {
                        if (!Number.isFinite(exp) && exp !== 0 || !Number.isFinite(resultType)) {
                            console.warn(`Skipping invalid blocked cache entry for "${url}": invalid exp or resultType`);
                            return [];
                        }

                        if (!validResultTypes.has(resultType)) {
                            console.warn(`Skipping blocked cache entry for "${url}": unrecognized resultType ${resultType}`);
                            return [];
                        }
                        return [[url, {exp, resultType}]];
                    })
                );
            }
        }
    });

    /**
     * Loads processing caches (without tabId) from local storage.
     *
     * @param {string} processingKey The key used to retrieve the processing caches from local storage.
     * @param {Object} [callback] The callback function to execute after loading the processing caches.
     */
    StorageUtil.getFromSessionStore(processingKey, callback => {
        if (callback && typeof callback === 'object') {
            for (const name of Object.keys(processingCaches)) {
                if (callback[name] && typeof callback[name] === 'object') {
                    const entries = Object.entries(callback[name]).filter(([key]) => !StorageUtil.isDangerousKey(key));
                    processingCaches[name] = new Map(entries);
                }
            }
        }
    });

    /**
     * Update the caches that use localStorage (allowed and blocked caches).
     */
    const updateLocalStorage = () => {
        const write = () => {
            const allowedOut = Object.create(null);
            const blockedOut = Object.create(null);

            for (const name of Object.keys(allowedCaches)) {
                allowedOut[name] = Object.fromEntries(allowedCaches[name]);
            }

            for (const name of Object.keys(blockedCaches)) {
                blockedOut[name] = Object.fromEntries(
                    Array.from(blockedCaches[name], ([url, entry]) => [
                        url,
                        {exp: entry.exp, resultType: entry.resultType}
                    ])
                );
            }

            StorageUtil.setToLocalStore(allowedKey, allowedOut);
            StorageUtil.setToLocalStore(blockedKey, blockedOut);
        };

        // Debounce the write operation to avoid excessive writes
        if (localStorageTimeoutID) {
            clearTimeout(localStorageTimeoutID);
        }
        localStorageTimeoutID = setTimeout(write, debounceDelay);
    };

    /**
     * Update the caches that use sessionStorage (processing caches).
     */
    const updateSessionStorage = () => {
        const write = () => {
            const out = Object.create(null);

            for (const name of Object.keys(processingCaches)) {
                out[name] = Object.fromEntries(processingCaches[name]);
            }

            StorageUtil.setToSessionStore(processingKey, out);
        };

        // Debounce the write operation to avoid excessive writes
        if (sessionStorageTimeoutID) {
            clearTimeout(sessionStorageTimeoutID);
        }
        sessionStorageTimeoutID = setTimeout(write, debounceDelay);
    };

    /**
     * Cleans up expired entries from all caches.
     *
     * @returns {number} The number of expired entries removed from all caches.
     */
    const cleanExpiredEntries = () => {
        const now = Date.now();
        let totalRemoved = 0;

        const cleanGroup = (group, onDirty) => {
            let groupRemoved = 0;

            for (const map of Object.values(group)) {
                for (const [key, value] of map.entries()) {
                    const expTime = value && typeof value === 'object' && 'exp' in value ? value.exp : value;

                    // Removes expired keys from the map
                    // Ignores keys with expiration time of 0 (indicating no expiration)
                    if (expTime !== 0 && expTime < now) {
                        map.delete(key);
                        groupRemoved++;
                    }
                }
            }

            // Only trigger storage update if this group had removals
            if (groupRemoved > 0) {
                totalRemoved += groupRemoved;
                onDirty();
            }
        };

        let localDirty = false;
        cleanGroup(allowedCaches, () => {
            localDirty = true;
        });
        cleanGroup(blockedCaches, () => {
            localDirty = true;
        });
        cleanGroup(processingCaches, () => updateSessionStorage());

        if (localDirty) {
            updateLocalStorage();
        }
        return totalRemoved;
    };

    // Run initial cleanup and schedule periodic cleanup
    cleanExpiredEntries();
    setInterval(cleanExpiredEntries, cleanupInterval);

    /**
     * Clears all allowed caches.
     */
    const clearAllowedCache = () => {
        for (const cache of Object.values(allowedCaches)) {
            cache.clear();
        }

        for (const patternCache of Object.values(allowedPatternCaches)) {
            patternCache.clear();
        }

        updateLocalStorage();
    };

    /**
     * Clears all blocked caches.
     */
    const clearBlockedCache = () => {
        for (const cache of Object.values(blockedCaches)) {
            cache.clear();
        }

        updateLocalStorage();
    };

    /**
     * Clears all processing caches.
     */
    const clearProcessingCache = () => {
        for (const cache of Object.values(processingCaches)) {
            cache.clear();
        }

        updateSessionStorage();
    };

    /**
     * Checks if a URL is in the allowed cache for a specific provider.
     *
     * @param {string|URL} url The URL to check, can be a string or a URL object.
     * @param {string} name The name of the provider (e.g., "precisionSec").
     * @returns {boolean} Returns true if the URL is in the allowed cache and not expired, false otherwise.
     */
    const isUrlInAllowedCache = (url, name) => {
        if (name !== "all" && !providersSet.has(name)) {
            console.warn(`Unknown cache provider name: "${name}"`);
            return false;
        }

        try {
            const key = UrlHelpers.normalizeUrl(url);

            if (!key) {
                console.warn(`Invalid URL provided for allowed cache check: ${url}`);
                return false;
            }

            const map = allowedCaches[name];

            if (!map) {
                console.warn(`Allowed cache "${name}" not found`);
                return false;
            }

            if (map.has(key)) {
                const exp = map.get(key);

                if (exp === 0 || exp > Date.now()) {
                    return true;
                }

                // Entry expired, remove it
                map.delete(key);
                updateLocalStorage();
            }
        } catch (error) {
            console.error(`Error checking allowed cache for ${url}:`, error);
        }
        return false;
    };

    /**
     * Checks if a string is in the allowed cache for a specific provider.
     *
     * @param {string} str The string to check against the map's patterns.
     * @param {string} name The name of the provider (e.g., "precisionSec").
     * @returns {boolean} Returns true if the string is in the allowed cache and not expired, false otherwise.
     */
    const isPatternInAllowedCache = (str, name) => {
        if (typeof str !== 'string' || str.length > 2048) {
            console.warn(`Invalid string provided: "${str}"`);
            return false;
        }

        if (name !== "all" && !providersSet.has(name)) {
            console.warn(`Unknown cache provider name: "${name}"`);
            return false;
        }

        try {
            const map = allowedCaches[name];
            const patternCache = allowedPatternCaches[name];

            if (!map || !patternCache) {
                console.warn(`Allowed cache "${name}" not found`);
                return false;
            }

            // O(1) exact-key check
            if (map.has(str)) {
                return true;
            }

            // O(1) wildcard pattern check for *.str
            if (patternCache.has("*." + str)) {
                return true;
            }

            const dotIndex = str.indexOf(".");

            // O(n) wildcard pattern check for str with subdomains (e.g., sub.str)
            if (dotIndex !== -1) {
                const wildcardKey = "*." + str.slice(dotIndex + 1);

                if (patternCache.has(wildcardKey)) {
                    return true;
                }
            }
        } catch (error) {
            console.error(`Error checking allowed cache for string "${str}":`, error);
        }
        return false;
    };

    /**
     * Add a URL to the allowed cache for a specific provider.
     *
     * @param {string|URL} url The URL to add, can be a string or a URL object.
     * @param {string} name The name of the provider (e.g., "precisionSec").
     */
    const addUrlToAllowedCache = (url, name) => {
        if (name !== "all" && !providersSet.has(name)) {
            console.warn(`Unknown cache provider name: "${name}"`);
            return;
        }

        try {
            const key = UrlHelpers.normalizeUrl(url);

            if (!key) {
                console.warn(`Invalid URL provided for allowed cache addition: ${url}`);
                return;
            }

            const expTime = Date.now() + expirationTime * 1000;

            if (name === "all") {
                for (const cache of Object.values(allowedCaches)) {
                    cache.set(key, expTime);
                }
            } else if (allowedCaches[name]) {
                allowedCaches[name].set(key, expTime);
            } else {
                console.warn(`Cache "${name}" not found`);
            }

            updateLocalStorage();
        } catch (error) {
            console.error(`Error adding URL to allowed cache for ${url}:`, error);
        }
    };

    /**
     * Add a string key to the allowed cache for a specific provider.
     *
     * @param {string} str The string to add.
     * @param {string} name The name of the cache (e.g., "precisionSec", "global").
     */
    const addStringToAllowedCache = (str, name) => {
        if (typeof str !== 'string' || str.length > 2048) {
            console.warn(`Invalid string provided for allowed cache string addition: "${str}"`);
            return;
        }

        if (name !== "all" && !providersSet.has(name)) {
            console.warn(`Unknown cache provider name: "${name}"`);
            return;
        }

        try {
            if (name === "all") {
                for (const cache of Object.values(allowedCaches)) {
                    cache.set(str, 0);
                }

                if (str.startsWith("*.")) {
                    for (const patternCache of Object.values(allowedPatternCaches)) {
                        patternCache.add(str);
                    }
                }
            } else if (allowedCaches[name]) {
                allowedCaches[name].set(str, 0);

                if (str.startsWith("*.")) {
                    allowedPatternCaches[name].add(str);
                }
            } else {
                console.warn(`Cache "${name}" not found`);
            }

            updateLocalStorage();
        } catch (error) {
            console.error(`Error adding string to allowed cache for "${str}":`, error);
        }
    };

    /**
     * Checks if a URL is in the blocked cache for a specific provider.
     *
     * @param {string|URL} url The URL to check, can be a string or a URL object.
     * @param {string} name The name of the provider (e.g., "precisionSec").
     * @returns {boolean} Returns true if the URL is in the allowed cache and not expired, false otherwise.
     */
    const isUrlInBlockedCache = (url, name) => {
        if (name !== "all" && !providersSet.has(name)) {
            console.warn(`Unknown cache provider name: "${name}"`);
            return false;
        }

        try {
            const key = UrlHelpers.normalizeUrl(url);

            if (!key) {
                console.warn(`Invalid URL provided for blocked cache check: ${url}`);
                return false;
            }

            const map = blockedCaches[name];

            if (!map?.has(key)) {
                return false;
            }

            const entry = map.get(key);

            if (entry.exp === 0 || entry.exp > Date.now()) {
                return true;
            }

            // Entry expired, remove it
            map.delete(key);
            updateLocalStorage();
        } catch (error) {
            console.error(`Error checking blocked cache for ${url}:`, error);
        }
        return false;
    };

    /**
     * Add a URL to the blocked cache for a specific provider.
     *
     * @param {string|URL} url The URL to add, can be a string or a URL object.
     * @param {string} name The name of the provider (e.g., "precisionSec").
     * @param {string} resultType The resultType of the URL (e.g., "malicious", "phishing").
     */
    const addUrlToBlockedCache = (url, name, resultType) => {
        if (name !== "all" && !providersSet.has(name)) {
            console.warn(`Unknown cache provider name: "${name}"`);
            return;
        }

        if (!Number.isFinite(resultType)) {
            console.warn(`Invalid resultType provided for blocked cache addition: ${resultType}`);
            return;
        }

        try {
            const key = UrlHelpers.normalizeUrl(url);

            if (!key) {
                console.warn(`Invalid URL provided for blocked cache addition: ${url}`);
                return;
            }

            const expTime = Date.now() + expirationTime * 1000;
            const cache = blockedCaches[name];

            if (name === "all") {
                for (const providerCache of Object.values(blockedCaches)) {
                    providerCache.set(key, {exp: expTime, resultType});
                }
            } else if (cache) {
                cache.set(key, {exp: expTime, resultType});
            } else {
                console.warn(`Cache "${name}" not found`);
            }

            updateLocalStorage();
        } catch (error) {
            console.error(`Error adding URL to blocked cache for ${url}:`, error);
        }
    };

    /**
     * Get the result type of a blocked URL from the cache for a specific provider.
     *
     * @param {string|URL} url The URL to check, can be a string or a URL object.
     * @param {string} name The name of the provider (e.g., "precisionSec").
     * @returns {*|null} Returns the result type (e.g., "Malicious", "Phishing") if found and not expired, null otherwise.
     */
    const getBlockedResultType = (url, name) => {
        if (name !== "all" && !providersSet.has(name)) {
            console.warn(`Unknown cache provider name: "${name}"`);
            return ProtectionResult.ResultType.FAILED;
        }

        try {
            const key = UrlHelpers.normalizeUrl(url);

            if (!key) {
                console.warn(`Invalid URL provided for getting blocked result type: ${url}`);
                return ProtectionResult.ResultType.FAILED;
            }

            const cache = blockedCaches[name];

            if (!cache?.has(key)) {
                return ProtectionResult.ResultType.FAILED;
            }

            const entry = cache.get(key);

            if (entry.exp === 0 || entry.exp > Date.now()) {
                return entry.resultType;
            }

            // Entry expired, remove it
            cache.delete(key);
            updateLocalStorage();
        } catch (error) {
            console.error(`Error getting blocked result type for ${url}:`, error);
            console.warn(`Returning default result type for ${url} in provider "${name}" due to error`);
        }
        return ProtectionResult.ResultType.FAILED;
    };

    /**
     * Remove a URL from the blocked cache for a specific provider.
     *
     * @param {string|URL} url The URL to remove, can be a string or a URL object.
     * @param {string} name The name of the provider (e.g., "precisionSec").
     */
    const removeUrlFromBlockedCache = (url, name) => {
        if (name !== "all" && !providersSet.has(name)) {
            console.warn(`Unknown cache provider name: "${name}"`);
            return;
        }

        try {
            const key = UrlHelpers.normalizeUrl(url);

            if (!key) {
                console.warn(`Invalid URL provided for blocked cache removal: ${url}`);
                return;
            }

            if (name === "all") {
                for (const cache of Object.values(blockedCaches)) {
                    cache.delete(key);
                }
            } else if (blockedCaches[name]) {
                blockedCaches[name].delete(key);
            } else {
                console.warn(`Cache "${name}" not found`);
            }

            updateLocalStorage();
        } catch (error) {
            console.error(`Error removing URL from blocked cache for ${url}:`, error);
        }
    };

    /**
     * Checks if a URL is in the processing cache for a specific provider.
     *
     * @param {string|URL} url The URL to check, can be a string or a URL object.
     * @param {string} name The name of the provider (e.g., "precisionSec").
     * @returns {boolean} Returns true if the URL is in the processing cache and not expired, false otherwise.
     */
    const isUrlInProcessingCache = (url, name) => {
        if (name !== "all" && !providersSet.has(name)) {
            console.warn(`Unknown cache provider name: "${name}"`);
            return false;
        }

        try {
            const key = UrlHelpers.normalizeUrl(url);

            if (!key) {
                console.warn(`Invalid URL provided for processing cache check: ${url}`);
                return false;
            }

            const map = processingCaches[name];

            if (!map) {
                console.warn(`Processing cache "${name}" not found`);
                return false;
            }

            if (map.has(key)) {
                const entry = map.get(key);

                if (entry.exp > Date.now()) {
                    return true;
                }

                // Entry expired, remove it
                map.delete(key);
                updateSessionStorage();
            }
        } catch (error) {
            console.error(`Error checking processing cache for ${url}:`, error);
        }
        return false;
    };

    /**
     * Add a URL to the processing cache, associating it with a specific tabId.
     *
     * @param {string|URL} url The URL to add, can be a string or a URL object.
     * @param {string} name The name of the provider (e.g., "precisionSec").
     * @param {number} tabId The ID of the tab associated with this URL.
     */
    const addUrlToProcessingCache = (url, name, tabId) => {
        if (name !== "all" && !providersSet.has(name)) {
            console.warn(`Unknown cache provider name: "${name}"`);
            return;
        }

        try {
            const key = UrlHelpers.normalizeUrl(url);

            if (!key) {
                console.warn(`Invalid URL provided for processing cache addition: ${url}`);
                return;
            }

            const expTime = Date.now() + 60 * 1000; // Expiration for processing cache is 60 seconds
            const entry = {exp: expTime, tabId};

            if (name === "all") {
                for (const cache of Object.values(processingCaches)) {
                    cache.set(key, entry);
                }
            } else if (processingCaches[name]) {
                processingCaches[name].set(key, entry);
            } else {
                console.warn(`Processing cache "${name}" not found`);
            }

            updateSessionStorage();
        } catch (error) {
            console.error(`Error adding URL to processing cache for ${url}:`, error);
        }
    };

    /**
     * Remove a URL from the processing cache for a specific provider.
     *
     * @param {string|URL} url The URL to remove, can be a string or a URL object.
     * @param {string} name The name of the provider (e.g., "precisionSec").
     */
    const removeUrlFromProcessingCache = (url, name) => {
        if (name !== "all" && !providersSet.has(name)) {
            console.warn(`Unknown cache provider name: "${name}"`);
            return;
        }

        try {
            const key = UrlHelpers.normalizeUrl(url);

            if (!key) {
                console.warn(`Invalid URL provided for processing cache removal: ${url}`);
                return;
            }

            if (name === "all") {
                for (const cache of Object.values(processingCaches)) {
                    cache.delete(key);
                }
            } else if (processingCaches[name]) {
                processingCaches[name].delete(key);
            } else {
                console.warn(`Processing cache "${name}" not found`);
            }

            updateSessionStorage();
        } catch (error) {
            console.error(`Error removing URL from processing cache for ${url}:`, error);
        }
    };

    /**
     * Remove all entries in the processing cache for all keys associated with a specific tabId.
     *
     * @param {number} tabId The ID of the tab whose entries should be removed.
     */
    const removeKeysByTabId = tabId => {
        let removedCount = 0;

        for (const name of Object.keys(processingCaches)) {
            const map = processingCaches[name];

            if (!map) {
                console.warn(`Processing cache "${name}" not found`);
                continue;
            }

            const toRemove = [];

            for (const [key, entry] of map.entries()) {
                if (entry.tabId === tabId) {
                    toRemove.push(key);
                }
            }

            for (const key of toRemove) {
                map.delete(key);
                removedCount++;
            }
        }

        // Persist the changes to session storage
        if (removedCount > 0) {
            console.debug(`Removed ${removedCount} entries from processing cache for tab ID ${tabId}`);
            updateSessionStorage();
        }
    };

    return Object.freeze({
        clearAllowedCache,
        clearBlockedCache,
        clearProcessingCache,
        isUrlInAllowedCache,
        isPatternInAllowedCache,
        addUrlToAllowedCache,
        addStringToAllowedCache,
        isUrlInBlockedCache,
        addUrlToBlockedCache,
        getBlockedResultType,
        removeUrlFromBlockedCache,
        isUrlInProcessingCache,
        addUrlToProcessingCache,
        removeUrlFromProcessingCache,
        removeKeysByTabId
    });
})();
