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
    let allowedKey = "allowedCache";
    let blockedKey = "blockedCache";
    let processingKey = "processingCache";

    // Caches for allowed, blocked, and processing entries
    let allowedCaches = {};
    let blockedCaches = {};
    let processingCaches = {};

    // Timeout ID for debounced updates
    let localStorageTimeoutID = null;
    let sessionStorageTimeoutID = null;

    // Debounce delay for local and session storage updates
    let debounceDelay = 100;

    // Expiration time for cache entries in milliseconds
    let expirationTime;

    // Sets the expiration time for cache entries based on user settings
    Settings.get(settings => {
        const expSeconds = Number(settings?.cacheExpirationSeconds);
        const min = 60;
        const def = 86400;
        expirationTime = Number.isFinite(expSeconds) && expSeconds >= min ? expSeconds : def;
    });

    const providers = [
        // Global
        "global",

        // Official Partners
        "adGuardSecurity", "adGuardFamily",
        "alphaMountain",
        "precisionSec",

        // Non-Partnered Providers
        "certEE",
        "cleanBrowsingSecurity", "cleanBrowsingFamily",
        "cloudflareSecurity", "cloudflareFamily",
        "controlDSecurity", "controlDFamily",
        "dns4EUSecurity", "dns4EUFamily",
        "quad9",
    ];

    // Initialize caches for each provider
    for (const name of providers) {
        allowedCaches[name] = new Map();
        blockedCaches[name] = new Map();
        processingCaches[name] = new Map();
    }

    // Load allowed caches (without tabId) from local storage
    StorageUtil.getFromLocalStore(allowedKey, storedAllowed => {
        if (storedAllowed) {
            for (const name of Object.keys(allowedCaches)) {
                if (storedAllowed[name]) {
                    allowedCaches[name] = new Map(Object.entries(storedAllowed[name]));
                }
            }
        }
    });

    // Load blocked caches (without tabId) from local storage
    StorageUtil.getFromLocalStore(blockedKey, storedBlocked => {
        if (storedBlocked) {
            for (const name of Object.keys(blockedCaches)) {
                if (storedBlocked[name]) {
                    blockedCaches[name] = new Map(
                        Object.entries(storedBlocked[name]).map(([url, entry]) => [
                            url, {exp: entry.exp, resultType: entry.resultType}
                        ])
                    );
                }
            }
        }
    });

    // Load processing caches (with tabId) from session storage
    StorageUtil.getFromSessionStore(processingKey, storedProcessing => {
        if (storedProcessing) {
            for (const name of Object.keys(processingCaches)) {
                if (storedProcessing[name]) {
                    processingCaches[name] = new Map(Object.entries(storedProcessing[name]));
                }
            }
        }
    });

    /**
     * Update the caches that use localStorage (allowed and blocked caches).
     */
    const updateLocalStorage = () => {
        // Checks if the allowed caches are valid
        if (!allowedCaches || typeof allowedCaches !== 'object') {
            console.warn('allowedCache is not defined or not an object');
            return;
        }

        // Checks if the blocked caches are valid
        if (!blockedCaches || typeof blockedCaches !== 'object') {
            console.warn('blockedCache is not defined or not an object');
            return;
        }

        const write = () => {
            const allowedOut = {};
            const blockedOut = {};

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
        // Checks if the processing cache is valid
        if (!processingCaches || typeof processingCaches !== 'object') {
            console.warn('processingCache is not defined or not an object');
            return;
        }

        const write = () => {
            const out = {};

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
     * @returns {number} - The number of expired entries removed from all caches.
     */
    const cleanExpiredEntries = () => {
        const now = Date.now();
        let removed = 0;

        const cleanGroup = (group, onDirty) => {
            for (const map of Object.values(group)) {
                for (const [key, value] of map.entries()) {
                    const expTime = value && typeof value === 'object' && 'exp' in value ? value.exp : value;

                    // Removes expired keys from the map
                    // Ignores keys with expiration time of 0 (indicating no expiration)
                    if (expTime !== 0 && expTime < now) {
                        map.delete(key);
                        removed++;
                    }
                }
            }

            // Sets the dirty flag if keys were removed
            if (removed > 0) {
                onDirty(true);
            }
        };

        cleanGroup(allowedCaches, () => updateLocalStorage());
        cleanGroup(blockedCaches, () => updateLocalStorage());
        cleanGroup(processingCaches, () => updateSessionStorage());
        return removed;
    };

    /**
     * Clears all allowed caches.
     */
    const clearAllowedCache = () => {
        // Returns if the allowed cache is not defined
        if (!allowedCaches || typeof allowedCaches !== 'object') {
            console.warn('allowedCache is not defined or not an object');
            return;
        }

        // Clears all allowed caches
        for (const cache of Object.values(allowedCaches)) {
            cache.clear();
        }

        updateLocalStorage();
    };

    /**
     * Clears all blocked caches.
     */
    const clearBlockedCache = () => {
        // Returns if the blocked cache is not defined
        if (!blockedCaches || typeof blockedCaches !== 'object') {
            console.warn('blockedCache is not defined or not an object');
            return;
        }

        // Clears all blocked caches
        for (const cache of Object.values(blockedCaches)) {
            cache.clear();
        }

        updateLocalStorage();
    };

    /**
     * Clears all processing caches.
     */
    const clearProcessingCache = () => {
        // Checks if the processing cache is valid
        if (!processingCaches || typeof processingCaches !== 'object') {
            console.warn('processingCache is not defined or not an object');
            return;
        }

        // Clears all processing caches
        for (const cache of Object.values(processingCaches)) {
            cache.clear();
        }

        updateSessionStorage();
    };

    /**
     * Checks if a URL is in the allowed cache for a specific provider.
     *
     * @param url {string|URL} - The URL to check, can be a string or a URL object.
     * @param name {string} - The name of the provider (e.g., "precisionSec").
     * @returns {boolean} - Returns true if the URL is in the allowed cache and not expired, false otherwise.
     */
    const isUrlInAllowedCache = (url, name) => {
        // Returns if the allowed cache is not defined.
        if (!allowedCaches || typeof allowedCaches !== 'object') {
            console.warn('allowedCache is not defined or not an object');
            return false;
        }

        try {
            const key = UrlHelpers.normalizeUrl(url);
            const map = allowedCaches[name];

            if (!map) {
                return false;
            }

            if (map.has(key)) {
                const exp = map.get(key);

                if (exp > Date.now()) {
                    return true;
                }

                map.delete(key);
                cleanExpiredEntries();
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
     * @param str {string} - The string to check.
     * @param name {string} - The name of the provider (e.g., "precisionSec").
     * @returns {boolean} - Returns true if the string is in the allowed cache and not expired, false otherwise.
     */
    const isStringInAllowedCache = (str, name) => {
        // Returns if the allowed cache is not defined.
        if (!allowedCaches || typeof allowedCaches !== 'object') {
            console.warn('allowedCache is not defined or not an object');
            return false;
        }

        try {
            const map = allowedCaches[name];

            if (!map) {
                return false;
            }

            if (map.has(str)) {
                return true;
            }
        } catch (error) {
            console.error(`Error checking allowed cache for string "${str}":`, error);
        }
        return false;
    };

    /**
     * Checks if a string is in the allowed cache for a specific provider.
     *
     * @param str {string} - The string to check against the map's patterns.
     * @param name {string} - The name of the provider (e.g., "precisionSec").
     * @returns {boolean} - Returns true if the string is in the allowed cache and not expired, false otherwise.
     */
    const isPatternInAllowedCache = (str, name) => {
        // Returns if the allowed cache is not defined.
        if (!allowedCaches || typeof allowedCaches !== 'object') {
            console.warn('allowedCache is not defined or not an object');
            return false;
        }

        try {
            const map = allowedCaches[name];

            if (!map) {
                return false;
            }

            // Checks if any key in the map (patterns, like *.example.com) matches the string
            for (const pattern of map.keys()) {
                // Uses a simple pattern matching logic
                if (pattern.startsWith("*.")) {
                    const domain = pattern.slice(2);

                    if (str === domain || str.endsWith("." + domain)) {
                        return true;
                    }
                } else if (str === pattern) {
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
     * @param url {string|URL} - The URL to add, can be a string or a URL object.
     * @param name {string} - The name of the provider (e.g., "precisionSec").
     */
    const addUrlToAllowedCache = (url, name) => {
        // Returns if the allowed cache is not defined.
        if (!allowedCaches || typeof allowedCaches !== 'object') {
            console.warn('allowedCache is not defined or not an object');
            return;
        }

        try {
            const key = UrlHelpers.normalizeUrl(url);
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

            cleanExpiredEntries();
            updateLocalStorage();
        } catch (error) {
            console.error(`Error adding URL to allowed cache for ${url}:`, error);
        }
    };

    /**
     * Add a string key to the allowed cache for a specific provider.
     *
     * @param str {string} - The string to add.
     * @param name {string} - The name of the cache (e.g., "precisionSec", "global").
     */
    const addStringToAllowedCache = (str, name) => {
        // Returns if the allowed cache is not defined.
        if (!allowedCaches || typeof allowedCaches !== 'object') {
            console.warn('allowedCache is not defined or not an object');
            return;
        }

        try {
            const expTime = 0;

            if (name === "all") {
                for (const cache of Object.values(allowedCaches)) {
                    cache.set(str, expTime);
                }
            } else if (allowedCaches[name]) {
                allowedCaches[name].set(str, expTime);
            } else {
                console.warn(`Cache "${name}" not found`);
            }

            cleanExpiredEntries();
            updateLocalStorage();
        } catch (error) {
            console.error(`Error adding string to allowed cache for "${str}":`, error);
        }
    };

    /**
     * Checks if a URL is in the blocked cache for a specific provider.
     *
     * @param url {string|URL} - The URL to check, can be a string or a URL object.
     * @param name {string} - The name of the provider (e.g., "precisionSec").
     * @returns {boolean} - Returns true if the URL is in the allowed cache and not expired, false otherwise.
     */
    const isUrlInBlockedCache = (url, name) => {
        // Returns if the blocked cache is not defined.
        if (!blockedCaches || typeof blockedCaches !== 'object') {
            console.warn('blockedCache is not defined or not an object');
            return false;
        }

        try {
            const key = UrlHelpers.normalizeUrl(url);
            const map = blockedCaches[name];

            if (!map?.has(key)) {
                return false;
            }

            const entry = map.get(key);

            if (entry.exp > Date.now()) {
                return true;
            }

            map.delete(key);
            cleanExpiredEntries();
            updateLocalStorage();
        } catch (error) {
            console.error(`Error checking blocked cache for ${url}:`, error);
        }
        return false;
    };

    /**
     * Add a URL to the blocked cache for a specific provider.
     *
     * @param url {string|URL} - The URL to add, can be a string or a URL object.
     * @param name {string} - The name of the provider (e.g., "precisionSec").
     * @param resultType {string} - The resultType of the URL (e.g., "malicious", "phishing").
     */
    const addUrlToBlockedCache = (url, name, resultType) => {
        // Returns if the blocked cache is not defined.
        if (!blockedCaches || typeof blockedCaches !== 'object') {
            console.warn('blockedCache is not defined or not an object');
            return;
        }

        try {
            const key = UrlHelpers.normalizeUrl(url);
            const expTime = Date.now() + expirationTime * 1000;
            const cache = blockedCaches[name];

            if (name === "all") {
                for (const cache of Object.values(blockedCaches)) {
                    cache.set(key, {exp: expTime, resultType: resultType});
                }
            } else if (cache) {
                cache.set(key, {exp: expTime, resultType: resultType});
            } else {
                console.warn(`Cache "${name}" not found`);
            }

            cleanExpiredEntries();
            updateLocalStorage();
        } catch (error) {
            console.error(`Error adding URL to blocked cache for ${url}:`, error);
        }
    };

    /**
     * Get the result type of a blocked URL from the cache for a specific provider.
     *
     * @param url {string|URL} - The URL to check, can be a string or a URL object.
     * @param name {string} - The name of the provider (e.g., "precisionSec").
     * @returns {*|null} - Returns the result type (e.g., "Malicious", "Phishing") if found and not expired, null otherwise.
     */
    const getBlockedResultType = (url, name) => {
        // Returns if the blocked cache is not defined.
        if (!blockedCaches || typeof blockedCaches !== 'object') {
            console.warn('blockedCache is not defined or not an object');
            return null;
        }

        try {
            const key = UrlHelpers.normalizeUrl(url);
            const cache = blockedCaches[name];

            if (!cache?.has(key)) {
                return null;
            }

            const entry = cache.get(key);

            if (entry.exp > Date.now()) {
                return entry.resultType;
            } else {
                cache.delete(key);
                cleanExpiredEntries();
                updateLocalStorage();
            }
        } catch (error) {
            console.error(`Error getting blocked result type for ${url}:`, error);
        }
        return null;
    };

    /**
     * Remove a URL from the blocked cache for a specific provider.
     *
     * @param url {string|URL} - The URL to remove, can be a string or a URL object.
     * @param name {string} - The name of the provider (e.g., "precisionSec").
     */
    const removeUrlFromBlockedCache = (url, name) => {
        // Returns if the blocked cache is not defined.
        if (!blockedCaches || typeof blockedCaches !== 'object') {
            console.warn('blockedCache is not defined or not an object');
            return;
        }

        try {
            const key = UrlHelpers.normalizeUrl(url);

            if (name === "all") {
                for (const cache of Object.values(blockedCaches)) {
                    cache.delete(key);
                }
            } else if (blockedCaches[name]) {
                blockedCaches[name].delete(key);
            } else {
                console.warn(`Cache "${name}" not found`);
            }

            cleanExpiredEntries();
            updateLocalStorage();
        } catch (error) {
            console.error(`Error removing URL from blocked cache for ${url}:`, error);
        }
    };

    /**
     * Checks if a URL is in the processing cache for a specific provider.
     *
     * @param url {string|URL} - The URL to check, can be a string or a URL object.
     * @param name {string} - The name of the provider (e.g., "precisionSec").
     * @returns {boolean} - Returns true if the URL is in the processing cache and not expired, false otherwise.
     */
    const isUrlInProcessingCache = (url, name) => {
        // Checks if the processing cache is valid
        if (!processingCaches || typeof processingCaches !== 'object') {
            console.warn('processingCaches is not defined or not an object');
            return false;
        }

        try {
            const key = UrlHelpers.normalizeUrl(url);
            const map = processingCaches[name];

            if (!map) {
                return false;
            }

            if (map.has(key)) {
                const entry = map.get(key);

                if (entry.exp > Date.now()) {
                    return true;
                }

                map.delete(key);
                cleanExpiredEntries();
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
     * @param {string|URL} url - The URL to add, can be a string or a URL object.
     * @param {string} name - The name of the provider (e.g., "precisionSec").
     * @param {number} tabId - The ID of the tab associated with this URL.
     */
    const addUrlToProcessingCache = (url, name, tabId) => {
        // Checks if the processing cache is valid
        if (!processingCaches || typeof processingCaches !== 'object') {
            console.warn('processingCaches is not defined or not an object');
            return;
        }

        try {
            const key = UrlHelpers.normalizeUrl(url);
            const expTime = Date.now() + 60 * 1000; // Expiration for processing cache is 60 seconds
            const entry = {exp: expTime, tabId: tabId};

            if (name === "all") {
                for (const cache of Object.values(processingCaches)) {
                    cache.set(key, entry);
                }
            } else if (processingCaches[name]) {
                processingCaches[name].set(key, entry);
            } else {
                console.warn(`Processing cache "${name}" not found`);
            }

            cleanExpiredEntries();
            updateSessionStorage();
        } catch (error) {
            console.error(`Error adding URL to processing cache for ${url}:`, error);
        }
    };

    /**
     * Remove a URL from the processing cache for a specific provider.
     *
     * @param url {string|URL} - The URL to remove, can be a string or a URL object.
     * @param name {string} - The name of the provider (e.g., "precisionSec").
     */
    const removeUrlFromProcessingCache = (url, name) => {
        // Checks if the processing cache is valid
        if (!processingCaches || typeof processingCaches !== 'object') {
            console.warn('processingCaches is not defined or not an object');
            return;
        }

        try {
            const key = UrlHelpers.normalizeUrl(url);

            if (name === "all") {
                for (const cache of Object.values(processingCaches)) {
                    cache.delete(key);
                }
            } else if (processingCaches[name]) {
                processingCaches[name].delete(key);
            } else {
                console.warn(`Processing cache "${name}" not found`);
            }

            cleanExpiredEntries();
            updateSessionStorage();
        } catch (error) {
            console.error(`Error removing URL from processing cache for ${url}:`, error);
        }
    };

    /**
     * Retrieve all normalized-URL keys (or string keys) in the processing cache for a given provider
     * that are associated with the specified tabId and not yet expired.
     *
     * @param {string} name - The name of the provider (e.g., "precisionSec").
     * @param {number} tabId - The ID of the tab to filter by.
     * @returns {string[]} - An array of keys (normalized URLs or strings) that match the criteria.
     */
    const getKeysByTabId = (name, tabId) => {
        // Checks if the processing cache is valid
        if (!processingCaches || typeof processingCaches !== 'object') {
            console.warn('processingCaches is not defined or not an object');
            return [];
        }

        const results = [];
        const map = processingCaches[name];

        // Checks if the map is valid
        if (!map) {
            return results;
        }

        const now = Date.now();

        // Removes expired keys from the map
        for (const [key, entry] of map.entries()) {
            if (entry.tabId === tabId) {
                if (entry.exp > now) {
                    results.push(key);
                } else {
                    map.delete(key);
                }
            }
        }

        cleanExpiredEntries();
        updateSessionStorage();
        return results;
    };

    /**
     * Remove all entries in the processing cache for all keys associated with a specific tabId.
     *
     * @param tabId - The ID of the tab whose entries should be removed.
     */
    const removeKeysByTabId = tabId => {
        // Checks if the processing cache is valid
        if (!processingCaches || typeof processingCaches !== 'object') {
            console.warn('processingCaches is not defined or not an object');
            return;
        }

        let removedCount = 0;

        for (const name of Object.keys(processingCaches)) {
            const map = processingCaches[name];

            // Checks if the cache is valid
            if (!map) {
                continue;
            }

            for (const [key, entry] of map.entries()) {
                if (entry.tabId === tabId) {
                    removedCount++;
                    map.delete(key);
                }
            }
        }

        // Persist the changes to session storage
        if (removedCount > 0) {
            console.debug(`Removed ${removedCount} entries from processing cache for tab ID ${tabId}`);
            updateSessionStorage();
        }
    };

    return {
        clearAllowedCache,
        clearBlockedCache,
        clearProcessingCache,
        isUrlInAllowedCache,
        isStringInAllowedCache,
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
        getKeysByTabId,
        removeKeysByTabId,
    };
})();
