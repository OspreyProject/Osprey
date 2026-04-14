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

globalThis.OspreyCacheService = (() => {
    // Global variables
    const browserAPI = globalThis.OspreyBrowserAPI;
    const urlService = globalThis.OspreyUrlService;
    const protectionResult = globalThis.OspreyProtectionResult;

    const cacheKey = "osprey_cache";
    let cacheSnapshot = null;
    let loadingPromise = null;
    let flushTimer = null;
    let flushPromise = null;
    let flushResolver = null;

    const processing = new Map();
    const defaultSnapshot = () => ({version: 2, globalAllowPatterns: [], providers: {}});

    const normalizeEntryMap = value => !value || typeof value !== "object" ? {} : Object.fromEntries(
        Object.entries(value).filter(([, entry]) => entry && typeof entry === "object")
    );

    const normalizeProvider = record => ({
        allowed: normalizeEntryMap(record?.allowed),
        blocked: normalizeEntryMap(record?.blocked),
    });

    const normalizePatterns = value => Array.isArray(value) ?
        value.filter(pattern => typeof pattern === "string" && pattern.startsWith("*.")) : [];

    const normalizeSnapshot = input => {
        const value = input && typeof input === "object" ? input : {};
        const providers = value.providers && typeof value.providers === "object" ?
            Object.fromEntries(Object.entries(value.providers).map(([providerId, record]) => [providerId, normalizeProvider(record)])) : {};

        return {...defaultSnapshot(), globalAllowPatterns: normalizePatterns(value.globalAllowPatterns), providers};
    };

    const ensureProvider = (snapshot, providerId) => {
        if (!snapshot.providers[providerId]) {
            snapshot.providers[providerId] = normalizeProvider();
        }
        return snapshot.providers[providerId];
    };

    const getRecord = (snapshot, providerId, type, lookupKey) => snapshot.providers?.[providerId]?.[type]?.[lookupKey] || null;

    const setRecord = async (providerId, type, lookupKey, record) => {
        const snapshot = await getSnapshot();
        ensureProvider(snapshot, providerId)[type][lookupKey] = record;
        scheduleFlush();
    };

    const deleteRecord = async (providerId, type, lookupKey) => {
        const snapshot = await getSnapshot();
        const records = snapshot.providers?.[providerId]?.[type];

        if (!records?.[lookupKey]) {
            return;
        }

        delete records[lookupKey];
        scheduleFlush();
    };

    const createEntryGetter = type => async (providerId, lookupKey) => getRecord(await getSnapshot(), providerId, type, lookupKey);
    const createEntryMarker = (type, createRecord) => async (providerId, lookupKey, ...args) => setRecord(providerId, type, lookupKey, createRecord(...args));
    const processingKey = (providerId, lookupKey) => `${providerId}::${lookupKey}`;

    const flush = async () => {
        if (flushTimer) {
            clearTimeout(flushTimer);
            flushTimer = null;
        }

        if (!flushPromise) {
            flushPromise = new Promise(resolve => {
                flushResolver = resolve;
            });
        }

        try {
            await browserAPI.storageSet("local", {[cacheKey]: cacheSnapshot});
        } catch (error) {
            console.error("OspreyCacheService failed to persist cache snapshot", error);
        } finally {
            flushResolver?.();
            flushResolver = null;
            flushPromise = null;
        }
    };

    const scheduleFlush = (delayMs = 150) => {
        if (flushTimer) {
            clearTimeout(flushTimer);
        }

        flushTimer = setTimeout(() => {
            flushTimer = null;
            flush();
        }, delayMs);

        if (!flushPromise) {
            flushPromise = new Promise(resolve => {
                flushResolver = resolve;
            });
        }

        return flushPromise;
    };

    const loadSnapshot = async () => {
        const stored = await browserAPI.storageGet("local", cacheKey).catch(() => ({}));
        return normalizeSnapshot(stored?.[cacheKey]);
    };

    const resolveLoadingSnapshot = () => loadSnapshot()
        .then(snapshot => {
            cacheSnapshot = snapshot;
            loadingPromise = null;
            return snapshot;
        })
        .catch(error => {
            loadingPromise = null;
            console.error("OspreyCacheService failed to load cache snapshot", error);
            throw error;
        });

    const getSnapshot = async ({fresh = false} = {}) => {
        if (!fresh && cacheSnapshot) {
            return cacheSnapshot;
        }

        if (fresh || !loadingPromise) {
            loadingPromise = resolveLoadingSnapshot();
        }
        return await loadingPromise;
    };

    const pruneExpiredEntries = (entries, now) => {
        let removed = false;

        for (const [key, entry] of Object.entries(entries || {})) {
            if (!entry || Number(entry.exp) < now) {
                delete entries[key];
                removed = true;
            }
        }
        return removed;
    };

    const cleanupExpired = async () => {
        const snapshot = await getSnapshot();
        const now = Date.now();
        let dirty = false;

        for (const provider of Object.values(snapshot.providers)) {
            dirty = pruneExpiredEntries(provider.allowed, now) || dirty;
            dirty = pruneExpiredEntries(provider.blocked, now) || dirty;
        }

        if (dirty) {
            await flush();
        }
    };

    const matchesGlobalPattern = async url => {
        const snapshot = await getSnapshot();
        const parsed = url instanceof URL ? url : urlService.parseHttpUrl(url);

        if (!parsed) {
            return false;
        }

        const hostname = urlService.canonicalizeHostname(parsed.hostname);

        return snapshot.globalAllowPatterns.some(pattern => {
            const canonicalPattern = urlService.canonicalizeHostname(pattern.slice(2));
            return hostname === canonicalPattern || hostname.endsWith(`.${canonicalPattern}`);
        });
    };

    const getAllowedEntry = createEntryGetter("allowed");
    const getBlockedEntry = createEntryGetter("blocked");
    const markAllowed = createEntryMarker("allowed", expirationSeconds => ({exp: Date.now() + expirationSeconds * 1000}));

    const markBlocked = createEntryMarker("blocked", (result, expirationSeconds) => ({
        exp: Date.now() + expirationSeconds * 1000,
        result,
    }));

    const allowPattern = async pattern => {
        const snapshot = await getSnapshot();

        if (!snapshot.globalAllowPatterns.includes(pattern)) {
            snapshot.globalAllowPatterns.push(pattern);
            await scheduleFlush();
        }
    };

    const clearAll = async () => {
        cacheSnapshot = defaultSnapshot();
        processing.clear();
        await flush();
    };

    const clearBlockedForLookup = async lookupKey => {
        const snapshot = await getSnapshot();
        let removed = 0;

        for (const provider of Object.values(snapshot.providers)) {
            if (provider?.blocked && Object.hasOwn(provider.blocked, lookupKey)) {
                delete provider.blocked[lookupKey];
                removed += 1;
            }
        }

        if (!removed) {
            return;
        }

        await scheduleFlush();
    };

    const clearBlockedForProviderLookup = (providerId, lookupKey) => deleteRecord(providerId, "blocked", lookupKey);

    const isProcessing = (providerId, lookupKey) => {
        const key = processingKey(providerId, lookupKey);
        const entry = processing.get(key);

        if (!entry) {
            return false;
        }

        if (entry.exp < Date.now()) {
            processing.delete(key);
            return false;
        }
        return true;
    };

    const markProcessing = (providerId, lookupKey, tabId = 0) => {
        processing.set(processingKey(providerId, lookupKey), {exp: Date.now() + 60000, tabId});
    };

    const clearProcessing = (providerId, lookupKey) => {
        processing.delete(processingKey(providerId, lookupKey));
    };

    const clearProcessingByTab = tabId => {
        for (const [key, entry] of processing.entries()) {
            if (entry.tabId === tabId) {
                processing.delete(key);
            }
        }
    };


    const storeOutcomes = async (entries, expirationSeconds) => {
        if (!Array.isArray(entries) || entries.length === 0) {
            return;
        }

        const snapshot = await getSnapshot();
        const expiry = Date.now() + Number(expirationSeconds || 0) * 1000;

        for (const entry of entries) {
            const providerId = String(entry?.providerId || '');
            const lookupKey = String(entry?.lookupKey || '');

            if (!providerId || !lookupKey) {
                continue;
            }

            const providerRecord = ensureProvider(snapshot, providerId);
            delete providerRecord.allowed[lookupKey];
            delete providerRecord.blocked[lookupKey];

            if (protectionResult.blockingResults.has(entry?.outcome)) {
                providerRecord.blocked[lookupKey] = {exp: expiry, result: entry.outcome};
            } else {
                providerRecord.allowed[lookupKey] = {exp: expiry};
            }
        }

        await scheduleFlush();
    };

    // Run cache cleanup on a 5-minute interval rather than on every read
    setInterval(cleanupExpired, 5 * 60 * 1000);

    // Public API
    return Object.freeze({
        matchesGlobalPattern,
        getAllowedEntry,
        getBlockedEntry,
        markAllowed,
        markBlocked,
        allowPattern,
        clearAll,
        clearBlockedForLookup,
        clearBlockedForProviderLookup,
        isProcessing,
        markProcessing,
        clearProcessing,
        clearProcessingByTab,
        storeOutcomes,
        flush,
    });
})();
