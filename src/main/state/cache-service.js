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
    const timer = globalThis.OspreyTimer;

    const cacheKey = "osprey_cache";
    const metaKey = cacheKey;
    const shardPrefix = `${cacheKey}::p::`;
    const shardKey = providerId => `${shardPrefix}${providerId}`;
    const flushDelay = 500;

    let cacheSnapshot = null;
    let loadingPromise = null;
    let flushTimer = null;
    let flushPromise = null;
    let flushResolver = null;

    const dirtyProviders = new Set();
    let metaDirty = false;

    const processing = new Map();
    const defaultSnapshot = () => ({version: 2, globalAllowPatterns: [], providers: {}});

    const markProviderDirty = providerId => {
        if (providerId) {
            dirtyProviders.add(providerId);
        }
    };

    const markMetaDirty = () => {
        metaDirty = true;
    };

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

        return {
            ...defaultSnapshot(),
            globalAllowPatterns: normalizePatterns(value.globalAllowPatterns),
            providers
        };
    };

    const ensureProvider = (snapshot, providerId) => {
        if (!snapshot.providers[providerId]) {
            snapshot.providers[providerId] = normalizeProvider();
            markMetaDirty();
        }
        return snapshot.providers[providerId];
    };

    const getRecord = (snapshot, providerId, type, lookupKey) => snapshot.providers?.[providerId]?.[type]?.[lookupKey] || null;

    const setRecord = async (providerId, type, lookupKey, record) => {
        const snapshot = await getSnapshot();
        ensureProvider(snapshot, providerId)[type][lookupKey] = record;
        markProviderDirty(providerId);
        scheduleFlush();
    };

    const deleteRecord = async (providerId, type, lookupKey) => {
        const snapshot = await getSnapshot();
        const records = snapshot.providers?.[providerId]?.[type];

        if (!records?.[lookupKey]) {
            return;
        }

        delete records[lookupKey];
        markProviderDirty(providerId);
        scheduleFlush();
    };

    const createEntryGetter = type => async (providerId, lookupKey) => getRecord(await getSnapshot(), providerId, type, lookupKey);
    const createEntryMarker = (type, createRecord) => async (providerId, lookupKey, ...args) => setRecord(providerId, type, lookupKey, createRecord(...args));
    const processingKey = (providerId, lookupKey) => `${providerId}::${lookupKey}`;

    const ensureFlushPromise = () => {
        if (!flushPromise) {
            flushPromise = new Promise(resolve => {
                flushResolver = resolve;
            });
        }
        return flushPromise;
    };

    const buildMetaRecord = () => ({
        version: cacheSnapshot.version,
        globalAllowPatterns: cacheSnapshot.globalAllowPatterns,
        providerIds: Object.keys(cacheSnapshot.providers),
    });

    const flush = async () => {
        if (flushTimer) {
            clearTimeout(flushTimer);
            flushTimer = null;
        }

        ensureFlushPromise();

        const providersToWrite = [...dirtyProviders];
        const writeMeta = metaDirty;

        dirtyProviders.clear();
        metaDirty = false;

        const payload = {};
        const removeKeys = [];

        if (writeMeta) {
            payload[metaKey] = buildMetaRecord();
        }

        for (const providerId of providersToWrite) {
            const record = cacheSnapshot?.providers?.[providerId];

            if (record) {
                payload[shardKey(providerId)] = record;
            } else {
                removeKeys.push(shardKey(providerId));
            }
        }

        try {
            if (Object.keys(payload).length > 0) {
                await browserAPI.storageSet("local", payload);
            }

            if (removeKeys.length > 0) {
                await browserAPI.storageRemove("local", removeKeys);
            }
        } catch (error) {
            console.error("OspreyCacheService failed to persist cache snapshot", error);

            if (writeMeta) {
                metaDirty = true;
            }

            for (const providerId of providersToWrite) {
                dirtyProviders.add(providerId);
            }
        } finally {
            flushResolver?.();
            flushResolver = null;
            flushPromise = null;
        }
    };

    const scheduleFlush = (delayMs = flushDelay) => {
        if (flushTimer) {
            clearTimeout(flushTimer);
        }

        flushTimer = setTimeout(() => {
            flushTimer = null;
            flush().catch(error => {
                console.error("OspreyCacheService failed to flush cache snapshot", error);
            });
        }, delayMs);
        return ensureFlushPromise();
    };

    const loadSnapshot = async () => {
        const metaStored = await browserAPI.storageGet("local", metaKey).catch(() => ({}));
        const meta = metaStored?.[metaKey];

        if (meta && typeof meta === "object" && meta.providers && typeof meta.providers === "object") {
            const migrated = normalizeSnapshot(meta);

            markMetaDirty();

            for (const providerId of Object.keys(migrated.providers)) {
                markProviderDirty(providerId);
            }

            scheduleFlush();
            return migrated;
        }

        const providerIds = meta && Array.isArray(meta.providerIds) ?
            meta.providerIds.filter(id => typeof id === "string" && id.length > 0) : [];

        const keys = providerIds.map(shardKey);

        const shardStored = keys.length > 0 ?
            await browserAPI.storageGet("local", keys).catch(() => ({})) : {};

        const providers = {};

        for (const providerId of providerIds) {
            providers[providerId] = normalizeProvider(shardStored?.[shardKey(providerId)]);
        }

        return {
            ...defaultSnapshot(),
            globalAllowPatterns: normalizePatterns(meta?.globalAllowPatterns),
            providers,
        };
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
        return loadingPromise;
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

        for (const [providerId, provider] of Object.entries(snapshot.providers)) {
            const providerDirty = pruneExpiredEntries(provider.allowed, now) ||
                pruneExpiredEntries(provider.blocked, now);

            if (providerDirty) {
                markProviderDirty(providerId);
                dirty = true;
            }
        }

        if (dirty) {
            await flush();
        }
    };

    const matchesGlobalPattern = async url => {
        const snapshot = await getSnapshot();
        const parsed = urlService.parseHttpUrl(url);

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
            markMetaDirty();
            scheduleFlush();
        }
    };

    const clearAll = async () => {
        const alreadyClear = Boolean(cacheSnapshot) &&
            cacheSnapshot.version === 2 &&
            cacheSnapshot.globalAllowPatterns.length === 0 &&
            Object.keys(cacheSnapshot.providers).length === 0 &&
            processing.size === 0;

        if (!alreadyClear) {
            const previousProviderIds = cacheSnapshot ? Object.keys(cacheSnapshot.providers) : [];

            cacheSnapshot = defaultSnapshot();
            processing.clear();

            markMetaDirty();

            for (const providerId of previousProviderIds) {
                markProviderDirty(providerId);
            }

            scheduleFlush(0);
        }
    };

    const clearBlockedForLookup = async lookupKey => {
        const snapshot = await getSnapshot();
        let removed = 0;

        for (const [providerId, provider] of Object.entries(snapshot.providers)) {
            if (provider?.blocked && Object.hasOwn(provider.blocked, lookupKey)) {
                delete provider.blocked[lookupKey];
                markProviderDirty(providerId);
                removed += 1;
            }
        }

        if (!removed) {
            return;
        }

        scheduleFlush();
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

            markProviderDirty(providerId);
        }

        scheduleFlush();
    };

    // Run cache cleanup on a 5-minute interval rather than on every read
    setInterval(cleanupExpired, 5 * 60 * 1000);

    // Perform an initial cleanup on startup to remove any entries that
    // may have expired while the extension was not running
    cleanupExpired().catch(error => {
        console.warn("OspreyCacheService failed to cleanup on startup", error);
    });

    // Public API
    return timer.instrument('OspreyCacheService', {
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
    });
})();
