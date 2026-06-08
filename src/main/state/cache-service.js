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
    const browserAPI = globalThis.OspreyBrowserAPI;
    const urlService = globalThis.OspreyUrlService;
    const protectionResult = globalThis.OspreyProtectionResult;

    const cacheKey = "osprey_cache";
    const metaKey = cacheKey;
    const shardPrefix = `${cacheKey}::p::`;
    const shardKey = providerId => `${shardPrefix}${providerId}`;

    const flushDelay = 500;

    const maxEntriesPerMap = 500;
    const pruneThreshold = Math.floor(maxEntriesPerMap * 0.9);

    let cacheSnapshot = null;
    let loadingPromise = null;
    let flushTimer = null;
    let flushPromise = null;
    let flushResolver = null;

    const dirtyProviders = new Set();
    let metaDirty = false;

    const processing = new Map();
    const processingTabs = new Map();
    let parsedAllowPatternsCache = null;

    const defaultSnapshot = () => ({version: 2, globalAllowPatterns: [], providers: new Map()});

    const markProviderDirty = providerId => {
        if (providerId) {
            dirtyProviders.add(providerId);
        }
    };

    const markMetaDirty = () => {
        metaDirty = true;
    };

    const normalizeEntryMap = value => {
        const map = new Map();

        if (!value || typeof value !== "object" || Array.isArray(value)) {
            return map;
        }

        for (const [key, entry] of Object.entries(value)) {
            if (entry && typeof entry === "object") {
                map.set(key, {
                    exp: Number(entry.exp) || 0,
                    result: entry.result
                });
            }
        }
        return map;
    };

    const normalizeProvider = record => ({
        allowed: normalizeEntryMap(record?.allowed),
        blocked: normalizeEntryMap(record?.blocked),
    });

    const normalizePatterns = value => {
        if (!Array.isArray(value)) {
            return [];
        }
        return value.filter(pattern => typeof pattern === "string" && pattern.startsWith("*."));
    };

    const normalizeSnapshot = input => {
        const value = input && typeof input === "object" ? input : {};
        const providers = new Map();

        if (value.providers && typeof value.providers === "object" && !Array.isArray(value.providers)) {
            for (const [providerId, providerData] of Object.entries(value.providers)) {
                providers.set(providerId, normalizeProvider(providerData));
            }
        }

        return {
            version: 2,
            globalAllowPatterns: normalizePatterns(value.globalAllowPatterns),
            providers
        };
    };

    const ensureProvider = (snapshot, providerId) => {
        let provider = snapshot.providers.get(providerId);

        if (!provider) {
            provider = {allowed: new Map(), blocked: new Map()};
            snapshot.providers.set(providerId, provider);
            markMetaDirty();
        }
        return provider;
    };

    const getRecord = (snapshot, providerId, type, lookupKey) => {
        const provider = snapshot.providers.get(providerId);
        return provider ? provider[type].get(lookupKey) || null : null;
    };

    const setRecord = async (providerId, type, lookupKey, record) => {
        const snapshot = await getSnapshot();
        const entries = ensureProvider(snapshot, providerId)[type];

        entries.set(lookupKey, record);
        boundEntryMap(entries, Date.now());
        markProviderDirty(providerId);
        scheduleFlush();
    };

    const deleteRecord = async (providerId, type, lookupKey) => {
        const snapshot = await getSnapshot();
        const provider = snapshot.providers.get(providerId);

        if (!provider?.[type].has(lookupKey)) {
            return;
        }

        provider[type].delete(lookupKey);
        markProviderDirty(providerId);
        scheduleFlush();
    };

    const pruneExpiredEntries = (entriesMap, now) => {
        if (!entriesMap || entriesMap.size === 0) {
            return false;
        }

        let removed = false;

        for (const [key, entry] of entriesMap.entries()) {
            if (!entry || entry.exp < now) {
                entriesMap.delete(key);
                removed = true;
            }
        }
        return removed;
    };

    const boundEntryMap = (entriesMap, now) => {
        if (!entriesMap || entriesMap.size < pruneThreshold) {
            return false;
        }

        let changed = pruneExpiredEntries(entriesMap, now);
        const overflow = entriesMap.size - maxEntriesPerMap;

        if (overflow > 0) {
            let deleted = 0;

            for (const key of entriesMap.keys()) {
                entriesMap.delete(key);
                deleted++;

                if (deleted >= overflow) {
                    break;
                }
            }

            changed = true;
        }
        return changed;
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
        providerIds: Array.from(cacheSnapshot.providers.keys()),
    });

    const flush = async () => {
        if (flushTimer) {
            clearTimeout(flushTimer);
            flushTimer = null;
        }

        ensureFlushPromise();

        const providersToWrite = Array.from(dirtyProviders);
        const writeMeta = metaDirty;

        dirtyProviders.clear();
        metaDirty = false;

        const payload = {};
        const removeKeys = [];

        if (writeMeta) {
            payload[metaKey] = buildMetaRecord();
        }

        for (const providerId of providersToWrite) {
            const record = cacheSnapshot?.providers.get(providerId);

            if (record) {
                payload[shardKey(providerId)] = {
                    allowed: Object.fromEntries(record.allowed),
                    blocked: Object.fromEntries(record.blocked)
                };
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

            for (const element of providersToWrite) {
                dirtyProviders.add(element);
            }
        } finally {
            if (flushResolver) {
                flushResolver();
            }

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

            for (const providerId of migrated.providers.keys()) {
                markProviderDirty(providerId);
            }

            scheduleFlush();
            return migrated;
        }

        const providerIds = meta && Array.isArray(meta.providerIds) ?
            meta.providerIds.filter(id => typeof id === "string" && id.length > 0) : [];

        const keys = providerIds.map(shardKey);
        const shardStored = keys.length > 0 ? await browserAPI.storageGet("local", keys).catch(() => ({})) : {};
        const providers = new Map();

        for (const providerId of providerIds) {
            providers.set(providerId, normalizeProvider(shardStored?.[shardKey(providerId)]));
        }

        return {
            version: 2,
            globalAllowPatterns: normalizePatterns(meta?.globalAllowPatterns),
            providers,
        };
    };

    const resolveLoadingSnapshot = () => {
        const currentPromise = loadSnapshot()
            .then(snapshot => {
                cacheSnapshot = snapshot;

                if (loadingPromise === currentPromise) {
                    loadingPromise = null;
                }
                return snapshot;
            }).catch(error => {
                if (loadingPromise === currentPromise) {
                    loadingPromise = null;
                }

                console.error("OspreyCacheService failed to load cache snapshot", error);
                throw error;
            });
        return currentPromise;
    };

    const getSnapshot = async ({fresh = false} = {}) => {
        if (!fresh && cacheSnapshot) {
            return cacheSnapshot;
        }

        if (fresh || !loadingPromise) {
            loadingPromise = resolveLoadingSnapshot();
        }
        return loadingPromise;
    };

    const cleanupExpired = async () => {
        const snapshot = await getSnapshot();
        const now = Date.now();
        let dirty = false;

        for (const [providerId, provider] of snapshot.providers.entries()) {
            const allowedDirty = pruneExpiredEntries(provider.allowed, now);
            const blockedDirty = pruneExpiredEntries(provider.blocked, now);

            if (allowedDirty || blockedDirty) {
                markProviderDirty(providerId);
                dirty = true;
            }
        }

        for (const [key, entry] of processing.entries()) {
            if (entry.exp < now) {
                processing.delete(key);

                if (entry.tabId) {
                    const tabKeys = processingTabs.get(entry.tabId);

                    if (tabKeys) {
                        tabKeys.delete(key);

                        if (tabKeys.size === 0) {
                            processingTabs.delete(entry.tabId);
                        }
                    }
                }
            }
        }

        if (dirty) {
            await flush();
        }
    };

    const getParsedGlobalPatterns = async () => {
        const snapshot = await getSnapshot();
        const currentVersion = snapshot.globalAllowPatterns.length;

        if (parsedAllowPatternsCache && parsedAllowPatternsCache.version === currentVersion) {
            return parsedAllowPatternsCache.patternsSet;
        }

        const patternsSet = new Set();

        for (let i = 0; i < currentVersion; i++) {
            patternsSet.add(urlService.canonicalizeHostname(snapshot.globalAllowPatterns[i].slice(2)));
        }

        parsedAllowPatternsCache = {version: currentVersion, patternsSet};
        return patternsSet;
    };

    const matchesGlobalPattern = async url => {
        const parsed = urlService.parseHttpUrl(url);

        if (!parsed) {
            return false;
        }

        let hostname = urlService.canonicalizeHostname(parsed.hostname);
        const patternsSet = await getParsedGlobalPatterns();

        while (hostname) {
            if (patternsSet.has(hostname)) {
                return true;
            }

            const nextDot = hostname.indexOf(".");

            if (nextDot === -1) {
                break;
            }

            hostname = hostname.slice(nextDot + 1);
        }
        return false;
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
            cacheSnapshot.providers.size === 0 &&
            processing.size === 0;

        if (!alreadyClear) {
            const previousProviderIds = cacheSnapshot ? Array.from(cacheSnapshot.providers.keys()) : [];

            cacheSnapshot = defaultSnapshot();
            processing.clear();
            processingTabs.clear();
            parsedAllowPatternsCache = null;

            markMetaDirty();

            for (const element of previousProviderIds) {
                markProviderDirty(element);
            }

            scheduleFlush(0);
        }
    };

    const clearBlockedForLookup = async lookupKey => {
        const snapshot = await getSnapshot();
        let removed = 0;

        for (const [providerId, provider] of snapshot.providers.entries()) {
            if (provider?.blocked?.has(lookupKey)) {
                provider.blocked.delete(lookupKey);
                markProviderDirty(providerId);
                removed++;
            }
        }

        if (removed > 0) {
            scheduleFlush();
        }
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

            if (entry.tabId) {
                const tabSet = processingTabs.get(entry.tabId);

                if (tabSet) {
                    tabSet.delete(key);

                    if (tabSet.size === 0) {
                        processingTabs.delete(entry.tabId);
                    }
                }
            }
            return false;
        }
        return true;
    };

    const markProcessing = (providerId, lookupKey, tabId = 0) => {
        const key = processingKey(providerId, lookupKey);
        processing.set(key, {exp: Date.now() + 60000, tabId});

        if (tabId) {
            let tabKeys = processingTabs.get(tabId);

            if (!tabKeys) {
                tabKeys = new Set();
                processingTabs.set(tabId, tabKeys);
            }

            tabKeys.add(key);
        }
    };

    const clearProcessing = (providerId, lookupKey) => {
        const key = processingKey(providerId, lookupKey);
        const entry = processing.get(key);

        if (entry) {
            processing.delete(key);

            if (entry.tabId) {
                const tabKeys = processingTabs.get(entry.tabId);

                if (tabKeys) {
                    tabKeys.delete(key);

                    if (tabKeys.size === 0) {
                        processingTabs.delete(entry.tabId);
                    }
                }
            }
        }
    };

    const clearProcessingByTab = tabId => {
        const tabKeys = processingTabs.get(tabId);

        if (tabKeys) {
            for (const key of tabKeys) {
                processing.delete(key);
            }

            processingTabs.delete(tabId);
        }
    };

    const storeOutcomes = async (entries, expirationSeconds) => {
        if (!Array.isArray(entries) || entries.length === 0) {
            return;
        }

        const snapshot = await getSnapshot();
        const now = Date.now();
        const expiry = now + Number(expirationSeconds || 0) * 1000;

        for (const entry of entries) {
            const providerId = String(entry?.providerId || "");
            const lookupKey = String(entry?.lookupKey || "");

            if (!providerId || !lookupKey) {
                continue;
            }

            const providerRecord = ensureProvider(snapshot, providerId);

            providerRecord.allowed.delete(lookupKey);
            providerRecord.blocked.delete(lookupKey);

            if (protectionResult.blockingResults.has(entry?.outcome)) {
                providerRecord.blocked.set(lookupKey, {exp: expiry, result: entry.outcome});
                boundEntryMap(providerRecord.blocked, now);
            } else {
                providerRecord.allowed.set(lookupKey, {exp: expiry});
                boundEntryMap(providerRecord.allowed, now);
            }

            markProviderDirty(providerId);
        }

        scheduleFlush();
    };

    setInterval(cleanupExpired, 5 * 60 * 1000);

    cleanupExpired().catch(error => {
        console.warn("OspreyCacheService failed to cleanup on startup", error);
    });

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
    });
})();
