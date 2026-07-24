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
'use strict';

globalThis.OspreyResultAggregationService = (() => {
    const browserAPI = globalThis.OspreyBrowserAPI;
    const protectionResult = globalThis.OspreyProtectionResult;
    const urlService = globalThis.OspreyUrlService;

    const sessionArea = 'session';
    const storageKey = 'osprey.blockedContexts';

    const orphanGraceMs = 60000;

    const blockedByTab = new Map();
    const orphanedByUrl = new Map();
    const frameZeroUrlByTab = new Map();
    const warningPageReadyTabs = new Set();

    const authoritativeBlocked = new Set();
    const authoritativeMeta = new Set();

    const urlKeyFor = url => {
        if (typeof url !== 'string' || url.length === 0) {
            return '';
        }

        try {
            return urlService?.normalizeUrl?.(url) || url;
        } catch {
            return url;
        }
    };

    const pruneOrphans = (now = Date.now()) => {
        for (const [key, orphan] of orphanedByUrl.entries()) {
            if (!Number.isFinite(orphan.expiresAt) || orphan.expiresAt <= now) {
                orphanedByUrl.delete(key);
            }
        }
    };

    let hydrationPromise = null;
    let persistPromise = Promise.resolve();
    let persistScheduled = false;

    const markBlockedAuthoritative = tabId => {
        if (typeof tabId === 'number') {
            authoritativeBlocked.add(tabId);
        }
    };

    const markMetaAuthoritative = tabId => {
        if (typeof tabId === 'number') {
            authoritativeMeta.add(tabId);
        }
    };

    const serializeContext = context => {
        if (!context) {
            return null;
        }

        return {
            url: context.url,
            entries: Array.from(context.entries.entries()),
            redirected: context.redirected,
            retired: context.retired,
            total: context.total,
        };
    };

    const serializeState = () => {
        pruneOrphans();

        const tabs = {};
        const orphans = [];
        const tabIds = new Set();

        for (const tabId of blockedByTab.keys()) {
            tabIds.add(tabId);
        }

        for (const tabId of frameZeroUrlByTab.keys()) {
            tabIds.add(tabId);
        }

        for (const tabId of warningPageReadyTabs) {
            tabIds.add(tabId);
        }

        for (const tabId of tabIds) {
            tabs[String(tabId)] = {
                blocked: serializeContext(blockedByTab.get(tabId)),
                frameZeroUrl: frameZeroUrlByTab.get(tabId) || '',
                warningReady: warningPageReadyTabs.has(tabId),
            };
        }

        for (const [key, orphan] of orphanedByUrl.entries()) {
            orphans.push({
                key,
                blocked: serializeContext(orphan.context),
                expiresAt: orphan.expiresAt,
            });
        }
        return {tabs, orphans};
    };

    const restoreEntries = rawEntries => {
        const entries = new Map();

        if (!Array.isArray(rawEntries)) {
            return entries;
        }

        for (let i = 0, len = rawEntries.length; i < len; i++) {
            const pair = rawEntries[i];

            if (Array.isArray(pair) && typeof pair[0] === 'string' && typeof pair[1] === 'string') {
                entries.set(pair[0], pair[1]);
            }
        }
        return entries;
    };

    const deserializeContext = blocked => {
        if (!blocked || typeof blocked !== 'object') {
            return null;
        }

        const entries = restoreEntries(blocked.entries);

        if (entries.size === 0) {
            return null;
        }

        const storedTotal = Number(blocked.total);

        return {
            url: typeof blocked.url === 'string' ? blocked.url : '',
            entries,
            redirected: blocked.redirected === true,
            retired: blocked.retired === true,
            total: Math.max(entries.size, Number.isFinite(storedTotal) ? storedTotal : 0),
        };
    };

    const restoreTab = (rawTabId, entry) => {
        const tabId = Number.parseInt(rawTabId, 10);

        if (!Number.isFinite(tabId) || !entry || typeof entry !== 'object') {
            return;
        }

        if (!authoritativeBlocked.has(tabId)) {
            const context = deserializeContext(entry.blocked);

            if (context) {
                blockedByTab.set(tabId, context);
            }
        }

        if (authoritativeMeta.has(tabId)) {
            return;
        }

        if (typeof entry.frameZeroUrl === 'string' && entry.frameZeroUrl.length > 0) {
            frameZeroUrlByTab.set(tabId, entry.frameZeroUrl);
        }

        if (entry.warningReady === true) {
            warningPageReadyTabs.add(tabId);
        }
    };

    const hydrate = async () => {
        try {
            const stored = await browserAPI.storageGet(sessionArea, storageKey);
            const snapshot = stored?.[storageKey];

            if (!snapshot || typeof snapshot !== 'object') {
                return;
            }

            const tabs = snapshot.tabs && typeof snapshot.tabs === 'object' ? snapshot.tabs : {};
            const rawTabIds = Object.keys(tabs);

            for (let i = 0, len = rawTabIds.length; i < len; i++) {
                restoreTab(rawTabIds[i], tabs[rawTabIds[i]]);
            }

            const orphans = Array.isArray(snapshot.orphans) ? snapshot.orphans : [];
            const now = Date.now();

            for (let i = 0, len = orphans.length; i < len; i++) {
                const orphan = orphans[i];
                const expiresAt = Number(orphan?.expiresAt);

                if (typeof orphan?.key !== 'string' || !Number.isFinite(expiresAt) || expiresAt <= now || orphanedByUrl.has(orphan.key)) {
                    continue;
                }

                const context = deserializeContext(orphan.blocked);

                if (context) {
                    orphanedByUrl.set(orphan.key, {context, expiresAt});
                }
            }

            pruneOrphans(now);
        } catch (error) {
            console.warn('Failed to restore blocked-context state from session storage', error);
        }
    };

    const ensureHydrated = () => {
        if (hydrationPromise === null) {
            hydrationPromise = hydrate();
        }
        return hydrationPromise;
    };

    const persistNow = async () => {
        try {
            await browserAPI.storageSet(sessionArea, {[storageKey]: serializeState()});
        } catch (error) {
            console.warn('Failed to persist blocked-context state to session storage', error);
        }
    };

    const persist = () => {
        if (!persistScheduled) {
            persistScheduled = true;

            persistPromise = persistPromise.then(() => {
                persistScheduled = false;
                return persistNow();
            });
        }
        return persistPromise;
    };

    const cloneContext = current => {
        if (!current) {
            return null;
        }

        const entries = current.entries;
        const length = entries.size;

        if (length === 0) {
            return null;
        }

        let primaryOrigin = '';
        let primaryResult = null;
        let primaryRank = Number.MAX_SAFE_INTEGER;
        const origins = Array.from({length});
        let idx = 0;

        for (const [origin, result] of entries.entries()) {
            const rank = protectionResult.severityRank(result);

            if (primaryResult === null || rank < primaryRank) {
                primaryOrigin = origin;
                primaryResult = result;
                primaryRank = rank;
            }

            origins[idx++] = origin;
        }

        return {
            url: current.url,
            primaryOrigin,
            primaryResult,
            origins,
            redirected: current.redirected,
            retired: current.retired === true,
            remaining: length,
            total: Math.max(current.total, length),
        };
    };

    const beginNavigation = tabId => {
        markBlockedAuthoritative(tabId);
        markMetaAuthoritative(tabId);
        blockedByTab.delete(tabId);
        warningPageReadyTabs.delete(tabId);

        persist().then(() => {
            // ignored
        });
    };

    const setFrameZeroUrl = (tabId, url) => {
        markMetaAuthoritative(tabId);
        frameZeroUrlByTab.set(tabId, url);

        persist().then(() => {
            // ignored
        });
    };

    const getFrameZeroUrl = tabId => frameZeroUrlByTab.get(tabId) || '';

    const recordBlockingResult = (tabId, url, origin, result) => {
        markBlockedAuthoritative(tabId);

        let context = blockedByTab.get(tabId);
        const firstForUrl = !context || context.url !== url;

        if (firstForUrl) {
            const entriesMap = new Map();
            entriesMap.set(origin, result);

            context = {
                url,
                entries: entriesMap,
                redirected: false,
                retired: false,
                total: 1,
            };

            blockedByTab.set(tabId, context);
        } else {
            const entries = context.entries;

            if (!entries.has(origin)) {
                entries.set(origin, result);
                context.total = Math.max(context.total + 1, entries.size);
            }
        }

        persist().then(() => {
            // ignored
        });

        return {
            context: cloneContext(context),
            firstForUrl,
        };
    };

    const markRedirected = tabId => {
        const context = blockedByTab.get(tabId);

        if (context) {
            markBlockedAuthoritative(tabId);
            context.redirected = true;

            persist().then(() => {
                // ignored
            });
        }
    };

    const retire = tabId => {
        markBlockedAuthoritative(tabId);
        markMetaAuthoritative(tabId);

        const context = blockedByTab.get(tabId);

        if (context) {
            context.retired = true;
        }

        frameZeroUrlByTab.delete(tabId);
        warningPageReadyTabs.delete(tabId);

        persist().then(() => {
            // ignored
        });
    };

    const reactivate = tabId => {
        const context = blockedByTab.get(tabId);

        if (context?.retired !== true) {
            return false;
        }

        markBlockedAuthoritative(tabId);
        markMetaAuthoritative(tabId);

        context.retired = false;
        context.redirected = true;
        frameZeroUrlByTab.set(tabId, context.url);

        persist().then(() => {
            // ignored
        });
        return true;
    };

    const isRetired = tabId => {
        const context = blockedByTab.get(tabId);
        return context === undefined ? false : context.retired === true;
    };

    const isRedirected = tabId => {
        const context = blockedByTab.get(tabId);
        return context === undefined ? false : context.redirected;
    };

    const getBlockedContext = tabId => {
        const context = blockedByTab.get(tabId);
        return context === undefined ? null : cloneContext(context);
    };

    const removeOrigin = (tabId, origin) => {
        const current = blockedByTab.get(tabId);

        if (!current) {
            return null;
        }

        markBlockedAuthoritative(tabId);
        const entries = current.entries;
        entries.delete(origin);

        if (entries.size > 0) {
            persist().then(() => {
                // ignored
            });
            return cloneContext(current);
        }

        blockedByTab.delete(tabId);

        persist().then(() => {
            // ignored
        });
        return null;
    };

    const clear = tabId => {
        markBlockedAuthoritative(tabId);
        markMetaAuthoritative(tabId);
        blockedByTab.delete(tabId);
        frameZeroUrlByTab.delete(tabId);
        warningPageReadyTabs.delete(tabId);

        persist().then(() => {
            // ignored
        });
    };

    const releaseTab = tabId => {
        markBlockedAuthoritative(tabId);
        markMetaAuthoritative(tabId);

        const context = blockedByTab.get(tabId);

        if (context && context.entries.size > 0) {
            const key = urlKeyFor(context.url);

            if (key) {
                context.retired = true;
                orphanedByUrl.set(key, {context, expiresAt: Date.now() + orphanGraceMs});
            }
        }

        blockedByTab.delete(tabId);
        frameZeroUrlByTab.delete(tabId);
        warningPageReadyTabs.delete(tabId);

        persist().then(() => {
            // ignored
        });
    };

    const adoptForUrl = (tabId, url) => {
        if (typeof tabId !== 'number' || blockedByTab.has(tabId)) {
            return false;
        }

        pruneOrphans();

        const key = urlKeyFor(url);
        const orphan = key ? orphanedByUrl.get(key) : undefined;

        if (!orphan) {
            return false;
        }

        orphanedByUrl.delete(key);
        markBlockedAuthoritative(tabId);
        markMetaAuthoritative(tabId);

        const context = orphan.context;
        context.retired = false;
        context.redirected = true;

        blockedByTab.set(tabId, context);
        frameZeroUrlByTab.set(tabId, context.url);

        persist().then(() => {
            // ignored
        });
        return true;
    };

    const markWarningPageReady = tabId => {
        markMetaAuthoritative(tabId);
        warningPageReadyTabs.add(tabId);

        persist().then(() => {
            // ignored
        });
    };

    const isWarningPageReady = tabId => warningPageReadyTabs.has(tabId);

    return Object.freeze({
        ensureHydrated,
        persist,
        releaseTab,
        adoptForUrl,
        retire,
        reactivate,
        isRetired,
        beginNavigation,
        setFrameZeroUrl,
        getFrameZeroUrl,
        recordBlockingResult,
        markRedirected,
        isRedirected,
        getBlockedContext,
        removeOrigin,
        clear,
        markWarningPageReady,
        isWarningPageReady,
    });
})();
