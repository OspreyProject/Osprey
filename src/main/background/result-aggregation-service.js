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
    const blockedByTab = new Map();
    const frameZeroUrlByTab = new Map();
    const warningPageReadyTabs = new Set();

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
        const origins = Array.from({length});
        let idx = 0;

        for (const [origin, result] of entries.entries()) {
            if (idx === 0) {
                primaryOrigin = origin;
                primaryResult = result;
            }

            origins[idx++] = origin;
        }

        return {
            url: current.url,
            primaryOrigin,
            primaryResult,
            origins,
            redirected: current.redirected,
        };
    };

    const beginNavigation = tabId => {
        blockedByTab.delete(tabId);
        warningPageReadyTabs.delete(tabId);
    };

    const setFrameZeroUrl = (tabId, url) => {
        frameZeroUrlByTab.set(tabId, url);
    };

    const getFrameZeroUrl = tabId => frameZeroUrlByTab.get(tabId) || '';

    const recordBlockingResult = (tabId, url, origin, result) => {
        let context = blockedByTab.get(tabId);
        const firstForUrl = !context || context.url !== url;

        if (firstForUrl) {
            const entriesMap = new Map();
            entriesMap.set(origin, result);

            context = {
                url,
                entries: entriesMap,
                redirected: false,
            };

            blockedByTab.set(tabId, context);
        } else {
            const entries = context.entries;

            if (!entries.has(origin)) {
                entries.set(origin, result);
            }
        }

        return {
            context: cloneContext(context),
            firstForUrl,
        };
    };

    const markRedirected = tabId => {
        const context = blockedByTab.get(tabId);

        if (context) {
            context.redirected = true;
        }
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

        const entries = current.entries;
        entries.delete(origin);

        if (entries.size > 0) {
            return cloneContext(current);
        }

        blockedByTab.delete(tabId);
        return null;
    };

    const clear = tabId => {
        blockedByTab.delete(tabId);
        frameZeroUrlByTab.delete(tabId);
        warningPageReadyTabs.delete(tabId);
    };

    const markWarningPageReady = tabId => {
        warningPageReadyTabs.add(tabId);
    };

    const isWarningPageReady = tabId => warningPageReadyTabs.has(tabId);

    return Object.freeze({
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
