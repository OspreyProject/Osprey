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

globalThis.OspreyResultAggregationService = (() => {
    const blockedByTab = new Map();
    const frameZeroUrlByTab = new Map();

    const cloneContext = current => {
        const primary = current?.entries?.[0];

        return primary ? {
            url: current.url,
            primaryOrigin: primary.origin,
            primaryResult: primary.result,
            origins: current.entries.map(entry => entry.origin),
            redirected: current.redirected,
        } : null;
    };

    const beginNavigation = (tabId, url, frameId = 0) => {
        if (frameId === 0) {
            frameZeroUrlByTab.set(tabId, url);
            blockedByTab.delete(tabId);
        }
    };

    const getFrameZeroUrl = tabId => frameZeroUrlByTab.get(tabId) || "";

    const recordBlockingResult = (tabId, url, origin, result) => {
        let context = blockedByTab.get(tabId);
        const firstForUrl = !context || context.url !== url;

        if (firstForUrl) {
            context = {url, entries: [{origin, result}], redirected: false};
            blockedByTab.set(tabId, context);
        } else if (!context.entries.some(entry => entry.origin === origin)) {
            context.entries.push({origin, result});
        }

        return {
            context: cloneContext(context),
            firstForUrl
        };
    };

    const markRedirected = tabId => {
        const context = blockedByTab.get(tabId);

        if (context) {
            context.redirected = true;
        }
    };

    const isRedirected = tabId => Boolean(blockedByTab.get(tabId)?.redirected);
    const getBlockedContext = tabId => cloneContext(blockedByTab.get(tabId));

    const removeOrigin = (tabId, origin) => {
        const current = blockedByTab.get(tabId);

        if (!current) {
            return null;
        }

        current.entries = current.entries.filter(entry => entry.origin !== origin);

        if (current.entries.length > 0) {
            return cloneContext(current);
        }

        blockedByTab.delete(tabId);
        return null;
    };

    const clear = tabId => {
        blockedByTab.delete(tabId);
        frameZeroUrlByTab.delete(tabId);
    };

    // Public API
    return Object.freeze({
        beginNavigation,
        getFrameZeroUrl,
        recordBlockingResult,
        markRedirected,
        isRedirected,
        getBlockedContext,
        removeOrigin,
        clear,
    });
})();
