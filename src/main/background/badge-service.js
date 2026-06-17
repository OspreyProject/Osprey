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

globalThis.OspreyBadgeService = (() => {
    const browserAPI = globalThis.OspreyBrowserAPI;

    const desiredCounts = new Map();
    const appliedCounts = new Map();
    const colorsSetTabs = new Set();
    const dirtyTabs = new Set();

    let globalTimer = null;
    const coalesceMs = 50;

    const maxCachedStrings = 1024;
    const cachedStrings = Array.from({length: maxCachedStrings});

    for (let i = 0; i < maxCachedStrings; i++) {
        cachedStrings[i] = String(i);
    }

    const getString = val => val < maxCachedStrings ? cachedStrings[val] : String(val);

    const badgeTextPacket = {
        tabId: 0,
        text: ''
    };

    const backgroundColorPacket = {
        color: '#ff4b4b',
        tabId: 0
    };

    const textColorPacket = {
        color: '#ffffff',
        tabId: 0
    };

    const ignoreMissingTab = error => {
        if (error?.message?.includes('No tab with id')) {
            return;
        }

        globalThis.console.error(error);
    };

    const processDirtyTabs = () => {
        globalTimer = null;

        for (const tabId of dirtyTabs) {
            const desired = desiredCounts.get(tabId);

            if (desired === undefined) {
                continue;
            }

            const applied = appliedCounts.get(tabId) ?? -1;

            if (applied === desired) {
                continue;
            }

            appliedCounts.set(tabId, desired);
            badgeTextPacket.tabId = tabId;

            if (desired === 0) {
                colorsSetTabs.delete(tabId);
                badgeTextPacket.text = '';
                browserAPI.actionSetBadgeText(badgeTextPacket).catch(ignoreMissingTab);
                continue;
            }

            badgeTextPacket.text = getString(desired);
            browserAPI.actionSetBadgeText(badgeTextPacket).catch(ignoreMissingTab);

            if (!colorsSetTabs.has(tabId)) {
                backgroundColorPacket.tabId = tabId;
                textColorPacket.tabId = tabId;

                browserAPI.actionSetBadgeBackgroundColor(backgroundColorPacket).catch(ignoreMissingTab);
                browserAPI.actionSetBadgeTextColor(textColorPacket).catch(ignoreMissingTab);

                colorsSetTabs.add(tabId);
            }
        }

        dirtyTabs.clear();
    };

    const scheduleApply = tabId => {
        dirtyTabs.add(tabId);

        if (globalTimer === null) {
            globalTimer = setTimeout(processDirtyTabs, coalesceMs);
        }
    };

    const request = (tabId, count) => {
        if (typeof tabId !== 'number') {
            return;
        }

        const desired = Math.trunc(count);
        const currentDesired = desiredCounts.get(tabId) ?? 0;

        if (currentDesired === desired) {
            return;
        }

        desiredCounts.set(tabId, desired);
        scheduleApply(tabId);
    };

    const clear = tabId => {
        request(tabId, 0);
    };

    const clearTab = tabId => {
        if (typeof tabId !== 'number') {
            return;
        }

        desiredCounts.delete(tabId);
        appliedCounts.delete(tabId);
        colorsSetTabs.delete(tabId);
        dirtyTabs.delete(tabId);

        if (dirtyTabs.size === 0 && globalTimer !== null) {
            clearTimeout(globalTimer);
            globalTimer = null;
        }
    };

    const reapply = tabId => {
        if (typeof tabId !== 'number') {
            return;
        }

        appliedCounts.delete(tabId);
        colorsSetTabs.delete(tabId);

        if (desiredCounts.has(tabId)) {
            scheduleApply(tabId);
        }
    };

    const syncWithContext = (tabId, context) => {
        const count = context && Array.isArray(context.origins) ? context.origins.length : 0;
        request(tabId, count);
    };

    return Object.freeze({
        clear,
        clearTab,
        reapply,
        syncWithContext,
    });
})();
